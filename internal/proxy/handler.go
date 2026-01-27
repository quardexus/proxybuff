package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quardexus/proxybuff/internal/cache"
	"github.com/quardexus/proxybuff/internal/config"
)

type Handler struct {
	cfg       config.Config
	origin    *url.URL
	cacheDisk cache.Disk
	matchers  []cache.Matcher
	recache   *recacheScheduler
	locks     *keyedLocker

	client *http.Client
	proxy  *httputil.ReverseProxy
}

func New(cfg config.Config) (*Handler, error) {
	u, err := url.Parse(cfg.Origin)
	if err != nil {
		return nil, fmt.Errorf("parse origin: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("origin must be a full URL with scheme and host, got %q", cfg.Origin)
	}

	matchers, err := cache.CompileMatchers(cfg.Cache)
	if err != nil {
		return nil, err
	}

	recacheMatchers, err := cache.CompileMatchers(cfg.Recache)
	if err != nil {
		return nil, err
	}

	cd := cache.Disk{Dir: cfg.CacheDir, TTL: cfg.TTL}
	if err := cd.Validate(); err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = transport
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		// Save original host before the default director overwrites it.
		originalHost := req.Host
		origDirector(req)
		if !cfg.UseOriginHost {
			req.Host = originalHost
		}
	}
	// keep the default error handler behavior (502), but do not log secrets.

	h := &Handler{
		cfg:       cfg,
		origin:    u,
		cacheDisk: cd,
		matchers:  matchers,
		locks:     newKeyedLocker(),
		client:    &http.Client{Transport: transport},
		proxy:     rp,
	}

	if len(recacheMatchers) > 0 && cfg.RecacheWorkers > 0 {
		h.recache = newRecacheScheduler(cd, u, h.client, h.locks, recacheMatchers, cfg.RecacheAhead, cfg.RecacheWorkers)
	}

	return h, nil
}

// StartBackground launches background components (like recache scheduler).
// It is safe to call multiple times.
func (h *Handler) StartBackground(ctx context.Context) {
	// Start is idempotent enough for our usage (single start from main).
	if h.recache != nil {
		h.recache.Start(ctx)
	}

	// Disk cache garbage collector: delete expired entries periodically.
	if h.cacheDisk.Dir != "" && h.cacheDisk.TTL > 0 {
		go func() {
			t := time.NewTicker(h.cacheDisk.TTL)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					_, _ = h.cacheDisk.SweepExpired(now)
				}
			}
		}()
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// We only cache GET/HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.proxy.ServeHTTP(w, r)
		return
	}

	path := r.URL.Path
	cacheable := h.shouldCache(path)

	// Range support (single range): if full file is already cached, serve range from disk.
	// Otherwise proxy the range request and (if cacheable) fill the full file in background.
	if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
		if cacheable {
			now := time.Now()
			meta, f, ok, err := h.cacheDisk.LoadFresh(path, now)
			if err != nil {
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			if ok {
				defer f.Close()
				if h.serveSingleRangeFromCache(w, r, meta, f, now, rangeHdr) {
					return
				}
			}

			// Cache miss or unsupported range format: still proxy the range request,
			// but start background full download to populate cache for next time.
			h.maybeFillFullInBackground(r)
		}

		h.proxy.ServeHTTP(w, r)
		return
	}

	if !cacheable {
		h.proxy.ServeHTTP(w, r)
		return
	}

	now := time.Now()
	meta, f, ok, err := h.cacheDisk.LoadFresh(path, now)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if ok {
		defer f.Close()
		h.serveFromCache(w, r, meta, f, now)
		return
	}

	// Serialize cache fills per-key.
	key := cache.KeyForPath(path)

	// Non-blocking lock: if another client is already fetching this file,
	// we do not wait. We simply bypass the cache for this request and
	// stream directly from upstream to ensure low latency for everyone.
	unlock, ok := h.locks.TryLock(key)
	if !ok {
		h.proxy.ServeHTTP(w, r)
		return
	}
	defer unlock()

	// Re-check after acquiring lock (though with TryLock this is less likely to change,
	// but good practice if we ever revert to blocking).
	now = time.Now()
	meta, f, ok, err = h.cacheDisk.LoadFresh(path, now)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if ok {
		defer f.Close()
		h.serveFromCache(w, r, meta, f, now)
		return
	}

	// For HEAD: we can serve from cache (above), but we don't populate cache via HEAD.
	if r.Method == http.MethodHead {
		h.proxy.ServeHTTP(w, r)
		return
	}

	h.fetchAndCache(w, r)
}

func (h *Handler) shouldCache(path string) bool {
	if len(h.matchers) == 0 {
		return false
	}
	for _, m := range h.matchers {
		if m.Match(path) {
			return true
		}
	}
	return false
}

func (h *Handler) serveSingleRangeFromCache(w http.ResponseWriter, r *http.Request, meta *cache.Meta, f *os.File, now time.Time, rangeHdr string) bool {
	// Only support "bytes=<start>-<end>", "bytes=<start>-", "bytes=-<suffix>" and only a single range.
	// If unsupported, return false to fallback to proxying.
	size := meta.Size
	if size <= 0 {
		return false
	}
	if meta.Status != http.StatusOK {
		return false
	}

	start, end, ok := parseSingleByteRange(rangeHdr, size)
	if !ok {
		return false
	}

	// Serve headers from cached meta, plus ProxyBuff diagnostics.
	copyHeader(w.Header(), meta.Header)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.Header().Set("X-ProxyBuff-Cache", "HIT")

	if h.cfg.AgeHeader {
		age := int(now.Sub(meta.CreatedAt).Seconds())
		if age < 0 {
			age = 0
		}
		w.Header().Set("Age", strconv.Itoa(age))
	}

	w.WriteHeader(http.StatusPartialContent)
	if r.Method == http.MethodHead {
		return true
	}

	// Ensure we only read the requested bytes.
	_, _ = f.Seek(0, io.SeekStart)
	sr := io.NewSectionReader(f, start, end-start+1)
	_, _ = io.Copy(w, sr)
	return true
}

func parseSingleByteRange(h string, size int64) (start int64, end int64, ok bool) {
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(h, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimSpace(strings.TrimPrefix(h, "bytes="))
	if spec == "" {
		return 0, 0, false
	}
	// Only single range supported (no commas).
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a := strings.TrimSpace(parts[0])
	b := strings.TrimSpace(parts[1])

	// suffix-byte-range-spec: "-<suffix>"
	if a == "" {
		if b == "" {
			return 0, 0, false
		}
		suf, err := strconv.ParseInt(b, 10, 64)
		if err != nil || suf <= 0 {
			return 0, 0, false
		}
		if suf > size {
			suf = size
		}
		return size - suf, size - 1, true
	}

	// "<start>-<end>" or "<start>-"
	s, err := strconv.ParseInt(a, 10, 64)
	if err != nil || s < 0 {
		return 0, 0, false
	}
	if s >= size {
		return 0, 0, false
	}
	if b == "" {
		return s, size - 1, true
	}
	e, err := strconv.ParseInt(b, 10, 64)
	if err != nil || e < 0 {
		return 0, 0, false
	}
	if e < s {
		return 0, 0, false
	}
	if e >= size {
		e = size - 1
	}
	return s, e, true
}

func (h *Handler) maybeFillFullInBackground(r *http.Request) {
	// Only for GET (HEAD doesn't need body).
	if r.Method != http.MethodGet {
		return
	}

	path := r.URL.Path
	key := cache.KeyForPath(path)
	unlock, ok := h.locks.TryLock(key)
	if !ok {
		return
	}

	// If we got the lock, do the full fetch in a goroutine to not block this request.
	go func() {
		defer unlock()

		// If another request filled it while we were queued to run, avoid extra origin hit.
		_, _, fresh, err := h.cacheDisk.LoadFresh(path, time.Now())
		if err == nil && fresh {
			return
		}

		h.fetchFullToCache(r, path)
	}()
}

func (h *Handler) fetchFullToCache(src *http.Request, path string) {
	upstreamURL := h.upstreamURL(src.URL)

	// Detach from the client request: this fill should continue even if the client disconnects.
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		return
	}

	// Copy client headers, but ensure no Range and stable cached variants.
	req.Header = cloneHeader(src.Header)
	req.Header.Del("Range")
	removeHopByHopRequestHeaders(req.Header)
	req.Header.Set("Accept-Encoding", "identity")

	// Preserve Host behavior.
	if h.cfg.UseOriginHost {
		req.Host = h.origin.Host
	} else {
		req.Host = src.Host
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}

	now := time.Now()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := h.cacheDisk.PrepareWrite(path)
	if err != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}

	f, err := os.Create(tmpBody)
	if err != nil {
		_ = os.Remove(tmpMeta)
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}

	n, err := io.Copy(f, resp.Body)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmpBody)
		_ = os.Remove(tmpMeta)
		return
	}

	if err := os.Rename(tmpBody, bodyFinal); err != nil {
		_ = os.Remove(tmpBody)
		_ = os.Remove(tmpMeta)
		return
	}

	storedHeader := filterHopByHopResponseHeaders(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(n, 10))

	meta := &cache.Meta{
		Path:      path,
		Status:    resp.StatusCode,
		Header:    storedHeader,
		CreatedAt: now,
		ExpiresAt: now.Add(h.cacheDisk.TTL),
		Size:      n,
	}

	if err := h.cacheDisk.WriteMeta(tmpMeta, metaFinal, meta); err != nil {
		_ = os.Remove(metaFinal)
		_ = os.Remove(bodyFinal)
		return
	}

	if h.recache != nil {
		h.recache.Update(path, meta.ExpiresAt)
	}
}

func (h *Handler) serveFromCache(w http.ResponseWriter, r *http.Request, meta *cache.Meta, f *os.File, now time.Time) {
	// Serve headers from cached meta (filtered at store-time), plus ProxyBuff diagnostics.
	copyHeader(w.Header(), meta.Header)
	w.Header().Set("X-ProxyBuff-Cache", "HIT")

	if h.cfg.AgeHeader {
		age := int(now.Sub(meta.CreatedAt).Seconds())
		if age < 0 {
			age = 0
		}
		w.Header().Set("Age", strconv.Itoa(age))
	}

	// Ensure Content-Length matches our cached body size.
	if meta.Size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	}

	w.WriteHeader(meta.Status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, f)
}

var bufPool = sync.Pool{
	New: func() interface{} {
		// 32KB buffer
		return make([]byte, 32*1024)
	},
}

func (h *Handler) fetchAndCache(w http.ResponseWriter, r *http.Request) {
	upstreamURL := h.upstreamURL(r.URL)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	req.Header = cloneHeader(r.Header)
	removeHopByHopRequestHeaders(req.Header)
	// Ensure cached variants are stable across clients.
	req.Header.Set("Accept-Encoding", "identity")

	// X-Forwarded-For
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		prior := req.Header.Get("X-Forwarded-For")
		if prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+ip)
		} else {
			req.Header.Set("X-Forwarded-For", ip)
		}
	}
	req.Header.Set("X-Forwarded-Host", r.Host)
	if r.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}

	if h.cfg.UseOriginHost {
		req.Host = h.origin.Host
	} else {
		req.Host = r.Host
	}

	resp, err := h.client.Do(req)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Always forward response to client. Cache only 200 OK.
	outHeader := filterHopByHopResponseHeaders(resp.Header)
	copyHeader(w.Header(), outHeader)
	w.Header().Set("X-ProxyBuff-Cache", "MISS")
	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(w, resp.Body)
		return
	}

	// Prepare cache write.
	now := time.Now()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := h.cacheDisk.PrepareWrite(r.URL.Path)
	if err != nil {
		// Can't cache; just proxy body.
		_, _ = io.Copy(w, resp.Body)
		return
	}

	// Async writer setup
	// 8MB buffer for async disk writes
	diskCh := make(chan []byte, 8*1024*1024/(32*1024)) // approx slots for 32k chunks to total 8MB
	diskErrCh := make(chan error, 1)
	var diskCloseOnce sync.Once
	closeDisk := func() { diskCloseOnce.Do(func() { close(diskCh) }) }

	// Start background writer
	go func() {
		defer close(diskErrCh)

		f, err := os.Create(tmpBody)
		if err != nil {
			diskErrCh <- err
			return
		}
		defer f.Close()

		for b := range diskCh {
			if _, err := f.Write(b); err != nil {
				diskErrCh <- err
				// drain channel to not block sender, and put buffers back
				bufPool.Put(b)
				for remaining := range diskCh {
					bufPool.Put(remaining)
				}
				return
			}
			bufPool.Put(b) // Return buffer to pool after writing to disk
		}
	}()

	var (
		cached       = true
		cachedBytes  int64
		clientClosed = false
		writeFailed  = false
	)

	// Cleanup if caching failed or aborted
	defer func() {
		if !cached {
			closeDisk() // Ensure writer finishes
			// Drain any errors
			<-diskErrCh
			_ = os.Remove(tmpMeta)
			_ = os.Remove(tmpBody)
		}
	}()

	for {
		// Check context before reading to support cancellation
		select {
		case <-r.Context().Done():
			clientClosed = true
			if cached {
				cached = false // Abort caching on partial download
			}
			return
		default:
		}

		buf := bufPool.Get().([]byte)
		// Reset len only? No, Read takes slice. Cap is 32k.
		// We use buf[:cap] just to be safe we offer full buffer to Read.
		// NOTE: New() returns 32k len/cap. TryLock/Put doesn't change cap.
		// If previous user sliced it to [:100], Put(slice) keeps cap=32k.
		// But verify: Go slices... passing slice header.
		// We should re-slice to full capacity before Read.
		buf = buf[:cap(buf)]

		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]

			// 1. Send to client
			if !clientClosed {
				if _, err := w.Write(chunk); err != nil {
					clientClosed = true
					cached = false
				}
			}

			// 2. Send to disk async
			if cached && !writeFailed {
				// Hand off ownership of 'chunk' (backed by 'buf') to the writer
				select {
				case diskCh <- chunk:
					// Ownership transferred to writer.
					// Writer will Put() it back.
				default:
					// Channel full - disk too slow
					writeFailed = true
					cached = false
					bufPool.Put(buf) // We kept ownership, so we Put
				}
			} else {
				// Not caching (or failed), we own the buffer, so return it
				bufPool.Put(buf)
			}

			cachedBytes += int64(n)
		} else {
			// n == 0, if we didn't use the buffer, Put it back immediately
			if cap(buf) > 0 { // Safety check
				bufPool.Put(buf)
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			// Upstream read error
			cached = false
			break
		}
	}

	// Close channel to signal writer to finish
	closeDisk()

	// Wait for writer to finish and check error
	if err := <-diskErrCh; err != nil {
		cached = false
	}

	if !cached {
		// Defer handles cleanup
		return
	}

	// Rename and save meta...
	if err := os.Rename(tmpBody, bodyFinal); err != nil {
		_ = os.Remove(tmpBody)
		return
	}

	storedHeader := filterHopByHopResponseHeaders(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(cachedBytes, 10))

	meta := &cache.Meta{
		Path:      r.URL.Path,
		Status:    resp.StatusCode,
		Header:    storedHeader,
		CreatedAt: now,
		ExpiresAt: now.Add(h.cacheDisk.TTL),
		Size:      cachedBytes,
	}

	if err := h.cacheDisk.WriteMeta(tmpMeta, metaFinal, meta); err != nil {
		_ = os.Remove(metaFinal)
		_ = os.Remove(bodyFinal)
		return
	}

	// Notify scheduler if this path is configured for recache.
	if h.recache != nil {
		h.recache.Update(r.URL.Path, meta.ExpiresAt)
	}
}

func (h *Handler) upstreamURL(in *url.URL) *url.URL {
	u := *h.origin
	u.Path = singleJoiningSlash(h.origin.Path, in.Path)
	u.RawQuery = in.RawQuery
	u.Fragment = ""
	return &u
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func cloneHeader(hdr http.Header) http.Header {
	out := make(http.Header, len(hdr))
	for k, vv := range hdr {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		out[k] = vv2
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func removeHopByHopRequestHeaders(h http.Header) {
	// https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(k)
	}
}

func filterHopByHopResponseHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for k, vv := range in {
		if isHopByHopHeader(k) {
			continue
		}
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		out[k] = vv2
	}
	return out
}

func isHopByHopHeader(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}
