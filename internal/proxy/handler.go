// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

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

// site is a single routing target: a set of matching hostnames with their own
// origin, cache rules and TLS domains. In single-host mode there is exactly one
// site (with an empty id and no host patterns) that handles every request.
type site struct {
	id            string
	hostMatch     []hostPattern
	tlsDomains    []hostPattern
	origin        *url.URL
	client        *http.Client
	proxy         *httputil.ReverseProxy
	matchers      []cache.Matcher
	ttl           time.Duration
	ageHeader     bool
	useOriginHost bool
	recache       *recacheScheduler
}

func (s *site) shouldCache(path string) bool {
	for _, m := range s.matchers {
		if m.Match(path) {
			return true
		}
	}
	return false
}

func (s *site) upstreamURL(in *url.URL) *url.URL {
	u := *s.origin
	u.Path = singleJoiningSlash(s.origin.Path, in.Path)
	u.RawQuery = in.RawQuery
	u.Fragment = ""
	return &u
}

type Handler struct {
	cfg         config.Config
	sites       []*site
	defaultSite *site
	cacheDisk   cache.Disk
	locks       *keyedLocker

	// bgSem bounds the number of concurrent background full-file downloads
	// triggered by Range misses, to avoid amplification.
	bgSem chan struct{}
}

const (
	maxBackgroundFills     = 16
	backgroundFetchTimeout = 10 * time.Minute
)

func newTransport(insecureSkipVerify bool) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

func New(cfg config.Config) (*Handler, error) {
	cd := cache.Disk{Dir: cfg.CacheDir, TTL: cfg.TTL}
	if err := cd.Validate(); err != nil {
		return nil, err
	}

	h := &Handler{
		cfg:       cfg,
		cacheDisk: cd,
		locks:     newKeyedLocker(),
		bgSem:     make(chan struct{}, maxBackgroundFills),
	}

	if len(cfg.Hosts) == 0 {
		// Single-host mode (backward compatible): one default site handles all.
		s, err := h.buildSite(siteSpec{
			id:            "",
			origin:        cfg.Origin,
			cache:         cfg.Cache,
			recache:       cfg.Recache,
			ttl:           cfg.TTL,
			useOriginHost: cfg.UseOriginHost,
			ageHeader:     cfg.AgeHeader,
			insecure:      cfg.InsecureSkipVerify,
			tlsDomains:    cfg.TLSDomains,
		})
		if err != nil {
			return nil, err
		}
		h.sites = []*site{s}
		h.defaultSite = s
		return h, nil
	}

	for _, hc := range cfg.Hosts {
		id := hc.Match[0]
		s, err := h.buildSite(siteSpec{
			id:            id,
			match:         hc.Match,
			origin:        hc.Origin,
			cache:         hc.Cache,
			recache:       hc.Recache,
			ttl:           hc.TTL,
			useOriginHost: hc.UseOriginHost,
			ageHeader:     hc.AgeHeader,
			insecure:      hc.InsecureSkipVerify,
			tlsDomains:    hc.TLSDomains,
		})
		if err != nil {
			return nil, err
		}
		h.sites = append(h.sites, s)
	}

	// Optional fallback site (from top-level origin) for unmatched Host headers.
	if strings.TrimSpace(cfg.Origin) != "" {
		s, err := h.buildSite(siteSpec{
			id:            "",
			origin:        cfg.Origin,
			cache:         cfg.Cache,
			recache:       cfg.Recache,
			ttl:           cfg.TTL,
			useOriginHost: cfg.UseOriginHost,
			ageHeader:     cfg.AgeHeader,
			insecure:      cfg.InsecureSkipVerify,
			tlsDomains:    cfg.TLSDomains,
		})
		if err != nil {
			return nil, err
		}
		h.sites = append(h.sites, s)
		h.defaultSite = s
	}

	return h, nil
}

type siteSpec struct {
	id            string
	match         []string
	origin        string
	cache         []string
	recache       []string
	ttl           time.Duration
	useOriginHost bool
	ageHeader     bool
	insecure      bool
	tlsDomains    []string
}

func (h *Handler) buildSite(spec siteSpec) (*site, error) {
	u, err := url.Parse(spec.origin)
	if err != nil {
		return nil, fmt.Errorf("parse origin %q: %w", spec.origin, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("origin must be a full URL with scheme and host, got %q", spec.origin)
	}

	matchers, err := cache.CompileMatchers(spec.cache)
	if err != nil {
		return nil, err
	}
	recacheMatchers, err := cache.CompileMatchers(spec.recache)
	if err != nil {
		return nil, err
	}

	transport := newTransport(spec.insecure)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = transport
	useOriginHost := spec.useOriginHost
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		// Save original host before the default director overwrites it.
		originalHost := req.Host
		origDirector(req)
		if !useOriginHost {
			req.Host = originalHost
		}
	}
	client := &http.Client{Transport: transport}

	s := &site{
		id:            spec.id,
		hostMatch:     parseHostPatterns(spec.match),
		tlsDomains:    parseHostPatterns(spec.tlsDomains),
		origin:        u,
		client:        client,
		proxy:         rp,
		matchers:      matchers,
		ttl:           spec.ttl,
		ageHeader:     spec.ageHeader,
		useOriginHost: useOriginHost,
	}

	if len(recacheMatchers) > 0 && h.cfg.RecacheWorkers > 0 {
		s.recache = newRecacheScheduler(spec.id, h.cacheDisk, u, client, h.locks, recacheMatchers, spec.ttl, h.cfg.RecacheAhead, h.cfg.RecacheWorkers)
	}
	return s, nil
}

// resolveSite selects the site for a request Host, preferring exact matches
// over wildcards and falling back to the default site (which is the only site
// in single-host mode).
func (h *Handler) resolveSite(hostHeader string) *site {
	host := hostHeader
	if strings.Contains(host, ":") {
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))

	for _, s := range h.sites {
		for _, hp := range s.hostMatch {
			if !hp.wildcard && hp.exact == host {
				return s
			}
		}
	}
	for _, s := range h.sites {
		for _, hp := range s.hostMatch {
			if hp.wildcard && hp.match(host) {
				return s
			}
		}
	}
	return h.defaultSite
}

// HostPolicy is an autocert.HostPolicy that permits any hostname matching a
// configured TLS domain (exact or wildcard) across all sites.
func (h *Handler) HostPolicy(_ context.Context, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, s := range h.sites {
		for _, hp := range s.tlsDomains {
			if hp.match(host) {
				return nil
			}
		}
	}
	return fmt.Errorf("acme: host %q is not configured for TLS", host)
}

// TLSDomains lists the configured TLS domain patterns across all sites (for logging).
func (h *Handler) TLSDomains() []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range h.sites {
		for _, hp := range s.tlsDomains {
			if !seen[hp.raw] {
				seen[hp.raw] = true
				out = append(out, hp.raw)
			}
		}
	}
	return out
}

// StartBackground launches background components (recache schedulers and the
// disk garbage collector). It is intended to be called once from main.
func (h *Handler) StartBackground(ctx context.Context) {
	for _, s := range h.sites {
		if s.recache != nil {
			s.recache.Start(ctx)
		}
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
	s := h.resolveSite(r.Host)
	if s == nil {
		http.Error(w, "no route for host", http.StatusBadGateway)
		return
	}

	// We only cache GET/HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.passThrough(s, w, r)
		return
	}

	path := r.URL.Path
	cacheable := s.shouldCache(path)

	// Range support (single range): if full file is already cached, serve range from disk.
	// Otherwise proxy the range request and (if cacheable) fill the full file in background.
	if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
		if cacheable {
			key := h.cacheKey(s, r).Hash()
			now := time.Now()
			meta, f, ok, err := h.cacheDisk.LoadFresh(key, now)
			if err != nil {
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			if ok {
				defer f.Close()
				if h.serveSingleRangeFromCache(s, w, r, meta, f, now, rangeHdr) {
					return
				}
			}

			// Cache miss or unsupported range format: still proxy the range request,
			// but start background full download to populate cache for next time.
			h.maybeFillFullInBackground(s, r)
		}

		h.passThrough(s, w, r)
		return
	}

	if !cacheable {
		h.passThrough(s, w, r)
		return
	}

	k := h.cacheKey(s, r)
	key := k.Hash()

	now := time.Now()
	meta, f, ok, err := h.cacheDisk.LoadFresh(key, now)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if ok {
		defer f.Close()
		h.serveFromCache(s, w, r, meta, f, now)
		return
	}

	// Non-blocking lock: if another client is already fetching this entry,
	// we do not wait. We simply bypass the cache for this request and
	// stream directly from upstream to ensure low latency for everyone.
	unlock, ok := h.locks.TryLock(key)
	if !ok {
		h.passThrough(s, w, r)
		return
	}
	defer unlock()

	// Re-check after acquiring lock (though with TryLock this is less likely to change,
	// but good practice if we ever revert to blocking).
	now = time.Now()
	meta, f, ok, err = h.cacheDisk.LoadFresh(key, now)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if ok {
		defer f.Close()
		h.serveFromCache(s, w, r, meta, f, now)
		return
	}

	// For HEAD: we can serve from cache (above), but we don't populate cache via HEAD.
	if r.Method == http.MethodHead {
		h.passThrough(s, w, r)
		return
	}

	h.fetchAndCache(s, w, r, k)
}

// cacheKey builds the cache identity for a request based on configuration.
// Site (host namespace) and Path are always included; Host and query are
// included when enabled (default on).
func (h *Handler) cacheKey(s *site, r *http.Request) cache.Key {
	k := cache.Key{Site: s.id, Path: r.URL.Path}
	// Varying by Host is only meaningful when we forward the client's Host upstream.
	if h.cfg.CacheVaryHost && !s.useOriginHost {
		k.Host = r.Host
	}
	if h.cfg.CacheKeyQuery {
		k.Query = r.URL.RawQuery
	}
	return k
}

// passThrough proxies a request to the site origin without caching, tagging the
// response as a cache MISS for observability.
func (h *Handler) passThrough(s *site, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-ProxyBuff-Cache", "MISS")
	s.proxy.ServeHTTP(w, r)
}

// cacheableResponse reports whether a response may be stored and later shared
// across clients. It refuses authenticated requests and responses the origin
// marked as uncacheable or as varying on request headers we do not key on.
func cacheableResponse(respHeader, reqHeader http.Header) bool {
	if reqHeader.Get("Authorization") != "" {
		return false
	}
	cc := strings.ToLower(respHeader.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "private") {
		return false
	}
	// We force Accept-Encoding: identity upstream, so a Vary on Accept-Encoding
	// is harmless. Any other Vary means the origin serves per-request variants
	// that our path/host/query key cannot distinguish, so we refuse to cache.
	if v := respHeader.Get("Vary"); strings.TrimSpace(v) != "" {
		for _, f := range strings.Split(v, ",") {
			switch strings.ToLower(strings.TrimSpace(f)) {
			case "", "accept-encoding":
			default:
				return false
			}
		}
	}
	return true
}

// storedResponseHeader returns the response headers to persist in cache
// metadata. It drops hop-by-hop headers and Set-Cookie, which must never be
// replayed to other clients from cache.
func storedResponseHeader(in http.Header) http.Header {
	out := filterHopByHopResponseHeaders(in)
	out.Del("Set-Cookie")
	return out
}

func (h *Handler) serveSingleRangeFromCache(s *site, w http.ResponseWriter, r *http.Request, meta *cache.Meta, f *os.File, now time.Time, rangeHdr string) bool {
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

	if s.ageHeader {
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

func (h *Handler) maybeFillFullInBackground(s *site, r *http.Request) {
	// Only for GET (HEAD doesn't need body).
	if r.Method != http.MethodGet {
		return
	}

	k := h.cacheKey(s, r)
	key := k.Hash()
	unlock, ok := h.locks.TryLock(key)
	if !ok {
		return
	}

	// Bound the number of concurrent background full downloads to avoid an
	// amplification vector (many distinct Range misses each pulling a full file).
	select {
	case h.bgSem <- struct{}{}:
	default:
		unlock()
		return
	}

	// If we got the lock, do the full fetch in a goroutine to not block this request.
	go func() {
		defer func() { <-h.bgSem }()
		defer unlock()

		// If another request filled it while we were queued to run, avoid extra origin hit.
		if _, _, fresh, err := h.cacheDisk.LoadFresh(key, time.Now()); err == nil && fresh {
			return
		}

		h.fetchFullToCache(s, r, k)
	}()
}

func (h *Handler) fetchFullToCache(s *site, src *http.Request, k cache.Key) {
	upstreamURL := s.upstreamURL(src.URL)

	// Detach from the client request but cap the lifetime so a slow origin can't
	// hold the per-key lock and a goroutine indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), backgroundFetchTimeout)
	defer cancel()
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
	if s.useOriginHost {
		req.Host = s.origin.Host
	} else {
		req.Host = src.Host
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || !cacheableResponse(resp.Header, src.Header) {
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}

	now := time.Now()
	key := k.Hash()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := h.cacheDisk.PrepareWrite(key)
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

	storedHeader := storedResponseHeader(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(n, 10))

	meta := &cache.Meta{
		Path:      k.Path,
		Site:      k.Site,
		Host:      k.Host,
		Query:     k.Query,
		Status:    resp.StatusCode,
		Header:    storedHeader,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
		Size:      n,
	}

	if err := h.cacheDisk.WriteMeta(tmpMeta, metaFinal, meta); err != nil {
		_ = os.Remove(metaFinal)
		_ = os.Remove(bodyFinal)
		return
	}

	if s.recache != nil {
		s.recache.Update(k, meta.ExpiresAt)
	}
}

func (h *Handler) serveFromCache(s *site, w http.ResponseWriter, r *http.Request, meta *cache.Meta, f *os.File, now time.Time) {
	// Serve headers from cached meta (filtered at store-time), plus ProxyBuff diagnostics.
	copyHeader(w.Header(), meta.Header)
	w.Header().Set("X-ProxyBuff-Cache", "HIT")

	if s.ageHeader {
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

func (h *Handler) fetchAndCache(s *site, w http.ResponseWriter, r *http.Request, k cache.Key) {
	upstreamURL := s.upstreamURL(r.URL)

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

	if s.useOriginHost {
		req.Host = s.origin.Host
	} else {
		req.Host = r.Host
	}

	resp, err := s.client.Do(req)
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

	// Cache only 200 OK responses the origin (and request) allow to be shared.
	if resp.StatusCode != http.StatusOK || !cacheableResponse(resp.Header, r.Header) {
		_, _ = io.Copy(w, resp.Body)
		return
	}

	// Prepare cache write.
	now := time.Now()
	key := k.Hash()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := h.cacheDisk.PrepareWrite(key)
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

	storedHeader := storedResponseHeader(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(cachedBytes, 10))

	meta := &cache.Meta{
		Path:      k.Path,
		Site:      k.Site,
		Host:      k.Host,
		Query:     k.Query,
		Status:    resp.StatusCode,
		Header:    storedHeader,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
		Size:      cachedBytes,
	}

	if err := h.cacheDisk.WriteMeta(tmpMeta, metaFinal, meta); err != nil {
		_ = os.Remove(metaFinal)
		_ = os.Remove(bodyFinal)
		return
	}

	// Notify scheduler if this entry is configured for recache.
	if s.recache != nil {
		s.recache.Update(k, meta.ExpiresAt)
	}
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
