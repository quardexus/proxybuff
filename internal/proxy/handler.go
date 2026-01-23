package proxy

import (
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
	"time"

	"github.com/quardexus/proxybuff/internal/cache"
	"github.com/quardexus/proxybuff/internal/config"
)

type Handler struct {
	cfg       config.Config
	origin    *url.URL
	cacheDisk cache.Disk
	matchers  []cache.Matcher
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

	return &Handler{
		cfg:       cfg,
		origin:    u,
		cacheDisk: cd,
		matchers:  matchers,
		locks:     newKeyedLocker(),
		client:    &http.Client{Transport: transport},
		proxy:     rp,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// We only cache GET/HEAD without Range.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.proxy.ServeHTTP(w, r)
		return
	}
	if r.Header.Get("Range") != "" {
		h.proxy.ServeHTTP(w, r)
		return
	}

	path := r.URL.Path
	if !h.shouldCache(path) {
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
	unlock := h.locks.Lock(key)
	defer unlock()

	// Re-check after acquiring lock.
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

	bodyFile, err := os.Create(tmpBody)
	if err != nil {
		_, _ = io.Copy(w, resp.Body)
		return
	}
	defer func() {
		_ = bodyFile.Close()
	}()

	var (
		cached       = true
		cachedBytes  int64
		copyBuf      = make([]byte, 32*1024)
		clientClosed = false
	)

	for {
		n, readErr := resp.Body.Read(copyBuf)
		if n > 0 {
			if !clientClosed {
				if _, err := w.Write(copyBuf[:n]); err != nil {
					clientClosed = true
				}
			}
			if cached {
				if _, err := bodyFile.Write(copyBuf[:n]); err != nil {
					cached = false
					_ = bodyFile.Close()
					_ = os.Remove(tmpBody)
				} else {
					cachedBytes += int64(n)
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			// Upstream read error; do not cache partial content.
			cached = false
			break
		}
	}

	if !cached {
		_ = os.Remove(tmpMeta)
		_ = os.Remove(tmpBody)
		return
	}

	_ = bodyFile.Close()
	if err := os.Rename(tmpBody, bodyFinal); err != nil {
		_ = os.Remove(tmpBody)
		return
	}

	storedHeader := filterHopByHopResponseHeaders(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(cachedBytes, 10))

	meta := &cache.Meta{
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
