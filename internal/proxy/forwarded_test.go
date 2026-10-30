// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quardexus/proxybuff/internal/config"
)

type seenHeaders struct {
	method string
	rng    string
	h      http.Header
}

// newForwardedTestHandler starts an origin that reports the request headers
// it receives and a Handler in front of it.
func newForwardedTestHandler(t *testing.T, proxyProtocolFrom []string) (*Handler, <-chan seenHeaders) {
	t.Helper()
	seen := make(chan seenHeaders, 16)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- seenHeaders{method: r.Method, rng: r.Header.Get("Range"), h: r.Header.Clone()}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("0123456789"))
	}))
	t.Cleanup(origin.Close)
	h, err := New(config.Config{
		HTTPEnabled:       true,
		HttpListen:        "127.0.0.1:0",
		CacheDir:          t.TempDir(),
		TTL:               time.Minute,
		Origin:            origin.URL,
		Cache:             []string{"/static/*"},
		CacheVaryHost:     true,
		ProxyProtocolFrom: proxyProtocolFrom,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, seen
}

func forgedRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "iam.example.com"
	// As set by the PROXY protocol listener from the verified header.
	r.RemoteAddr = "203.0.113.7:51234"
	r.Header.Add("X-Forwarded-For", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "7.7.7.7, 8.8.8.8")
	r.Header.Set("X-Real-IP", "6.6.6.6")
	r.Header.Set("Forwarded", "for=6.6.6.6;proto=https")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	// Try to have the hop-by-hop pass delete the headers proxybuff sets.
	r.Header.Set("Connection", "keep-alive, X-Real-IP, Forwarded")
	return r
}

func waitSeen(t *testing.T, seen <-chan seenHeaders, wantRange bool) seenHeaders {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case s := <-seen:
			if (s.rng != "") == wantRange {
				return s
			}
		case <-deadline:
			t.Fatalf("origin request (range=%v) not seen", wantRange)
		}
	}
}

func assertOwnedForwarded(t *testing.T, path string, got http.Header) {
	t.Helper()
	if v := strings.Join(got.Values("X-Forwarded-For"), " | "); v != "203.0.113.7" {
		t.Errorf("%s: X-Forwarded-For = %q, want only the verified client IP", path, v)
	}
	if v := strings.Join(got.Values("X-Real-IP"), " | "); v != "203.0.113.7" {
		t.Errorf("%s: X-Real-IP = %q, want the verified client IP", path, v)
	}
	if v := strings.Join(got.Values("Forwarded"), " | "); v != "for=203.0.113.7;proto=http;host=iam.example.com" {
		t.Errorf("%s: Forwarded = %q", path, v)
	}
	if v := got.Get("X-Forwarded-Host"); v != "iam.example.com" {
		t.Errorf("%s: X-Forwarded-Host = %q", path, v)
	}
	if v := got.Get("X-Forwarded-Proto"); v != "http" {
		t.Errorf("%s: X-Forwarded-Proto = %q", path, v)
	}
	for k, vv := range got {
		for _, v := range vv {
			if strings.Contains(v, "6.6.6.6") || strings.Contains(v, "7.7.7.7") || strings.Contains(v, "evil.example") {
				t.Errorf("%s: forged value reached the origin: %s: %q", path, k, v)
			}
		}
	}
}

// In PROXY protocol mode proxybuff is the first HTTP hop: whatever forwarding
// headers the client sends must not reach the origin (IAM) on any path.
func TestForgedForwardingHeadersAreReplaced(t *testing.T) {
	h, seen := newForwardedTestHandler(t, []string{"10.0.0.1"})

	t.Run("passThrough", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, forgedRequest(http.MethodPost, "/login"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		assertOwnedForwarded(t, "passThrough", waitSeen(t, seen, false).h)
	})

	t.Run("fetchAndCache", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, forgedRequest(http.MethodGet, "/static/a.txt"))
		if rec.Code != http.StatusOK || rec.Header().Get("X-ProxyBuff-Cache") != "MISS" {
			t.Fatalf("status = %d, cache = %q", rec.Code, rec.Header().Get("X-ProxyBuff-Cache"))
		}
		assertOwnedForwarded(t, "fetchAndCache", waitSeen(t, seen, false).h)
	})

	t.Run("rangeAndBackgroundFill", func(t *testing.T) {
		r := forgedRequest(http.MethodGet, "/static/b.txt")
		r.Header.Set("Range", "bytes=0-3")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		// The range itself is passed through; the full file is fetched in
		// the background without the Range header.
		assertOwnedForwarded(t, "range passThrough", waitSeen(t, seen, true).h)
		assertOwnedForwarded(t, "fetchFullToCache", waitSeen(t, seen, false).h)
		// Let the background fill finish writing before TempDir cleanup.
		for deadline := time.Now().Add(5 * time.Second); len(h.bgSem) > 0; {
			if time.Now().After(deadline) {
				t.Fatal("background fill did not finish")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// Without PROXY protocol the historical behaviour is kept: the client IP is
// appended to the client's X-Forwarded-For (proxybuff may sit behind another
// HTTP proxy).
func TestForwardingHeadersAppendWhenProxyProtocolOff(t *testing.T) {
	h, seen := newForwardedTestHandler(t, nil)
	r := forgedRequest(http.MethodPost, "/login")
	r.Header.Del("Connection")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	got := waitSeen(t, seen, false).h
	if v := got.Get("X-Forwarded-For"); v != "6.6.6.6, 7.7.7.7, 8.8.8.8, 203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q", v)
	}
	if v := got.Get("X-Real-IP"); v != "6.6.6.6" {
		t.Errorf("X-Real-IP = %q, want it passed through unchanged", v)
	}
}

func TestForwardedValue(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":        "203.0.113.7",
		"[2001:db8::1]":      `"[2001:db8::1]"`,
		"example.com":        "example.com",
		"example.com:8443":   `"example.com:8443"`,
		`a"b\c`:              `"a\"b\\c"`,
		"":                   `""`,
		"x-y_z.example~ok!#": "x-y_z.example~ok!#",
	}
	for in, want := range cases {
		if got := forwardedValue(in); got != want {
			t.Errorf("forwardedValue(%q) = %s, want %s", in, got, want)
		}
	}
}
