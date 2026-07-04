// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxy

import (
	"net/http"
	"testing"
)

func TestCacheableResponse(t *testing.T) {
	cases := []struct {
		name string
		resp http.Header
		req  http.Header
		want bool
	}{
		{"clean", http.Header{}, http.Header{}, true},
		{"authorized", http.Header{}, http.Header{"Authorization": {"Bearer x"}}, false},
		{"no-store", http.Header{"Cache-Control": {"no-store"}}, http.Header{}, false},
		{"private", http.Header{"Cache-Control": {"private, max-age=60"}}, http.Header{}, false},
		{"vary-ua", http.Header{"Vary": {"User-Agent"}}, http.Header{}, false},
		{"vary-encoding-ok", http.Header{"Vary": {"Accept-Encoding"}}, http.Header{}, true},
		{"vary-star", http.Header{"Vary": {"*"}}, http.Header{}, false},
	}
	for _, c := range cases {
		if got := cacheableResponse(c.resp, c.req); got != c.want {
			t.Errorf("%s: cacheableResponse = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStoredResponseHeaderDropsSetCookie(t *testing.T) {
	in := http.Header{
		"Content-Type": {"image/png"},
		"Set-Cookie":   {"session=secret; HttpOnly"},
		"Connection":   {"keep-alive"},
	}
	out := storedResponseHeader(in)
	if out.Get("Set-Cookie") != "" {
		t.Error("Set-Cookie must not be persisted in cache metadata")
	}
	if out.Get("Connection") != "" {
		t.Error("hop-by-hop Connection must be dropped")
	}
	if out.Get("Content-Type") != "image/png" {
		t.Error("Content-Type should be preserved")
	}
	// The original header must not be mutated.
	if in.Get("Set-Cookie") == "" {
		t.Error("input header was mutated")
	}
}

func TestParseSingleByteRange(t *testing.T) {
	const size = 100
	cases := []struct {
		spec               string
		wantStart, wantEnd int64
		wantOK             bool
	}{
		{"bytes=0-9", 0, 9, true},
		{"bytes=10-", 10, 99, true},
		{"bytes=-20", 80, 99, true},
		{"bytes=-0", 0, 0, false},
		{"bytes=90-500", 90, 99, true},   // clamped to size-1
		{"bytes=100-100", 0, 0, false},   // start >= size
		{"bytes=5-2", 0, 0, false},       // end < start
		{"bytes=0-9,20-29", 0, 0, false}, // multi-range unsupported
		{"items=0-9", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		start, end, ok := parseSingleByteRange(c.spec, size)
		if ok != c.wantOK || (ok && (start != c.wantStart || end != c.wantEnd)) {
			t.Errorf("parseSingleByteRange(%q) = (%d,%d,%v), want (%d,%d,%v)",
				c.spec, start, end, ok, c.wantStart, c.wantEnd, c.wantOK)
		}
	}
}
