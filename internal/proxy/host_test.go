// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxy

import (
	"testing"
	"time"

	"github.com/quardexus/proxybuff/internal/config"
)

func TestHostPatternMatch(t *testing.T) {
	cases := []struct {
		pat  string
		host string
		want bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.COM", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "A.Example.Com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "a.example.com.evil.com", false},
		{"*.example.com", "", false},
	}
	for _, c := range cases {
		hp := parseHostPatterns([]string{c.pat})
		if len(hp) != 1 {
			t.Fatalf("parseHostPatterns(%q) returned %d patterns", c.pat, len(hp))
		}
		if got := hp[0].match(c.host); got != c.want {
			t.Errorf("%q.match(%q) = %v, want %v", c.pat, c.host, got, c.want)
		}
	}
}

func TestResolveSite(t *testing.T) {
	cfg := config.Config{
		HTTPEnabled: true,
		HttpListen:  "127.0.0.1:0",
		CacheDir:    t.TempDir(),
		TTL:         time.Minute,
		Origin:      "http://default.internal", // fallback for unmatched hosts
		Hosts: []config.HostConfig{
			{Match: []string{"a.com", "www.a.com"}, Origin: "http://a.internal", TTL: time.Minute},
			{Match: []string{"*.b.com"}, Origin: "http://b.internal", TTL: time.Minute},
		},
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		host   string
		wantID string
	}{
		{"a.com", "a.com"},
		{"www.a.com", "a.com"},
		{"a.com:8443", "a.com"},
		{"x.b.com", "*.b.com"},
		{"unknown.example", ""}, // falls back to the default site (empty id)
	}
	for _, c := range cases {
		s := h.resolveSite(c.host)
		if s == nil {
			t.Fatalf("resolveSite(%q) = nil", c.host)
		}
		if s.id != c.wantID {
			t.Errorf("resolveSite(%q).id = %q, want %q", c.host, s.id, c.wantID)
		}
	}
}

func TestSingleHostRoutesEverything(t *testing.T) {
	cfg := config.Config{
		HTTPEnabled: true,
		HttpListen:  "127.0.0.1:0",
		CacheDir:    t.TempDir(),
		TTL:         time.Minute,
		Origin:      "http://only.internal",
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, host := range []string{"anything.com", "", "1.2.3.4:80"} {
		if s := h.resolveSite(host); s == nil || s.id != "" {
			t.Errorf("resolveSite(%q) did not return the single default site", host)
		}
	}
}
