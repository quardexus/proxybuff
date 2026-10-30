// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestParseBackwardCompatNoHosts(t *testing.T) {
	// --http uses the =port form (it is a bool-style flag so `--http 8080` would
	// stop parsing at the positional 8080), matching the documented usage.
	cfg, err := Parse([]string{"--origin", "https://example.com", "--http=8080", "--cache", "/", "--ttl", "3m"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Hosts) != 0 {
		t.Errorf("expected no hosts, got %d", len(cfg.Hosts))
	}
	if cfg.Origin != "https://example.com" {
		t.Errorf("origin = %q", cfg.Origin)
	}
	if cfg.HttpListen != "0.0.0.0:8080" {
		t.Errorf("httpListen = %q", cfg.HttpListen)
	}
	if cfg.TTL != 3*time.Minute {
		t.Errorf("ttl = %v", cfg.TTL)
	}
	if !cfg.CacheVaryHost || !cfg.CacheKeyQuery {
		t.Errorf("cache-vary-host and cache-key-query should default on")
	}
}

func TestCacheKeyFlagsCanBeDisabled(t *testing.T) {
	cfg, err := Parse([]string{"--origin", "https://example.com", "--cache-vary-host=false", "--cache-key-query=false"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CacheVaryHost || cfg.CacheKeyQuery {
		t.Errorf("flags should have been disabled: varyHost=%v keyQuery=%v", cfg.CacheVaryHost, cfg.CacheKeyQuery)
	}
}

func TestParseMultiHostConfig(t *testing.T) {
	p := writeTempConfig(t, `{
	  "httpListen": "0.0.0.0:8080",
	  "ttl": "5m",
	  "cache": ["*.png"],
	  "origin": "https://default.example.com",
	  "hosts": [
	    {"match": ["a.com", "www.a.com"], "origin": "https://a-origin.example.com", "cache": ["/", "*.jpg"], "tlsDomains": ["a.com", "www.a.com"]},
	    {"match": ["*.b.com"], "origin": "https://b-origin.example.com", "ttl": "1m"}
	  ]
	}`)

	cfg, err := Parse([]string{"--config", p})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("hosts = %d, want 2", len(cfg.Hosts))
	}

	a := cfg.Hosts[0]
	if a.Origin != "https://a-origin.example.com" {
		t.Errorf("a.Origin = %q", a.Origin)
	}
	if a.TTL != 5*time.Minute { // inherited from top-level
		t.Errorf("a.TTL = %v, want inherited 5m", a.TTL)
	}
	if len(a.Cache) != 2 {
		t.Errorf("a.Cache = %v, want its own two patterns", a.Cache)
	}
	if len(a.TLSDomains) != 2 {
		t.Errorf("a.TLSDomains = %v", a.TLSDomains)
	}

	b := cfg.Hosts[1]
	if b.Origin != "https://b-origin.example.com" {
		t.Errorf("b.Origin = %q", b.Origin)
	}
	if b.TTL != time.Minute { // explicit override
		t.Errorf("b.TTL = %v, want 1m", b.TTL)
	}
	if len(b.Cache) != 1 || b.Cache[0] != "*.png" { // inherited from top-level
		t.Errorf("b.Cache = %v, want inherited [*.png]", b.Cache)
	}
	if len(b.TLSDomains) != 0 { // only wildcard match → no concrete cert domain
		t.Errorf("b.TLSDomains = %v, want empty", b.TLSDomains)
	}
}

func TestMultiHostRequiresOrigin(t *testing.T) {
	p := writeTempConfig(t, `{"httpListen": "0.0.0.0:8080", "hosts": [{"match": ["a.com"]}]}`)
	if _, err := Parse([]string{"--config", p}); err == nil {
		t.Fatal("expected error: host without origin and no top-level origin to inherit")
	}
}

func TestMultiHostInheritsTopLevelOrigin(t *testing.T) {
	p := writeTempConfig(t, `{
	  "httpListen": "0.0.0.0:8080",
	  "origin": "https://shared.example.com",
	  "hosts": [{"match": ["a.com"]}, {"match": ["b.com"]}]
	}`)
	cfg, err := Parse([]string{"--config", p})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for i, h := range cfg.Hosts {
		if h.Origin != "https://shared.example.com" {
			t.Errorf("hosts[%d].Origin = %q, want inherited shared origin", i, h.Origin)
		}
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	p := writeTempConfig(t, `{"origin": "https://example.com", "bogusKey": 1}`)
	if _, err := Parse([]string{"--config", p}); err == nil {
		t.Fatal("expected error for unknown config key")
	}
}

func TestParseRejectsUnknownHostKey(t *testing.T) {
	p := writeTempConfig(t, `{"origin": "https://example.com", "hosts": [{"match": ["a.com"], "bogus": true}]}`)
	if _, err := Parse([]string{"--config", p}); err == nil {
		t.Fatal("expected error for unknown key inside a host entry")
	}
}

func TestNormalizeOriginScheme(t *testing.T) {
	// Hostnames without scheme default to http; a scheme is left untouched.
	if got, tlsIP := normalizeOrigin("example.com"); got != "http://example.com" || tlsIP {
		t.Errorf("normalizeOrigin(example.com) = %q,%v", got, tlsIP)
	}
	if got, _ := normalizeOrigin("https://example.com:443"); got != "https://example.com:443" {
		t.Errorf("scheme should be preserved, got %q", got)
	}
}

func TestProxyProtocolFromDefaultsOff(t *testing.T) {
	cfg, err := Parse([]string{"--origin", "https://example.com"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.ProxyProtocolFrom) != 0 {
		t.Fatalf("proxyProtocolFrom = %v, want empty", cfg.ProxyProtocolFrom)
	}
	al, err := cfg.ProxyProtocolAllowList()
	if err != nil || al.Len() != 0 {
		t.Fatalf("allow list = %v, %v; want empty", al, err)
	}
}

func TestProxyProtocolFromFlags(t *testing.T) {
	cfg, err := Parse([]string{
		"--origin", "https://example.com",
		"--proxy-protocol-from", "10.0.0.0/8, 192.168.1.5",
		"--proxy-protocol-from=2001:db8::/32",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"10.0.0.0/8", "192.168.1.5", "2001:db8::/32"}
	if strings.Join(cfg.ProxyProtocolFrom, "|") != strings.Join(want, "|") {
		t.Fatalf("proxyProtocolFrom = %v, want %v", cfg.ProxyProtocolFrom, want)
	}
	al, err := cfg.ProxyProtocolAllowList()
	if err != nil || al.Len() != 3 {
		t.Fatalf("allow list = %v, %v", al, err)
	}
}

func TestProxyProtocolFromJSONAndFlagOverride(t *testing.T) {
	p := writeTempConfig(t, `{"origin": "https://example.com", "proxyProtocolFrom": ["172.18.0.0/16", "172.19.0.2"]}`)
	cfg, err := Parse([]string{"--config", p})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.Join(cfg.ProxyProtocolFrom, ",") != "172.18.0.0/16,172.19.0.2" {
		t.Fatalf("proxyProtocolFrom = %v", cfg.ProxyProtocolFrom)
	}

	cfg, err = Parse([]string{"--config", p, "--proxy-protocol-from", "127.0.0.1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.Join(cfg.ProxyProtocolFrom, ",") != "127.0.0.1" {
		t.Fatalf("flag should override JSON, got %v", cfg.ProxyProtocolFrom)
	}
}

func TestProxyProtocolFromRejectsInvalid(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "300.0.0.1", "nginx", "fe80::1%eth0", "10.0.0.0/x"} {
		_, err := Parse([]string{"--origin", "https://example.com", "--proxy-protocol-from", bad})
		if err == nil || !strings.Contains(err.Error(), "proxyProtocolFrom") {
			t.Errorf("flag %q: err = %v, want proxyProtocolFrom error", bad, err)
		}
	}
	p := writeTempConfig(t, `{"origin": "https://example.com", "proxyProtocolFrom": ["10.0.0.0/8", "bad/cidr"]}`)
	if _, err := Parse([]string{"--config", p}); err == nil || !strings.Contains(err.Error(), "bad/cidr") {
		t.Errorf("JSON: err = %v, want error naming the bad entry", err)
	}
	p = writeTempConfig(t, `{"origin": "https://example.com", "proxyProtocolFrom": "10.0.0.0/8"}`)
	if _, err := Parse([]string{"--config", p}); err == nil {
		t.Errorf("JSON: proxyProtocolFrom must be an array")
	}
}

// A blank entry (unset env var, stray comma, "" in JSON) must fail startup
// rather than silently disabling the feature or overriding the JSON list.
func TestProxyProtocolFromRejectsBlankEntries(t *testing.T) {
	for _, bad := range []string{"", "  ", "10.0.0.1,", ",10.0.0.1", "10.0.0.1,,10.0.0.2"} {
		_, err := Parse([]string{"--origin", "https://example.com", "--proxy-protocol-from", bad})
		if err == nil || !strings.Contains(err.Error(), "empty entry") {
			t.Errorf("flag %q: err = %v, want empty entry error", bad, err)
		}
	}
	p := writeTempConfig(t, `{"origin": "https://example.com", "proxyProtocolFrom": ["172.18.0.5"]}`)
	if _, err := Parse([]string{"--config", p, "--proxy-protocol-from", ""}); err == nil {
		t.Errorf("empty flag must not silently clear the JSON list")
	}
	for _, js := range []string{`[""]`, `["10.0.0.1", " "]`} {
		p := writeTempConfig(t, `{"origin": "https://example.com", "proxyProtocolFrom": `+js+`}`)
		if _, err := Parse([]string{"--config", p}); err == nil || !strings.Contains(err.Error(), "proxyProtocolFrom") {
			t.Errorf("JSON %s: err = %v, want proxyProtocolFrom error", js, err)
		}
	}
	// An explicit empty JSON array is a valid "off".
	p = writeTempConfig(t, `{"origin": "https://example.com", "proxyProtocolFrom": []}`)
	cfg, err := Parse([]string{"--config", p})
	if err != nil || len(cfg.ProxyProtocolFrom) != 0 {
		t.Errorf("empty array: cfg = %v, err = %v", cfg.ProxyProtocolFrom, err)
	}
}

func TestProxyProtocolOn(t *testing.T) {
	base := []string{"--origin", "https://example.com", "--proxy-protocol-from", "172.30.0.10"}
	cfg, err := Parse(base)
	if err != nil || !cfg.ProxyProtocolOnHTTP() {
		t.Fatalf("default: OnHTTP = %v, err = %v; want true", cfg.ProxyProtocolOnHTTP(), err)
	}
	tls := []string{"--https=443", "--tls-domain", "iam.example.com"}
	cfg, err = Parse(append(append(append([]string{}, base...), tls...), "--proxy-protocol-on", "https"))
	if err != nil || cfg.ProxyProtocolOnHTTP() {
		t.Fatalf("https: OnHTTP = %v, err = %v; want false", cfg.ProxyProtocolOnHTTP(), err)
	}
	p := writeTempConfig(t, `{"origin": "https://example.com", "httpsEnabled": true, "httpsListen": ":443", "tlsDomains": ["iam.example.com"], "proxyProtocolFrom": ["172.30.0.10"], "proxyProtocolOn": "https"}`)
	cfg, err = Parse([]string{"--config", p})
	if err != nil || cfg.ProxyProtocolOnHTTP() {
		t.Fatalf("JSON https: OnHTTP = %v, err = %v; want false", cfg.ProxyProtocolOnHTTP(), err)
	}
	if _, err := Parse(append(append([]string{}, base...), "--proxy-protocol-on", "https")); err == nil || !strings.Contains(err.Error(), "requires https") {
		t.Errorf("https without TLS: err = %v, want requires https error", err)
	}
	for _, bad := range []string{"http", "HTTPS", "none", " both"} {
		if _, err := Parse(append(append(append([]string{}, base...), tls...), "--proxy-protocol-on", bad)); err == nil || !strings.Contains(err.Error(), "proxyProtocolOn") {
			t.Errorf("%q: err = %v, want proxyProtocolOn error", bad, err)
		}
	}
}
