// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxy

import "strings"

// hostPattern matches a request Host against a configured domain. It supports
// exact matches and a single leading wildcard label (e.g. "*.example.com",
// which matches "a.example.com" but not "example.com" or "a.b.example.com").
type hostPattern struct {
	raw      string
	wildcard bool
	suffix   string // ".example.com" when wildcard
	exact    string // full host when exact
}

func parseHostPatterns(patterns []string) []hostPattern {
	out := make([]hostPattern, 0, len(patterns))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			out = append(out, hostPattern{raw: p, wildcard: true, suffix: p[1:]})
		} else {
			out = append(out, hostPattern{raw: p, exact: p})
		}
	}
	return out
}

func (hp hostPattern) match(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if hp.wildcard {
		if !strings.HasSuffix(host, hp.suffix) {
			return false
		}
		label := host[:len(host)-len(hp.suffix)]
		return label != "" && !strings.Contains(label, ".")
	}
	return host == hp.exact
}

// exactHosts returns the non-wildcard entries of a match list. These are the
// concrete domains a site can obtain ACME certificates for by default.
func exactHosts(patterns []string) []string {
	var out []string
	for _, hp := range parseHostPatterns(patterns) {
		if !hp.wildcard {
			out = append(out, hp.exact)
		}
	}
	return out
}
