// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import "testing"

func TestKeyHashDistinctAndStable(t *testing.T) {
	variants := []Key{
		{Path: "/x"},
		{Site: "a.com", Path: "/x"},
		{Site: "b.com", Path: "/x"},
		{Path: "/x", Host: "a.com"},
		{Path: "/x", Query: "v=1"},
		{Path: "/x", Query: "v=2"},
		{Path: "/y"},
	}
	seen := map[string]int{}
	for i, k := range variants {
		hsum := k.Hash()
		if hsum != k.Hash() {
			t.Errorf("Hash not stable for %+v", k)
		}
		if len(hsum) != 64 {
			t.Errorf("Hash length = %d, want 64 hex chars", len(hsum))
		}
		if prev, ok := seen[hsum]; ok {
			t.Errorf("hash collision between variant %d (%+v) and %d (%+v)", i, k, prev, variants[prev])
		}
		seen[hsum] = i
	}
}
