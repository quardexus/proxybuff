// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

func writeEntry(t *testing.T, d Disk, key string, expiresAt time.Time) {
	t.Helper()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := d.PrepareWrite(key)
	if err != nil {
		t.Fatalf("PrepareWrite(%s): %v", key, err)
	}
	if err := os.WriteFile(tmpBody, []byte("body"), 0o644); err != nil {
		t.Fatalf("write tmp body: %v", err)
	}
	if err := os.Rename(tmpBody, bodyFinal); err != nil {
		t.Fatalf("rename body: %v", err)
	}
	if err := d.WriteMeta(tmpMeta, metaFinal, &Meta{Path: "/" + key, ExpiresAt: expiresAt, Size: 4}); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
}

func TestClearCacheRemovesEntriesButKeepsCerts(t *testing.T) {
	dir := t.TempDir()
	d := Disk{Dir: dir, TTL: time.Minute}

	// Two cache entries: one fresh, one already expired. Both are removed.
	writeEntry(t, d, "aabbccdd11", time.Unix(1<<31, 0))
	writeEntry(t, d, "eeff001122", time.Unix(1, 0))

	// Simulate the ACME cert cache living under the same dir; must survive.
	certFile := filepath.Join(d.CertsDir(), "example.com")
	if err := os.MkdirAll(d.CertsDir(), 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	if err := os.WriteFile(certFile, []byte("PEM"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	deleted, err := d.ClearCache()
	if err != nil {
		t.Fatalf("ClearCache: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// No cache entries remain.
	remaining := 0
	if err := d.Walk(func(meta Meta, bodyPath string) error {
		remaining++
		return nil
	}); err != nil {
		t.Fatalf("Walk after clear: %v", err)
	}
	if remaining != 0 {
		t.Errorf("remaining entries = %d, want 0", remaining)
	}

	// Certs are untouched.
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file was removed by ClearCache: %v", err)
	}
}

func TestClearCacheMissingDirIsNoop(t *testing.T) {
	d := Disk{Dir: filepath.Join(t.TempDir(), "does-not-exist"), TTL: time.Minute}
	deleted, err := d.ClearCache()
	if err != nil {
		t.Fatalf("ClearCache on missing dir: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
}

func TestClearCertsRemovesCertsButKeepsCache(t *testing.T) {
	dir := t.TempDir()
	d := Disk{Dir: dir, TTL: time.Minute}

	// One cache entry that must survive.
	writeEntry(t, d, "aabbccdd11", time.Unix(1<<31, 0))

	// Two cert-cache entries.
	if err := os.MkdirAll(d.CertsDir(), 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	for _, name := range []string{"example.com", "acme_account+key"} {
		if err := os.WriteFile(filepath.Join(d.CertsDir(), name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	deleted, err := d.ClearCerts()
	if err != nil {
		t.Fatalf("ClearCerts: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Certs gone.
	if entries, _ := os.ReadDir(d.CertsDir()); len(entries) != 0 {
		t.Errorf("cert entries remaining = %d, want 0", len(entries))
	}

	// Cache entry survives.
	remaining := 0
	if err := d.Walk(func(meta Meta, bodyPath string) error {
		remaining++
		return nil
	}); err != nil {
		t.Fatalf("Walk after clear-certs: %v", err)
	}
	if remaining != 1 {
		t.Errorf("cache entries = %d, want 1", remaining)
	}
}

func TestClearCertsMissingDirIsNoop(t *testing.T) {
	d := Disk{Dir: t.TempDir(), TTL: time.Minute} // no certs/ subdir
	deleted, err := d.ClearCerts()
	if err != nil {
		t.Fatalf("ClearCerts with no certs dir: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
}
