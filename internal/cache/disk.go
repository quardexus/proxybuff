// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Meta struct {
	Path      string      `json:"path"`
	Site      string      `json:"site,omitempty"`
	Host      string      `json:"host,omitempty"`
	Query     string      `json:"query,omitempty"`
	Status    int         `json:"status"`
	Header    http.Header `json:"header"`
	CreatedAt time.Time   `json:"createdAt"`
	ExpiresAt time.Time   `json:"expiresAt"`
	Size      int64       `json:"size"`
}

type Disk struct {
	Dir string
	TTL time.Duration
}

func (d Disk) Validate() error {
	if d.Dir == "" {
		return errors.New("cache dir is required")
	}
	if d.TTL <= 0 {
		return errors.New("cache ttl must be > 0")
	}
	return nil
}

// Key identifies a cache entry. Site namespaces entries per configured host so
// that different origins never collide on the same path. Path is always part of
// the identity; Host and Query are included only when the operator enables
// --cache-vary-host and --cache-key-query respectively (both on by default).
type Key struct {
	Site  string
	Path  string
	Host  string
	Query string
}

// Hash returns the on-disk identity for the key: a hex-encoded SHA-256 over the
// null-separated components in a fixed order.
func (k Key) Hash() string {
	h := sha256.New()
	h.Write([]byte(k.Site))
	h.Write([]byte{0})
	h.Write([]byte(k.Path))
	h.Write([]byte{0})
	h.Write([]byte(k.Host))
	h.Write([]byte{0})
	h.Write([]byte(k.Query))
	return hex.EncodeToString(h.Sum(nil))
}

func (d Disk) Paths(key string) (dir, bodyPath, metaPath string) {
	// spread across directories to avoid too many files per directory
	p1 := key[0:2]
	p2 := key[2:4]
	dir = filepath.Join(d.Dir, p1, p2, key)
	bodyPath = filepath.Join(dir, "body")
	metaPath = filepath.Join(dir, "meta.json")
	return
}

func (d Disk) LoadFresh(key string, now time.Time) (*Meta, *os.File, bool, error) {
	_, bodyPath, metaPath := d.Paths(key)

	meta, err := readMeta(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	if now.After(meta.ExpiresAt) {
		_ = os.Remove(metaPath)
		_ = os.Remove(bodyPath)
		return nil, nil, false, nil
	}

	f, err := os.Open(bodyPath)
	if err != nil {
		// meta exists but body is missing/corrupt; treat as miss
		_ = os.Remove(metaPath)
		return nil, nil, false, nil
	}
	return meta, f, true, nil
}

func (d Disk) PrepareWrite(key string) (_ string, dir string, tmpBody string, tmpMeta string, bodyFinal string, metaFinal string, err error) {
	dir, bodyFinal, metaFinal = d.Paths(key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", "", "", "", "", fmt.Errorf("mkdir cache dir: %w", err)
	}
	tmpBody = filepath.Join(dir, "body.tmp")
	tmpMeta = filepath.Join(dir, "meta.json.tmp")
	return key, dir, tmpBody, tmpMeta, bodyFinal, metaFinal, nil
}

func (d Disk) WriteMeta(tmpMeta, metaFinal string, m *Meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	if err := os.WriteFile(tmpMeta, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	if err := os.Rename(tmpMeta, metaFinal); err != nil {
		return fmt.Errorf("rename meta: %w", err)
	}
	return nil
}

// SweepExpired walks cache dir and removes expired entries (meta.json + body).
// This is a best-effort operation: it continues on individual errors.
func (d Disk) SweepExpired(now time.Time) (deleted int, err error) {
	root := strings.TrimSpace(d.Dir)
	if root == "" {
		return 0, errors.New("cache dir is required")
	}
	// If cache dir doesn't exist, nothing to do.
	if _, statErr := os.Stat(root); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return 0, nil
		}
		return 0, statErr
	}

	walkErr := filepath.WalkDir(root, func(p string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// skip this subtree entry
			return nil
		}
		if de.IsDir() {
			return nil
		}
		if de.Name() != "meta.json" {
			return nil
		}

		meta, readErr := readMeta(p)
		if readErr != nil {
			return nil
		}
		if !now.After(meta.ExpiresAt) {
			return nil
		}

		dir := filepath.Dir(p)
		bodyPath := filepath.Join(dir, "body")
		_ = os.Remove(p)
		_ = os.Remove(bodyPath)
		deleted++
		return nil
	})
	if walkErr != nil {
		return deleted, walkErr
	}
	return deleted, nil
}

// CertsDir returns the ACME certificate cache directory that lives alongside
// the HTTP cache (autocert.DirCache in cmd/proxybuff writes here).
func (d Disk) CertsDir() string {
	return filepath.Join(strings.TrimSpace(d.Dir), "certs")
}

// ClearCache removes every cache entry (meta.json + body) under the cache dir
// and prunes the now-empty entry directory. It deliberately matches only cache
// entries (identified by a meta.json), so unrelated data living under the same
// cache dir — notably the ACME "certs/" subdirectory — is left untouched.
// Best-effort: it continues on individual errors.
func (d Disk) ClearCache() (deleted int, err error) {
	root := strings.TrimSpace(d.Dir)
	if root == "" {
		return 0, errors.New("cache dir is required")
	}
	// If cache dir doesn't exist, nothing to do.
	if _, statErr := os.Stat(root); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return 0, nil
		}
		return 0, statErr
	}

	certsDir := d.CertsDir()
	walkErr := filepath.WalkDir(root, func(p string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// skip this subtree entry
			return nil
		}
		if de.IsDir() {
			// Never descend into the ACME cert cache.
			if p == certsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if de.Name() != "meta.json" {
			return nil
		}

		dir := filepath.Dir(p)
		bodyPath := filepath.Join(dir, "body")
		_ = os.Remove(p)
		_ = os.Remove(bodyPath)
		// The entry directory is now empty; prune it (ignores non-empty dirs).
		_ = os.Remove(dir)
		deleted++
		return nil
	})
	if walkErr != nil {
		return deleted, walkErr
	}
	return deleted, nil
}

// ClearCerts removes all cached ACME certificates and account data under the
// certs/ subdirectory. The next TLS handshake for each domain then triggers a
// fresh issuance via ACME (subject to the CA's rate limits). Best-effort;
// returns the number of top-level cert-cache entries removed.
func (d Disk) ClearCerts() (deleted int, err error) {
	if strings.TrimSpace(d.Dir) == "" {
		return 0, errors.New("cache dir is required")
	}
	certs := d.CertsDir()
	entries, readErr := os.ReadDir(certs)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return 0, nil
		}
		return 0, readErr
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(certs, e.Name())); err == nil {
			deleted++
		}
	}
	return deleted, nil
}

func readMeta(metaPath string) (*Meta, error) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var m Meta
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode meta: %w", err)
	}
	return &m, nil
}
