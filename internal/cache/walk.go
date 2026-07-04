// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WalkFunc is the callback type for Walk.
type WalkFunc func(meta Meta, bodyPath string) error

// Walk traverses the cache directory and calls fn for each valid cache entry.
// It skips invalid or corrupted entries.
func (d Disk) Walk(fn WalkFunc) error {
	root := strings.TrimSpace(d.Dir)
	if root == "" {
		return nil
	}
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if de.IsDir() {
			return nil
		}
		if de.Name() != "meta.json" {
			return nil
		}

		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}

		var m Meta
		if err := json.Unmarshal(b, &m); err != nil {
			return nil
		}

		// Body file is alongside meta.json
		bodyPath := filepath.Join(filepath.Dir(p), "body")

		return fn(m, bodyPath)
	})
}
