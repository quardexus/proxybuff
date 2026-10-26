//go:build !windows

// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import "os"

func openBody(path string) (*os.File, error) {
	return os.Open(path)
}

func replaceBody(tmpBody, bodyFinal string) error {
	return os.Rename(tmpBody, bodyFinal)
}
