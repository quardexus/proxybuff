// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import (
	"os"
	"path/filepath"
	"syscall"
)

// Allow a refreshed body to replace the pathname while an existing HIT keeps
// reading its original file handle, matching Unix rename semantics.
func openBody(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

func replaceBody(tmpBody, bodyFinal string) error {
	if _, err := os.Stat(bodyFinal); os.IsNotExist(err) {
		return os.Rename(tmpBody, bodyFinal)
	} else if err != nil {
		return err
	}
	// Windows cannot replace an open destination in place. Move its pathname
	// aside first; delete-sharing keeps existing HIT handles readable while
	// freeing the final name for the replacement.
	retired, err := os.CreateTemp(filepath.Dir(bodyFinal), "body.retired-*")
	if err != nil {
		return err
	}
	retiredPath := retired.Name()
	if err := retired.Close(); err != nil {
		_ = os.Remove(retiredPath)
		return err
	}
	defer os.Remove(retiredPath)
	if err := os.Rename(bodyFinal, retiredPath); err != nil {
		return err
	}
	return os.Rename(tmpBody, bodyFinal)
}
