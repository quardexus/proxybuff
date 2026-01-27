package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Meta struct {
	Path      string      `json:"path"`
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

func KeyForPath(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
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

func (d Disk) LoadFresh(path string, now time.Time) (*Meta, *os.File, bool, error) {
	key := KeyForPath(path)
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

func (d Disk) PrepareWrite(path string) (key string, dir string, tmpBody string, tmpMeta string, bodyFinal string, metaFinal string, err error) {
	key = KeyForPath(path)
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
