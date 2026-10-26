// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package cache

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func stageVersion(d Disk, key, body string) (*Meta, error) {
	_, _, tmpBody, _, _, _, err := d.PrepareWrite(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmpBody, []byte(body), 0600); err != nil {
		return nil, err
	}
	return &Meta{
		Path: "/asset", Status: http.StatusOK, Size: int64(len(body)),
		Header:    http.Header{"Etag": {body}, "Content-Length": {strconv.Itoa(len(body))}},
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func commitVersion(t *testing.T, d Disk, key, body string) {
	t.Helper()
	meta, err := stageVersion(d, key, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Commit(key, meta); err != nil {
		t.Fatal(err)
	}
}

func checkSnapshot(meta *Meta, body *os.File) error {
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(b)) != meta.Size || meta.Header.Get("Content-Length") != strconv.Itoa(len(b)) || meta.Header.Get("ETag") != string(b) {
		return fmt.Errorf("mixed cache versions: size=%d, headers=%v, body=%q", meta.Size, meta.Header, b)
	}
	return nil
}

func TestCommitKeepsOpenSnapshotConsistent(t *testing.T) {
	d := Disk{Dir: t.TempDir(), TTL: time.Hour}
	key := (Key{Path: "/asset"}).Hash()
	commitVersion(t, d, key, "old")
	oldMeta, oldBody, fresh, err := d.LoadFresh(key, time.Now())
	if err != nil || !fresh {
		t.Fatalf("load old snapshot: fresh=%v, err=%v", fresh, err)
	}
	defer oldBody.Close()

	// The open HIT must retain the old inode/handle even when a differently
	// sized version is published before the response consumes the body.
	commitVersion(t, d, key, "new and longer")
	if err := checkSnapshot(oldMeta, oldBody); err != nil {
		t.Fatal(err)
	}
	newMeta, newBody, fresh, err := d.LoadFresh(key, time.Now())
	if err != nil || !fresh {
		t.Fatalf("load new snapshot: fresh=%v, err=%v", fresh, err)
	}
	defer newBody.Close()
	if err := checkSnapshot(newMeta, newBody); err != nil {
		t.Fatal(err)
	}
	if newMeta.Header.Get("ETag") != "new and longer" {
		t.Fatal("replacement was not published")
	}
}

func TestConcurrentSnapshotsDuringCommit(t *testing.T) {
	d := Disk{Dir: t.TempDir(), TTL: time.Hour}
	key := (Key{Path: "/asset"}).Hash()
	commitVersion(t, d, key, "initial")
	const readers = 4
	var wg sync.WaitGroup
	ready := make(chan struct{}, readers)
	done := make(chan struct{})
	errors := make(chan error, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			for {
				select {
				case <-done:
					return
				default:
				}
				meta, body, fresh, err := d.LoadFresh(key, time.Now())
				if err != nil || !fresh {
					errors <- fmt.Errorf("HIT lost during replacement: fresh=%v, err=%v", fresh, err)
					return
				}
				err = checkSnapshot(meta, body)
				_ = body.Close()
				if err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	var stop sync.Once
	finish := func() { stop.Do(func() { close(done) }); wg.Wait() }
	defer finish()
	for i := 0; i < readers; i++ {
		<-ready
	}
	for version := 1; version <= 30; version++ {
		commitVersion(t, d, key, strings.Repeat(strconv.Itoa(version), version))
	}
	// Stop and join before inspecting errors or cleaning up the directory.
	finish()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestCommitMetadataPreparationFailurePreservesEntry(t *testing.T) {
	for _, failure := range []string{"marshal", "write"} {
		t.Run(failure, func(t *testing.T) {
			d := Disk{Dir: t.TempDir(), TTL: time.Hour}
			key := (Key{Path: "/asset"}).Hash()
			commitVersion(t, d, key, "original")
			meta, err := stageVersion(d, key, "replacement")
			if err != nil {
				t.Fatal(err)
			}
			if failure == "marshal" {
				meta.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			} else {
				_, _, _, tmpMeta, _, _, _ := d.PrepareWrite(key)
				if err := os.Mkdir(tmpMeta, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.Commit(key, meta); err == nil {
				t.Fatal("expected metadata preparation failure")
			}
			oldMeta, body, fresh, err := d.LoadFresh(key, time.Now())
			if err != nil || !fresh {
				t.Fatalf("failure discarded existing entry: fresh=%v, err=%v", fresh, err)
			}
			defer body.Close()
			if oldMeta.Header.Get("ETag") != "original" {
				t.Fatal("failure changed original metadata")
			}
			if err := checkSnapshot(oldMeta, body); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommitPublicationFailureLeavesMiss(t *testing.T) {
	d := Disk{Dir: t.TempDir(), TTL: time.Hour}
	key := (Key{Path: "/asset"}).Hash()
	commitVersion(t, d, key, "original")
	meta, err := stageVersion(d, key, "replacement")
	if err != nil {
		t.Fatal(err)
	}
	_, _, tmpBody, _, _, _, _ := d.PrepareWrite(key)
	if err := os.Remove(tmpBody); err != nil {
		t.Fatal(err)
	}
	if err := d.Commit(key, meta); err == nil {
		t.Fatal("expected body publication failure")
	}
	_, body, fresh, err := d.LoadFresh(key, time.Now())
	if body != nil {
		body.Close()
	}
	if err != nil || fresh {
		t.Fatalf("failed publication must be a MISS: fresh=%v, err=%v", fresh, err)
	}
	commitVersion(t, d, key, "recovered")
}

func TestLoadFreshLeavesExpiredEntryForSweep(t *testing.T) {
	d := Disk{Dir: t.TempDir(), TTL: time.Hour}
	key := (Key{Path: "/asset"}).Hash()
	writeEntry(t, d, key, time.Now().Add(-time.Minute))
	_, _, fresh, err := d.LoadFresh(key, time.Now())
	if err != nil || fresh {
		t.Fatalf("expired entry must be a MISS: fresh=%v, err=%v", fresh, err)
	}
	_, bodyPath, metaPath := d.Paths(key)
	for _, path := range []string{bodyPath, metaPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("read unexpectedly removed %s: %v", path, err)
		}
	}
	if deleted, err := d.SweepExpired(time.Now()); err != nil || deleted != 1 {
		t.Fatalf("GC did not remove expired entry: deleted=%d, err=%v", deleted, err)
	}
}
