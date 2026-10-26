// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quardexus/proxybuff/internal/cache"
)

type recacheTestTransport func(*http.Request) (*http.Response, error)

func (f recacheTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type recacheFixture struct {
	s        *recacheScheduler
	key      cache.Key
	requests atomic.Int32
	status   int
}

func newRecacheFixture(t *testing.T, ttl, ahead time.Duration) *recacheFixture {
	t.Helper()
	f := &recacheFixture{key: cache.Key{Path: "/app.js"}, status: http.StatusOK}
	matchers, err := cache.CompileMatchers([]string{"*.js"})
	if err != nil {
		t.Fatal(err)
	}
	disk := cache.Disk{Dir: t.TempDir(), TTL: ttl}
	origin := &url.URL{Scheme: "https", Host: "origin.test"}
	client := &http.Client{Transport: recacheTestTransport(func(*http.Request) (*http.Response, error) {
		f.requests.Add(1)
		return &http.Response{
			StatusCode: f.status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("updated")),
		}, nil
	})}
	f.s = newRecacheScheduler("", disk, origin, client, newKeyedLocker(), matchers, ttl, ahead, 1)
	return f
}

func (f *recacheFixture) store(t *testing.T, expiresAt time.Time) {
	t.Helper()
	_, _, body, _, _, _, err := f.s.disk.PrepareWrite(f.key.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(body, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := &cache.Meta{
		Path: f.key.Path, Status: http.StatusOK, Header: make(http.Header),
		CreatedAt: expiresAt.Add(-f.s.ttl), ExpiresAt: expiresAt, Size: 8,
	}
	if err := f.s.disk.Commit(f.key.Hash(), meta); err != nil {
		t.Fatal(err)
	}
}

func (f *recacheFixture) read(t *testing.T) (*cache.Meta, string) {
	t.Helper()
	meta, body, fresh, err := f.s.disk.LoadFresh(f.key.Hash(), time.Now())
	if body != nil {
		defer body.Close()
	}
	if err != nil || !fresh {
		t.Fatalf("cache not readable after refresh: fresh=%v, err=%v", fresh, err)
	}
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return meta, string(b)
}

func (f *recacheFixture) nextRefresh() (time.Time, bool) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	it, ok := f.s.byKey[f.key.Hash()]
	if !ok {
		return time.Time{}, false
	}
	return it.at, true
}

func TestRecacheRefreshOne(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ahead     time.Duration
		expiresIn time.Duration
		wantFetch bool
	}{
		{"due before expiry", 5 * time.Minute, time.Minute, true},
		{"fresh not yet due", 5 * time.Minute, 10 * time.Minute, false},
		{"expired", 5 * time.Minute, -time.Minute, true},
		{"zero ahead waits for expiry", 0, time.Minute, false},
		{"zero ahead refreshes expired", 0, -time.Minute, true},
		{"ahead equal to ttl", time.Hour, time.Minute, true},
		{"ahead greater than ttl", 2 * time.Hour, time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRecacheFixture(t, time.Hour, tc.ahead)
			expiresAt := time.Now().Add(tc.expiresIn)
			f.store(t, expiresAt)
			started := time.Now()
			f.s.refreshOne(context.Background(), f.key)
			meta, body := f.read(t)
			if tc.wantFetch {
				if f.requests.Load() != 1 || body != "updated" || meta.ExpiresAt.Before(started.Add(time.Hour)) {
					t.Fatalf("due entry was not refreshed: requests=%d, body=%q, expiry=%s", f.requests.Load(), body, meta.ExpiresAt)
				}
			} else if f.requests.Load() != 0 || body != "original" || !meta.ExpiresAt.Equal(expiresAt) {
				t.Fatalf("entry refreshed before its deadline: requests=%d, body=%q, expiry=%s", f.requests.Load(), body, meta.ExpiresAt)
			}
			if next, ok := f.nextRefresh(); !ok || !next.After(time.Now()) {
				t.Fatalf("next refresh must be in the future, got %s (scheduled=%v)", next, ok)
			}
		})
	}
}

func TestRecacheSkipsEntryUpdatedWhileQueued(t *testing.T) {
	f := newRecacheFixture(t, time.Hour, 5*time.Minute)
	expiresAt := time.Now().Add(time.Minute)
	f.store(t, expiresAt)
	f.s.Update(f.key, expiresAt)
	f.s.dispatchDue(time.Now())
	queued := <-f.s.taskCh

	// Simulate a client replacing the entry after dispatch, before the worker
	// acquires its lock. The stale queued task must use the new deadline.
	newExpiry := time.Now().Add(time.Hour)
	f.store(t, newExpiry)
	f.s.refreshOne(context.Background(), queued)
	if f.requests.Load() != 0 {
		t.Fatalf("already updated entry fetched again: requests=%d", f.requests.Load())
	}
	if next, ok := f.nextRefresh(); !ok || !next.Equal(newExpiry.Add(-5*time.Minute)) {
		t.Fatalf("new expiry not respected: next=%s, scheduled=%v", next, ok)
	}
}

func TestRecacheFailedRefreshPreservesFreshEntryAndRetriesLater(t *testing.T) {
	f := newRecacheFixture(t, time.Hour, 5*time.Minute)
	f.status = http.StatusServiceUnavailable
	expiresAt := time.Now().Add(4 * time.Minute)
	f.store(t, expiresAt)
	started := time.Now()
	f.s.refreshOne(context.Background(), f.key)
	finished := time.Now()
	meta, body := f.read(t)
	if f.requests.Load() != 1 || body != "original" || !meta.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("failed refresh lost original entry: requests=%d, body=%q, expiry=%s", f.requests.Load(), body, meta.ExpiresAt)
	}
	next, ok := f.nextRefresh()
	if !ok || next.Before(started.Add(time.Minute)) || next.After(finished.Add(time.Minute)) {
		t.Fatalf("failed refresh must retry in one minute, got %s (scheduled=%v)", next, ok)
	}
}

func TestRecacheSchedulerRefreshesBeforeExpiryWithoutImmediateRepeat(t *testing.T) {
	f := newRecacheFixture(t, time.Hour, 5*time.Minute)
	f.store(t, time.Now().Add(time.Minute))
	f.s.seedFromDisk()
	ctx, cancel := context.WithCancel(context.Background())
	workerDone, loopDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(workerDone); f.s.worker(ctx, 0) }()
	go func() { defer close(loopDone); f.s.loop(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-workerDone
		<-loopDone
	})

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if next, ok := f.nextRefresh(); ok && next.After(time.Now().Add(50*time.Minute)) {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("scheduled entry was not refreshed before expiry; requests=%d", f.requests.Load())
		case <-tick.C:
		}
	}
	_, body := f.read(t)
	if body != "updated" {
		t.Fatalf("scheduled refresh did not replace body: %q", body)
	}
	select {
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal("scheduler stopped unexpectedly")
	}
	if f.requests.Load() != 1 {
		t.Fatalf("freshly refreshed entry fetched repeatedly: requests=%d", f.requests.Load())
	}
}
