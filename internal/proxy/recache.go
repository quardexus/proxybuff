// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxy

import (
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quardexus/proxybuff/internal/cache"
)

type recacheScheduler struct {
	siteID  string
	disk    cache.Disk
	origin  *url.URL
	client  *http.Client
	locks   *keyedLocker
	ttl     time.Duration
	ahead   time.Duration
	workers int

	matchers []cache.Matcher

	mu       sync.Mutex
	pq       recachePQ
	byKey    map[string]*recacheItem
	inFlight map[string]struct{}

	wakeCh chan struct{}
	taskCh chan cache.Key
}

func newRecacheScheduler(siteID string, disk cache.Disk, origin *url.URL, client *http.Client, locks *keyedLocker, matchers []cache.Matcher, ttl, ahead time.Duration, workers int) *recacheScheduler {
	if workers <= 0 {
		workers = 1
	}
	if ahead < 0 {
		ahead = 0
	}
	s := &recacheScheduler{
		siteID:   siteID,
		disk:     disk,
		origin:   origin,
		client:   client,
		locks:    locks,
		ttl:      ttl,
		ahead:    ahead,
		workers:  workers,
		matchers: matchers,
		byKey:    make(map[string]*recacheItem),
		inFlight: make(map[string]struct{}),
		wakeCh:   make(chan struct{}, 1),
		taskCh:   make(chan cache.Key, workers*4),
	}
	heap.Init(&s.pq)
	return s
}

func (s *recacheScheduler) Start(ctx context.Context) {
	// Seed from disk once on startup so refresh continues after restart.
	s.seedFromDisk()

	for i := 0; i < s.workers; i++ {
		go s.worker(ctx, i)
	}
	go s.loop(ctx)
}

func (s *recacheScheduler) shouldRecache(path string) bool {
	if len(s.matchers) == 0 {
		return false
	}
	for _, m := range s.matchers {
		if m.Match(path) {
			return true
		}
	}
	return false
}

func (s *recacheScheduler) Update(k cache.Key, expiresAt time.Time) {
	if strings.TrimSpace(k.Path) == "" {
		return
	}
	if !s.shouldRecache(k.Path) {
		return
	}
	s.scheduleAt(k, expiresAt.Add(-s.ahead))
}

func (s *recacheScheduler) scheduleAt(k cache.Key, at time.Time) {
	id := k.Hash()
	s.mu.Lock()
	defer s.mu.Unlock()

	if it, ok := s.byKey[id]; ok {
		it.at = at
		it.key = k
		heap.Fix(&s.pq, it.index)
	} else {
		it := &recacheItem{key: k, at: at}
		heap.Push(&s.pq, it)
		s.byKey[id] = it
	}

	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

func (s *recacheScheduler) loop(ctx context.Context) {
	// Single timer that always targets the nearest scheduled refresh.
	for {
		if ctx.Err() != nil {
			return
		}

		var nextAt time.Time
		s.mu.Lock()
		if s.pq.Len() > 0 {
			nextAt = s.pq[0].at
		}
		s.mu.Unlock()

		var timer *time.Timer
		if nextAt.IsZero() {
			timer = time.NewTimer(30 * time.Second)
		} else {
			d := time.Until(nextAt)
			if d < 0 {
				d = 0
			}
			timer = time.NewTimer(d)
		}

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.wakeCh:
			timer.Stop()
			continue
		case <-timer.C:
			timer.Stop()
			s.dispatchDue(time.Now())
		}
	}
}

func (s *recacheScheduler) dispatchDue(now time.Time) {
	var due []cache.Key

	s.mu.Lock()
	for s.pq.Len() > 0 {
		it := s.pq[0]
		if it.at.After(now) {
			break
		}
		heap.Pop(&s.pq)
		id := it.key.Hash()
		delete(s.byKey, id)
		if _, ok := s.inFlight[id]; ok {
			continue
		}
		s.inFlight[id] = struct{}{}
		due = append(due, it.key)
	}
	s.mu.Unlock()

	for _, k := range due {
		select {
		case s.taskCh <- k:
		default:
			// Backpressure: reschedule soon and drop inFlight.
			s.finishTaskAndReschedule(k, now.Add(10*time.Second))
		}
	}
}

func (s *recacheScheduler) worker(ctx context.Context, idx int) {
	for {
		select {
		case <-ctx.Done():
			return
		case k := <-s.taskCh:
			s.refreshOne(ctx, k)
		}
	}
}

func (s *recacheScheduler) refreshOne(ctx context.Context, k cache.Key) {
	// TryLock to avoid blocking user traffic. If busy, retry soon.
	keyHash := k.Hash()
	unlock, ok := s.locks.TryLock(keyHash)
	if !ok {
		s.finishTaskAndReschedule(k, time.Now().Add(15*time.Second))
		return
	}
	defer unlock()

	// If it got refreshed by user traffic while we were waiting in queue,
	// reading meta here avoids extra origin hit.
	meta, _, fresh, err := s.disk.LoadFresh(keyHash, time.Now())
	if err == nil && fresh {
		// Still schedule the next refresh based on current expiry.
		s.finishTaskAndReschedule(k, meta.ExpiresAt.Add(-s.ahead))
		return
	}

	expiresAt, err := s.fetchToCache(ctx, k)
	if err != nil {
		log.Printf("recache: refresh failed for %s: %v", k.Path, err)
		s.finishTaskAndReschedule(k, time.Now().Add(s.retryDelay()))
		return
	}

	s.finishTaskAndReschedule(k, expiresAt.Add(-s.ahead))
}

func (s *recacheScheduler) retryDelay() time.Duration {
	// Simple stable retry: min(1m, ahead/5) but at least 10s.
	d := time.Minute
	if s.ahead > 0 {
		d = s.ahead / 5
	}
	if d <= 0 {
		d = 30 * time.Second
	}
	if d > time.Minute {
		d = time.Minute
	}
	if d < 10*time.Second {
		d = 10 * time.Second
	}
	return d
}

func (s *recacheScheduler) finishTaskAndReschedule(k cache.Key, nextAt time.Time) {
	s.mu.Lock()
	delete(s.inFlight, k.Hash())
	s.mu.Unlock()

	// If nextAt is zero/too early, normalize.
	if nextAt.IsZero() {
		nextAt = time.Now().Add(30 * time.Second)
	}
	if !s.shouldRecache(k.Path) {
		return
	}
	s.scheduleAt(k, nextAt)
}

func (s *recacheScheduler) fetchToCache(ctx context.Context, k cache.Key) (time.Time, error) {
	u := *s.origin
	u.Path = singleJoiningSlash(s.origin.Path, k.Path)
	u.RawQuery = k.Query
	u.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	// Refresh the exact variant we stored: use the entry's Host if it was keyed on it.
	if k.Host != "" {
		req.Host = k.Host
	} else {
		req.Host = s.origin.Host
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return time.Time{}, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	if !cacheableResponse(resp.Header, req.Header) {
		_, _ = io.Copy(io.Discard, resp.Body)
		return time.Time{}, fmt.Errorf("response not cacheable")
	}

	now := time.Now()
	key := k.Hash()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := s.disk.PrepareWrite(key)
	if err != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return time.Time{}, err
	}

	f, err := os.Create(tmpBody)
	if err != nil {
		_ = os.Remove(tmpMeta)
		_, _ = io.Copy(io.Discard, resp.Body)
		return time.Time{}, err
	}

	var n int64
	buf := make([]byte, 32*1024)
	n, err = io.CopyBuffer(f, resp.Body, buf)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmpBody)
		_ = os.Remove(tmpMeta)
		return time.Time{}, err
	}

	if err := os.Rename(tmpBody, bodyFinal); err != nil {
		_ = os.Remove(tmpBody)
		_ = os.Remove(tmpMeta)
		return time.Time{}, err
	}

	storedHeader := storedResponseHeader(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(n, 10))
	expiresAt := now.Add(s.ttl)
	meta := &cache.Meta{
		Path:      k.Path,
		Site:      k.Site,
		Host:      k.Host,
		Query:     k.Query,
		Status:    resp.StatusCode,
		Header:    storedHeader,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Size:      n,
	}

	if err := s.disk.WriteMeta(tmpMeta, metaFinal, meta); err != nil {
		_ = os.Remove(metaFinal)
		_ = os.Remove(bodyFinal)
		return time.Time{}, err
	}

	return expiresAt, nil
}

func (s *recacheScheduler) seedFromDisk() {
	// Walk cache dir and parse meta.json to schedule refreshes.
	root := s.disk.Dir
	if strings.TrimSpace(root) == "" {
		return
	}
	now := time.Now()
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() != "meta.json" {
			return nil
		}

		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var m cache.Meta
		if err := json.Unmarshal(b, &m); err != nil {
			return nil
		}
		if m.Path == "" {
			// Older cache entries (before v1.2.0) can't be recached.
			return nil
		}
		if m.Site != s.siteID {
			// Belongs to a different site's namespace.
			return nil
		}
		if !s.shouldRecache(m.Path) {
			return nil
		}
		k := cache.Key{Site: m.Site, Path: m.Path, Host: m.Host, Query: m.Query}
		// If already expired, schedule immediate refresh.
		refreshAt := m.ExpiresAt.Add(-s.ahead)
		if now.After(m.ExpiresAt) || refreshAt.Before(now) {
			refreshAt = now
		}
		s.scheduleAt(k, refreshAt)
		return nil
	})
}

type recacheItem struct {
	key   cache.Key
	at    time.Time
	index int
}

type recachePQ []*recacheItem

func (pq recachePQ) Len() int { return len(pq) }
func (pq recachePQ) Less(i, j int) bool {
	return pq[i].at.Before(pq[j].at)
}
func (pq recachePQ) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}
func (pq *recachePQ) Push(x interface{}) {
	it := x.(*recacheItem)
	it.index = len(*pq)
	*pq = append(*pq, it)
}
func (pq *recachePQ) Pop() interface{} {
	old := *pq
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	it.index = -1
	*pq = old[:n-1]
	return it
}
