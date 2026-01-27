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
	disk    cache.Disk
	origin  *url.URL
	client  *http.Client
	locks   *keyedLocker
	ahead   time.Duration
	workers int

	matchers []cache.Matcher

	mu       sync.Mutex
	pq       recachePQ
	byPath   map[string]*recacheItem
	inFlight map[string]struct{}

	wakeCh chan struct{}
	taskCh chan string
}

func newRecacheScheduler(disk cache.Disk, origin *url.URL, client *http.Client, locks *keyedLocker, matchers []cache.Matcher, ahead time.Duration, workers int) *recacheScheduler {
	if workers <= 0 {
		workers = 1
	}
	if ahead < 0 {
		ahead = 0
	}
	s := &recacheScheduler{
		disk:     disk,
		origin:   origin,
		client:   client,
		locks:    locks,
		ahead:    ahead,
		workers:  workers,
		matchers: matchers,
		byPath:   make(map[string]*recacheItem),
		inFlight: make(map[string]struct{}),
		wakeCh:   make(chan struct{}, 1),
		taskCh:   make(chan string, workers*4),
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

func (s *recacheScheduler) Update(path string, expiresAt time.Time) {
	if strings.TrimSpace(path) == "" {
		return
	}
	if !s.shouldRecache(path) {
		return
	}
	refreshAt := expiresAt.Add(-s.ahead)
	s.scheduleAt(path, refreshAt)
}

func (s *recacheScheduler) scheduleAt(path string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if it, ok := s.byPath[path]; ok {
		it.at = at
		heap.Fix(&s.pq, it.index)
	} else {
		it := &recacheItem{path: path, at: at}
		heap.Push(&s.pq, it)
		s.byPath[path] = it
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
	var due []string

	s.mu.Lock()
	for s.pq.Len() > 0 {
		it := s.pq[0]
		if it.at.After(now) {
			break
		}
		heap.Pop(&s.pq)
		delete(s.byPath, it.path)
		if _, ok := s.inFlight[it.path]; ok {
			continue
		}
		s.inFlight[it.path] = struct{}{}
		due = append(due, it.path)
	}
	s.mu.Unlock()

	for _, p := range due {
		select {
		case s.taskCh <- p:
		default:
			// Backpressure: reschedule soon and drop inFlight.
			s.finishTaskAndReschedule(p, now.Add(10*time.Second))
		}
	}
}

func (s *recacheScheduler) worker(ctx context.Context, idx int) {
	for {
		select {
		case <-ctx.Done():
			return
		case path := <-s.taskCh:
			s.refreshOne(ctx, path)
		}
	}
}

func (s *recacheScheduler) refreshOne(ctx context.Context, path string) {
	// TryLock to avoid blocking user traffic. If busy, retry soon.
	key := cache.KeyForPath(path)
	unlock, ok := s.locks.TryLock(key)
	if !ok {
		s.finishTaskAndReschedule(path, time.Now().Add(15*time.Second))
		return
	}
	defer unlock()

	// If it got refreshed by user traffic while we were waiting in queue,
	// reading meta here avoids extra origin hit.
	meta, _, fresh, err := s.disk.LoadFresh(path, time.Now())
	if err == nil && fresh {
		// Still schedule the next refresh based on current expiry.
		s.finishTaskAndReschedule(path, meta.ExpiresAt.Add(-s.ahead))
		return
	}

	expiresAt, err := s.fetchToCache(ctx, path)
	if err != nil {
		log.Printf("recache: refresh failed for %s: %v", path, err)
		s.finishTaskAndReschedule(path, time.Now().Add(s.retryDelay()))
		return
	}

	s.finishTaskAndReschedule(path, expiresAt.Add(-s.ahead))
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

func (s *recacheScheduler) finishTaskAndReschedule(path string, nextAt time.Time) {
	s.mu.Lock()
	delete(s.inFlight, path)
	s.mu.Unlock()

	// If nextAt is zero/too early, normalize.
	if nextAt.IsZero() {
		nextAt = time.Now().Add(30 * time.Second)
	}
	if !s.shouldRecache(path) {
		return
	}
	s.scheduleAt(path, nextAt)
}

func (s *recacheScheduler) fetchToCache(ctx context.Context, path string) (time.Time, error) {
	u := *s.origin
	u.Path = singleJoiningSlash(s.origin.Path, path)
	u.RawQuery = ""
	u.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Host = s.origin.Host

	resp, err := s.client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return time.Time{}, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	now := time.Now()
	_, _, tmpBody, tmpMeta, bodyFinal, metaFinal, err := s.disk.PrepareWrite(path)
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

	storedHeader := filterHopByHopResponseHeaders(resp.Header)
	storedHeader.Set("Content-Length", strconv.FormatInt(n, 10))
	expiresAt := now.Add(s.disk.TTL)
	meta := &cache.Meta{
		Path:      path,
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
		if !s.shouldRecache(m.Path) {
			return nil
		}
		// If already expired, schedule immediate refresh.
		refreshAt := m.ExpiresAt.Add(-s.ahead)
		if now.After(m.ExpiresAt) || refreshAt.Before(now) {
			refreshAt = now
		}
		s.scheduleAt(m.Path, refreshAt)
		return nil
	})
}

type recacheItem struct {
	path  string
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
