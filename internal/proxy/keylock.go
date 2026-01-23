package proxy

import "sync"

type keyedLocker struct {
	mu    sync.Mutex
	locks map[string]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedLocker() *keyedLocker {
	return &keyedLocker{locks: make(map[string]*refLock)}
}

func (k *keyedLocker) Lock(key string) (unlock func()) {
	k.mu.Lock()
	l, ok := k.locks[key]
	if !ok {
		l = &refLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs <= 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
