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

func (k *keyedLocker) TryLock(key string) (unlock func(), ok bool) {
	k.mu.Lock()
	l, existing := k.locks[key]
	if !existing {
		l = &refLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	// Try to acquire the lock without blocking
	if l.mu.TryLock() {
		return func() {
			l.mu.Unlock()
			k.mu.Lock()
			l.refs--
			if l.refs <= 0 {
				delete(k.locks, key)
			}
			k.mu.Unlock()
		}, true
	}

	// Failed to acquire, decrement ref count
	k.mu.Lock()
	l.refs--
	if l.refs <= 0 {
		delete(k.locks, key)
	}
	k.mu.Unlock()
	return nil, false
}
