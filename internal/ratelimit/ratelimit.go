// Package ratelimit provides a small in-memory, per-key token-bucket limiter.
//
// It is used at the edge (keyed by client IP, before authentication) as a
// coarse abuse guard. A production deployment would move this to a shared store
// (e.g. Redis) and add per-identity limits; see the README for that roadmap.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a thread-safe per-key token-bucket limiter.
//
// Idle buckets are evicted lazily so the map does not grow without bound under
// many distinct keys (e.g. one per source IP). Eviction is lossless: a bucket
// that has been idle long enough to refill to capacity is indistinguishable
// from a freshly created one, so dropping it never changes a decision.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64 // tokens per second
	capacity  float64 // burst size
	idleTTL   time.Duration
	lastSweep time.Time
	now       func() time.Time
}

// New returns a limiter allowing `burst` requests immediately and refilling at
// `ratePerSec` tokens per second per key.
func New(ratePerSec, burst float64, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	l := &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     ratePerSec,
		capacity: burst,
		now:      now,
	}
	// A bucket idle for capacity/rate seconds has fully refilled, so it is safe
	// (lossless) to evict. Floor the sweep cadence at a minute so a high rate
	// does not turn every request into a map scan.
	if ratePerSec > 0 {
		refill := time.Duration(burst / ratePerSec * float64(time.Second))
		l.idleTTL = max(refill, time.Minute)
	}
	l.lastSweep = now()
	return l
}

// Allow reports whether a request for key may proceed, consuming one token.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.capacity - 1, last: now}
		return true
	}

	// Refill based on elapsed time, capped at capacity.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(l.capacity, b.tokens+elapsed*l.rate)
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep evicts buckets that have been idle for at least idleTTL. It is gated to
// run at most once per idleTTL, so the amortized cost per request is negligible.
// Callers must hold l.mu.
func (l *Limiter) sweep(now time.Time) {
	if l.idleTTL <= 0 || now.Sub(l.lastSweep) < l.idleTTL {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.last) >= l.idleTTL {
			delete(l.buckets, k)
		}
	}
}
