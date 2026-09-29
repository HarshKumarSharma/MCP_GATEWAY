package ratelimit

import (
	"testing"
	"time"
)

func TestAllowBurstThenBlock(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 3, func() time.Time { return now }) // 1 rps, burst 3

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("4th request should be blocked (burst exhausted)")
	}
}

func TestRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1, func() time.Time { return now })

	if !l.Allow("k") {
		t.Fatal("first allowed")
	}
	if l.Allow("k") {
		t.Fatal("second blocked immediately")
	}
	now = now.Add(time.Second) // refill one token
	if !l.Allow("k") {
		t.Fatal("should be allowed after refill")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1, func() time.Time { return now })
	if !l.Allow("a") {
		t.Fatal("a first allowed")
	}
	if !l.Allow("b") {
		t.Fatal("b independent of a")
	}
}

func TestIdleBucketsAreEvicted(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 3, func() time.Time { return now }) // refill 3s -> idleTTL floored at 1m

	l.Allow("stale")
	if len(l.buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(l.buckets))
	}

	// Advance past the idle TTL and touch a different key; the sweep runs and
	// drops the now-idle "stale" bucket.
	now = now.Add(2 * l.idleTTL)
	l.Allow("fresh")

	if _, ok := l.buckets["stale"]; ok {
		t.Fatal("idle bucket should have been evicted")
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Fatal("active bucket should remain")
	}

	// Eviction is lossless: a re-seen key gets a full burst again, exactly as a
	// bucket that was merely idle would have after refilling.
	for i := 0; i < 3; i++ {
		if !l.Allow("stale") {
			t.Fatalf("re-seen key request %d should be allowed (full burst)", i)
		}
	}
}
