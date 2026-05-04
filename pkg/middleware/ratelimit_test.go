package middleware

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowBurst(t *testing.T) {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     10.0 / 60.0, // 10 per minute
		burst:    10,
		stop:     make(chan struct{}),
	}

	// First 10 requests should all be allowed (burst)
	for i := 0; i < 10; i++ {
		if !rl.allow("192.168.1.1") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	// 11th should be denied
	if rl.allow("192.168.1.1") {
		t.Fatal("request 11 should be rate-limited")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     5.0 / 60.0,
		burst:    5,
		stop:     make(chan struct{}),
	}

	// Exhaust IP A
	for i := 0; i < 5; i++ {
		rl.allow("10.0.0.1")
	}

	// IP B should still have its own bucket
	if !rl.allow("10.0.0.2") {
		t.Fatal("different IP should have independent rate limit")
	}

	// IP A should be limited
	if rl.allow("10.0.0.1") {
		t.Fatal("IP A should be rate-limited")
	}
}

func TestRateLimiter_TokenReplenish(t *testing.T) {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     100.0, // 100 tokens per second (very fast for test)
		burst:    5,
		stop:     make(chan struct{}),
	}

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.allow("10.0.0.1")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("should be limited after burst")
	}

	// Wait briefly for replenishment
	time.Sleep(50 * time.Millisecond)

	// Should have tokens again (100/sec * 0.05s = 5 tokens)
	if !rl.allow("10.0.0.1") {
		t.Fatal("should be allowed after token replenishment")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     1.0,
		burst:    10,
		stop:     make(chan struct{}),
	}

	rl.allow("old-ip")
	rl.visitors["old-ip"].lastSeen = time.Now().Add(-10 * time.Minute)

	rl.allow("new-ip")

	rl.cleanup(5 * time.Minute)

	if _, ok := rl.visitors["old-ip"]; ok {
		t.Fatal("old-ip should have been cleaned up")
	}
	if _, ok := rl.visitors["new-ip"]; !ok {
		t.Fatal("new-ip should still be present")
	}
}
