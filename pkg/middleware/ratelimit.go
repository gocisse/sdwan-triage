package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitConfig controls the per-IP rate limiter behaviour.
type RateLimitConfig struct {
	RequestsPerMinute int           // Max requests allowed per IP per minute (default 100)
	CleanupInterval   time.Duration // How often to evict stale entries (default 5m)
}

type visitor struct {
	tokens    float64
	lastSeen  time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     float64 // tokens per second
	burst    int     // max tokens (= RequestsPerMinute)
	stop     chan struct{}
}

// RateLimitMiddleware returns a Gin middleware that limits requests per IP.
// It uses an in-process token-bucket algorithm — no external dependencies required.
func RateLimitMiddleware(cfg RateLimitConfig) gin.HandlerFunc {
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = 100
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}

	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     float64(cfg.RequestsPerMinute) / 60.0, // tokens per second
		burst:    cfg.RequestsPerMinute,
		stop:     make(chan struct{}),
	}

	// Background goroutine to evict visitors not seen for 3 minutes
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.cleanup(3 * time.Minute)
			case <-rl.stop:
				return
			}
		}
	}()

	return func(c *gin.Context) {
		ip := extractIP(c)
		if !rl.allow(ip) {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// allow checks whether the given IP has tokens remaining (token bucket).
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{tokens: float64(rl.burst), lastSeen: now}
		rl.visitors[ip] = v
	}

	// Replenish tokens based on elapsed time
	elapsed := now.Sub(v.lastSeen).Seconds()
	v.tokens += elapsed * rl.rate
	if v.tokens > float64(rl.burst) {
		v.tokens = float64(rl.burst)
	}
	v.lastSeen = now

	if v.tokens < 1.0 {
		return false
	}

	v.tokens -= 1.0
	return true
}

// cleanup removes visitors not seen for the given duration.
func (rl *rateLimiter) cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for ip, v := range rl.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(rl.visitors, ip)
		}
	}
}

// extractIP returns the client IP, preferring X-Forwarded-For if present.
func extractIP(c *gin.Context) string {
	// Trust Gin's ClientIP which respects X-Forwarded-For and X-Real-IP
	ip := c.ClientIP()
	if ip == "" {
		ip, _, _ = net.SplitHostPort(c.Request.RemoteAddr)
	}
	return ip
}
