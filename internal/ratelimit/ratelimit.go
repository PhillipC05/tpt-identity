// Package ratelimit provides a simple sliding-window in-memory rate limiter.
// Each Limiter tracks a fixed number of tokens per IP (or arbitrary key) that
// refill at a steady rate. It is safe for concurrent use.
package ratelimit

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter is a per-key token-bucket rate limiter.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity int
	refill   time.Duration // one token refills every refill duration
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

// New returns a Limiter that allows capacity requests per window, where one
// token is added back every (window/capacity) interval.
func New(capacity int, window time.Duration) *Limiter {
	return &Limiter{
		buckets:  make(map[string]*bucket),
		capacity: capacity,
		refill:   window / time.Duration(capacity),
	}
}

// Allow returns true if the key is permitted to proceed, false if rate-limited.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, lastFill: time.Now()}
		l.buckets[key] = b
	}

	// Refill tokens proportional to elapsed time.
	now := time.Now()
	elapsed := now.Sub(b.lastFill)
	refilled := int(elapsed / l.refill)
	if refilled > 0 {
		b.tokens += refilled
		if b.tokens > l.capacity {
			b.tokens = l.capacity
		}
		b.lastFill = b.lastFill.Add(time.Duration(refilled) * l.refill)
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// Middleware returns an http.Handler that applies this limiter keyed by remote IP.
// Responses that exceed the limit receive 429 Too Many Requests.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !l.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler wraps an http.HandlerFunc with rate limiting.
func (l *Limiter) Handler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !l.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func remoteIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx]
	}
	return ip
}
