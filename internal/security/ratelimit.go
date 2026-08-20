package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64
	burst    float64
	disabled bool
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	if perMinute <= 0 {
		return &RateLimiter{disabled: true, buckets: map[string]*bucket{}}
	}
	if burst <= 0 {
		burst = perMinute / 4
		if burst < 1 {
			burst = 1
		}
	}
	return &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    float64(perMinute) / 60.0,
		burst:   float64(burst),
	}
}

func (l *RateLimiter) Allow(key string) bool {
	if l == nil || l.disabled {
		return true
	}
	if key == "" {
		key = "unknown"
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = minFloat(l.burst, b.tokens+elapsed*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func RateLimitKey(p *Principal, r *http.Request) string {
	if p != nil && p.ID != "" {
		return "id:" + p.ID
	}
	if p != nil && p.Subject != "" {
		return "sub:" + p.Subject
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "ip:" + r.RemoteAddr
	}
	return "ip:" + host
}

func OriginAllowed(allowed []string, origin string) bool {
	if len(allowed) == 0 {
		return true
	}
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return true // non-browser clients (Cursor, CLI) omit Origin
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), origin) {
			return true
		}
	}
	return false
}

func OriginMiddleware(allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !OriginAllowed(allowed, r.Header.Get("Origin")) {
			writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RateLimitMiddleware(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFromContext(r.Context())
		if !limiter.Allow(RateLimitKey(p, r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": map[string]any{
					"code":    "TOO_MANY_REQUESTS",
					"message": "rate limit exceeded",
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
