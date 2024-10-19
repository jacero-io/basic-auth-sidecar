package ratelimit

import (
	"sync"
	"time"

	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
    ips             map[string]*rate.Limiter
    lastActivity    map[string]time.Time
    mu              *sync.RWMutex
    r               rate.Limit
    b               int
    cleanupInterval time.Duration
    maxInactivity   time.Duration
    authenticator   *auth.Authenticator
}

func NewIPRateLimiter(r rate.Limit, b int, cleanupInterval, maxInactivity time.Duration, authenticator *auth.Authenticator) *IPRateLimiter {
    i := &IPRateLimiter{
        ips:             make(map[string]*rate.Limiter),
        lastActivity:    make(map[string]time.Time),
        mu:              &sync.RWMutex{},
        r:               r,
        b:               b,
        cleanupInterval: cleanupInterval,
        maxInactivity:   maxInactivity,
        authenticator:   authenticator,
    }

    go i.cleanupLoop()

    return i
}

func (i *IPRateLimiter) Allow(ip string, authHeader string) bool {
    // Check if the user is authenticated
    if authHeader != "" {
        authenticated, _ := i.authenticator.Authenticate(authHeader)
        if authenticated {
            return true // Skip rate limiting for authenticated users
        }
    }

    // Continue with rate limiting for unauthenticated users
    limiter := i.GetLimiter(ip)
    return limiter.Allow()
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}

	i.lastActivity[ip] = time.Now()
	return limiter
}

func (i *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(i.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		i.mu.Lock()
		for ip, lastActivity := range i.lastActivity {
			if time.Since(lastActivity) > i.maxInactivity {
				delete(i.ips, ip)
				delete(i.lastActivity, ip)
			}
		}
		i.mu.Unlock()
	}
}