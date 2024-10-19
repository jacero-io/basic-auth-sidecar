package ratelimit

import (
	"fmt"
	"testing"
	"time"

	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"github.com/jacero-io/basic-auth-sidecar/internal/config"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func TestIPRateLimiter_Allow(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Auth: struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		}{
			Username: "testuser",
			Password: "testpass",
		},
	}
	authenticator := auth.NewAuthenticator(cfg, logger)

	limiter := NewIPRateLimiter(rate.Limit(1), 1, 5*time.Minute, 1*time.Hour, authenticator)

	tests := []struct {
		name       string
		ip         string
		authHeader string
		expected   bool
	}{
		{"Unauthenticated - First request", "192.168.1.1", "", true},
		{"Unauthenticated - Second request", "192.168.1.1", "", false},
		{"Authenticated - First request", "192.168.1.2", "Basic dGVzdHVzZXI6dGVzdHBhc3M=", true},
		{"Authenticated - Second request", "192.168.1.2", "Basic dGVzdHVzZXI6dGVzdHBhc3M=", true},
		{"Different IP - First request", "192.168.1.3", "", true},
		{"Invalid auth - First request", "192.168.1.4", "Basic aW52YWxpZDppbnZhbGlk", true},
		{"Invalid auth - Second request", "192.168.1.4", "Basic aW52YWxpZDppbnZhbGlk", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := limiter.Allow(tt.ip, tt.authHeader)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIPRateLimiter_Cleanup(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Auth: struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		}{
			Username: "testuser",
			Password: "testpass",
		},
	}
	authenticator := auth.NewAuthenticator(cfg, logger)

	cleanupInterval := 100 * time.Millisecond
	maxInactivity := 200 * time.Millisecond

	limiter := NewIPRateLimiter(rate.Limit(1), 1, cleanupInterval, maxInactivity, authenticator)

	// Add some IPs
	limiter.Allow("192.168.1.1", "")
	limiter.Allow("192.168.1.2", "")
	limiter.Allow("192.168.1.3", "")

	// Wait for cleanup
	time.Sleep(3 * cleanupInterval)

	// Check if IPs were cleaned up
	limiter.mu.RLock()
	defer limiter.mu.RUnlock()

	if len(limiter.ips) != 0 {
		t.Errorf("Expected all limiters to be cleaned up, but found %d", len(limiter.ips))
	}

	// Check if lastActivity was cleaned up
	if len(limiter.lastActivity) != 0 {
		t.Errorf("Expected all lastActivity entries to be cleaned up, but found %d", len(limiter.lastActivity))
	}
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Auth: struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		}{
			Username: "testuser",
			Password: "testpass",
		},
	}
	authenticator := auth.NewAuthenticator(cfg, logger)

	limiter := NewIPRateLimiter(rate.Limit(100), 10, 5*time.Minute, 1*time.Hour, authenticator)

	const concurrentRequests = 100
	const requestsPerIP = 20

	done := make(chan bool)

	for i := 0; i < concurrentRequests; i++ {
		go func(i int) {
			ip := fmt.Sprintf("192.168.1.%d", i%5)
			for j := 0; j < requestsPerIP; j++ {
				limiter.Allow(ip, "")
			}
			done <- true
		}(i)
	}

	for i := 0; i < concurrentRequests; i++ {
		<-done
	}

	limiter.mu.RLock()
	defer limiter.mu.RUnlock()

	if len(limiter.ips) != 5 {
		t.Errorf("Expected 5 IPs in the limiter, but found %d", len(limiter.ips))
	}
}