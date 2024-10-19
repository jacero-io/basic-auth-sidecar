package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"github.com/jacero-io/basic-auth-sidecar/internal/config"
	"github.com/jacero-io/basic-auth-sidecar/internal/ratelimit"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func TestNewServer(t *testing.T) {
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
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(10), 1, 5, 60, authenticator)

	handler, err := NewServer(authenticator, rateLimiter, logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if handler == nil {
		t.Fatal("Handler is nil")
	}
}

func TestHealthCheckEndpoint(t *testing.T) {
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
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(1), 1, 5, 1, authenticator)
	
	handler, err := NewServer(authenticator, rateLimiter, logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"status": "OK"}
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["status"] != expected["status"] {
		t.Errorf("handler returned unexpected body: got %v want %v", response, expected)
	}
}

func TestMetricsEndpoint(t *testing.T) {
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
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(1), 1, 5, 1, authenticator)
	
	handler, err := NewServer(authenticator, rateLimiter, logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"metrics": "placeholder"}
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["metrics"] != expected["metrics"] {
		t.Errorf("handler returned unexpected body: got %v want %v", response, expected)
	}
}

func TestAuthenticateEndpoint(t *testing.T) {
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
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(10), 1, 5, 60, authenticator)

	handler, _ := NewServer(authenticator, rateLimiter, logger)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{"Valid credentials", "Basic dGVzdHVzZXI6dGVzdHBhc3M=", http.StatusOK},
		{"Invalid credentials", "Basic aW52YWxpZDppbnZhbGlk", http.StatusUnauthorized},
		{"Missing auth header", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/authenticate", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}
		})
	}
}

func TestRateLimiting(t *testing.T) {
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
	rateLimiter := ratelimit.NewIPRateLimiter(rate.Limit(1), 1, 5, 60, authenticator)

	handler, _ := NewServer(authenticator, rateLimiter, logger)

	makeRequest := func(authHeader string) int {
		req, _ := http.NewRequest("GET", "/authenticate", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// Test unauthenticated requests
	if status := makeRequest(""); status != http.StatusUnauthorized {
		t.Errorf("First unauthenticated request: handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	if status := makeRequest(""); status != http.StatusUnauthorized {
		t.Errorf("Second unauthenticated request: handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	// Test authenticated requests
	validAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
	if status := makeRequest(validAuth); status != http.StatusOK {
		t.Errorf("First authenticated request: handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if status := makeRequest(validAuth); status != http.StatusOK {
		t.Errorf("Second authenticated request: handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Test invalid authentication (should always return 401)
	invalidAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("invalid:invalid"))
	if status := makeRequest(invalidAuth); status != http.StatusUnauthorized {
		t.Errorf("First invalid auth request: handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	if status := makeRequest(invalidAuth); status != http.StatusUnauthorized {
		t.Errorf("Second invalid auth request: handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}