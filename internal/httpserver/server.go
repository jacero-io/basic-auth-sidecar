package httpserver

import (
	"encoding/json"
	"net/http"

	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"github.com/jacero-io/basic-auth-sidecar/internal/ratelimit"
	"go.uber.org/zap"
)

func NewServer(authenticator *auth.Authenticator, rateLimiter *ratelimit.IPRateLimiter, logger *zap.Logger) (http.Handler, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/metrics", metricsHandler)
	mux.HandleFunc("/authenticate", authenticateHandler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		// Bypass authentication for health and metrics endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			mux.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			handleUnauthenticatedRequest(w, ip, rateLimiter, logger)
			return
		}

		authenticated, err := authenticator.Authenticate(authHeader)
		if err != nil || !authenticated {
			handleFailedAuthentication(w, ip, authHeader, rateLimiter, logger, err)
			return
		}

		// Authenticated users bypass rate limiting
		mux.ServeHTTP(w, r)
	}), nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"metrics": "placeholder"})
}

func authenticateHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"authenticated": "true"})
}

func handleUnauthenticatedRequest(w http.ResponseWriter, ip string, rateLimiter *ratelimit.IPRateLimiter, logger *zap.Logger) {
	if !rateLimiter.Allow(ip, "") {
		logger.Warn("Rate limit exceeded for unauthenticated request", zap.String("ip", ip))
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Authentication required", http.StatusUnauthorized)
}

func handleFailedAuthentication(w http.ResponseWriter, ip, authHeader string, rateLimiter *ratelimit.IPRateLimiter, logger *zap.Logger, err error) {
	if err != nil {
		logger.Error("Authentication error", zap.Error(err))
	}
	if !rateLimiter.Allow(ip, authHeader) {
		logger.Warn("Rate limit exceeded for failed authentication", zap.String("ip", ip))
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Invalid authentication", http.StatusUnauthorized)
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}