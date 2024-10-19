package config

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestLoad(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name        string
		content     string
		envVars     map[string]string
		expectError bool
		validate    func(*testing.T, *Config)
	}{
		{
			name: "Valid config",
			content: `
auth:
  username: testuser
  password: testpass
server:
  grpc_port: 9001
  http_port: 8080
logging:
  level: info
rate_limit:
  requests_per_second: 5
  burst: 10
  cleanup_interval: 5m
  max_inactivity: 1h
`,
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Auth.Username != "testuser" {
					t.Errorf("Expected username 'testuser', got '%s'", cfg.Auth.Username)
				}
				if cfg.Auth.Password != "testpass" {
					t.Errorf("Expected password 'testpass', got '%s'", cfg.Auth.Password)
				}
				if cfg.Server.GRPCPort != 9001 {
					t.Errorf("Expected GRPC port 9001, got %d", cfg.Server.GRPCPort)
				}
				if cfg.Server.HTTPPort != 8080 {
					t.Errorf("Expected HTTP port 8080, got %d", cfg.Server.HTTPPort)
				}
				if cfg.Logging.Level != "info" {
					t.Errorf("Expected logging level 'info', got '%s'", cfg.Logging.Level)
				}
				if cfg.RateLimit.RequestsPerSecond != 5 {
					t.Errorf("Expected 5 requests per second, got %f", cfg.RateLimit.RequestsPerSecond)
				}
				if cfg.RateLimit.Burst != 10 {
					t.Errorf("Expected burst of 10, got %d", cfg.RateLimit.Burst)
				}
				if cfg.RateLimit.CleanupInterval != 5*time.Minute {
					t.Errorf("Expected cleanup interval of 5m, got %v", cfg.RateLimit.CleanupInterval)
				}
				if cfg.RateLimit.MaxInactivity != 1*time.Hour {
					t.Errorf("Expected max inactivity of 1h, got %v", cfg.RateLimit.MaxInactivity)
				}
			},
		},
		{
			name: "Missing required fields",
			content: `
server:
  grpc_port: 9001
  http_port: 8080
`,
			expectError: true,
		},
		{
			name: "Invalid YAML",
			content: `
auth:
  username: testuser
  password: testpass
server:
  grpc_port: 9001
  http_port: 8080
  invalid_yaml
`,
			expectError: true,
		},
		{
			name: "Environment variable override",
			content: `
auth:
  username: testuser
  password: testpass
server:
  grpc_port: 9001
  http_port: 8080
rate_limit:
  requests_per_second: 5
  burst: 10
  cleanup_interval: 5m
  max_inactivity: 1h
`,
			envVars: map[string]string{
				"AUTH_USERNAME": "envuser",
				"AUTH_PASSWORD": "envpass",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Auth.Username != "envuser" {
					t.Errorf("Expected username 'envuser', got '%s'", cfg.Auth.Username)
				}
				if cfg.Auth.Password != "envpass" {
					t.Errorf("Expected password 'envpass', got '%s'", cfg.Auth.Password)
				}
				// Validate other fields to ensure they're not affected
				if cfg.Server.GRPCPort != 9001 {
					t.Errorf("Expected GRPC port 9001, got %d", cfg.Server.GRPCPort)
				}
				if cfg.Server.HTTPPort != 8080 {
					t.Errorf("Expected HTTP port 8080, got %d", cfg.Server.HTTPPort)
				}
				if cfg.RateLimit.RequestsPerSecond != 5 {
					t.Errorf("Expected 5 requests per second, got %f", cfg.RateLimit.RequestsPerSecond)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary config file
			tmpfile, err := os.CreateTemp("", "config.*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.Write([]byte(tt.content)); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}
			// Defer unsetting environment variables
			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			// Test loading the config
			cfg, err := Load(tmpfile.Name(), logger)

			if tt.expectError {
				if err == nil {
					t.Error("Expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}