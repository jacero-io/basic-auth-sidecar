package auth

import (
	"testing"

	"github.com/jacero-io/basic-auth-sidecar/internal/config"
	"github.com/jacero-io/basic-auth-sidecar/internal/errors"
	"go.uber.org/zap"
)

func TestAuthenticator_Authenticate(t *testing.T) {
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

	auth := NewAuthenticator(cfg, logger)

	tests := []struct {
		name        string
		authHeader  string
		expected    bool
		expectError bool
		errorCode   string
	}{
		{"Valid credentials", "Basic dGVzdHVzZXI6dGVzdHBhc3M=", true, false, ""},
		{"Invalid credentials", "Basic aW52YWxpZDppbnZhbGlk", false, true, "AUTH_INVALID_CREDENTIALS"},
		{"Invalid header format", "InvalidHeader", false, true, "AUTH_INVALID_HEADER"},
		{"Empty header", "", false, true, "AUTH_INVALID_HEADER"},
		{"Missing colon in credentials", "Basic aW52YWxpZA==", false, true, "AUTH_INVALID_CONTENT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auth.Authenticate(tt.authHeader)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
			if (err != nil) != tt.expectError {
				t.Errorf("Expected error: %v, got error: %v", tt.expectError, err)
			}
			if err != nil {
				if appErr, ok := err.(*errors.AppError); ok {
					if appErr.Code != tt.errorCode {
						t.Errorf("Expected error code %s, got %s", tt.errorCode, appErr.Code)
					}
				} else {
					t.Errorf("Expected AppError, got %T", err)
				}
			}
		})
	}
}

func TestAuthenticator_GetUsername(t *testing.T) {
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

	auth := NewAuthenticator(cfg, logger)

	if auth.GetUsername() != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", auth.GetUsername())
	}
}