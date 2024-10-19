package auth

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jacero-io/basic-auth-sidecar/internal/config"
	"github.com/jacero-io/basic-auth-sidecar/internal/errors"
	"go.uber.org/zap"
)

type Authenticator struct {
	username string
	password string
	logger   *zap.Logger
}

func NewAuthenticator(cfg *config.Config, logger *zap.Logger) *Authenticator {
	return &Authenticator{
		username: cfg.Auth.Username,
		password: cfg.Auth.Password,
		logger:   logger,
	}
}

func (a *Authenticator) Authenticate(authHeader string) (bool, error) {
	a.logger.Debug("Received auth header", zap.String("header", authHeader))

	if !strings.HasPrefix(authHeader, "Basic ") {
		return false, errors.New(fmt.Errorf("invalid auth header format"), "Invalid authentication", "AUTH_INVALID_HEADER")
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return false, errors.New(err, "Invalid authentication", "AUTH_DECODE_ERROR")
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return false, errors.New(fmt.Errorf("invalid auth header content"), "Invalid authentication", "AUTH_INVALID_CONTENT")
	}

	username, password := pair[0], pair[1]

	if username == a.username && password == a.password {
		a.logger.Info("Authentication successful", zap.String("username", username))
		return true, nil
	}

	a.logger.Warn("Authentication failed", zap.String("username", username))
	return false, errors.ErrInvalidCredentials(fmt.Errorf("invalid credentials"))
}

// GetUsername returns the configured username
func (a *Authenticator) GetUsername() string {
	return a.username
}
