package errors

import (
	"fmt"
	"runtime"
	"strings"
)

// AppError represents a custom error type for our application
type AppError struct {
	Err     error
	Message string
	Code    string
	Stack   string
}

func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError
func New(err error, message string, code string) *AppError {
	stackTrace := getStackTrace()
	return &AppError{
		Err:     err,
		Message: message,
		Code:    code,
		Stack:   stackTrace,
	}
}

// getStackTrace returns a formatted stack trace
func getStackTrace() string {
	var sb strings.Builder
	for i := 2; i < 15; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		sb.WriteString(fmt.Sprintf("%s:%d\n", file, line))
	}
	return sb.String()
}

// Configuration errors
var (
	ErrConfigLoad = func(err error) *AppError {
		return New(err, "Failed to load configuration", "CONFIG_LOAD_ERROR")
	}
)

// Authentication errors
var (
	ErrInvalidCredentials = func(err error) *AppError {
		return New(err, "Invalid credentials", "AUTH_INVALID_CREDENTIALS")
	}
	ErrUserNotFound = func(err error) *AppError {
		return New(err, "User not found", "AUTH_USER_NOT_FOUND")
	}
)

// Server errors
var (
	ErrServerStart = func(err error) *AppError {
		return New(err, "Failed to start server", "SERVER_START_ERROR")
	}
	ErrServerShutdown = func(err error) *AppError {
		return New(err, "Failed to shutdown server gracefully", "SERVER_SHUTDOWN_ERROR")
	}
)
