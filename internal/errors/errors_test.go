package errors

import (
	"errors"
	"testing"
)

func TestAppError(t *testing.T) {
	err := errors.New("test error")
	appErr := New(err, "Test message", "TEST_CODE")

	if appErr.Error() != "Test message: test error" {
		t.Errorf("Expected error message 'Test message: test error', got '%s'", appErr.Error())
	}

	if appErr.Code != "TEST_CODE" {
		t.Errorf("Expected error code 'TEST_CODE', got '%s'", appErr.Code)
	}

	if appErr.Unwrap() != err {
		t.Errorf("Expected unwrapped error to be the original error")
	}

	if appErr.Stack == "" {
		t.Error("Expected stack trace to be non-empty")
	}
}