package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey test-api-key-123")

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if apiKey != "test-api-key-123" {
			t.Errorf("Expected 'test-api-key-123', got '%s'", apiKey)
		}
	})

	t.Run("missing authorization header", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, got '%s'", apiKey)
		}
	})

	t.Run("malformed authorization header - wrong prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer test-api-key-123")

		apiKey, err := GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error for malformed header, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', got '%s'", err.Error())
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, got '%s'", apiKey)
		}
	})

	t.Run("malformed authorization header - missing key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		apiKey, err := GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error for malformed header, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', got '%s'", err.Error())
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, got '%s'", apiKey)
		}
	})

	t.Run("empty authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "")

		apiKey, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
		if apiKey != "" {
			t.Errorf("Expected empty string, got '%s'", apiKey)
		}
	})
}