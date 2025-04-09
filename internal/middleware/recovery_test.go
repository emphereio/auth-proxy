package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecovery(t *testing.T) {
	// Capture log output for testing
	var buf bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() {
		log.Logger = originalLogger
	}()

	// Create the recovery middleware
	recoveryMiddleware := Recovery()

	// Test cases
	tests := []struct {
		name             string
		panicValue       interface{}
		requestID        string
		environment      string
		expectedStatus   int
		checkResponse    func(*testing.T, *httptest.ResponseRecorder)
		checkLogContains []string
	}{
		{
			name:           "StringPanic",
			panicValue:     "something went wrong",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)

				assert.Equal(t, "Internal Server Error", resp["error"])
				assert.Equal(t, float64(500), resp["status"])
				assert.NotContains(t, resp, "message") // No error details in production mode
			},
			checkLogContains: []string{
				"Panic recovered in HTTP handler",
				"something went wrong",
			},
		},
		{
			name:           "ErrorPanic",
			panicValue:     errors.New("runtime error"),
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)

				assert.Equal(t, "Internal Server Error", resp["error"])
			},
			checkLogContains: []string{
				"Panic recovered in HTTP handler",
				"runtime error",
			},
		},
		{
			name:           "OtherTypePanic",
			panicValue:     123,
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)

				assert.Equal(t, "Internal Server Error", resp["error"])
			},
			checkLogContains: []string{
				"Panic recovered in HTTP handler",
				"123",
			},
		},
		{
			name:           "WithRequestID",
			panicValue:     "error with request ID",
			requestID:      "test-request-id-456",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)

				assert.Equal(t, "Internal Server Error", resp["error"])
				assert.Equal(t, "test-request-id-456", resp["request_id"])
			},
			checkLogContains: []string{
				"Panic recovered in HTTP handler",
				"error with request ID",
				"test-request-id-456",
			},
		},
		{
			name:           "DevelopmentMode",
			panicValue:     "development error",
			environment:    "development",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				var resp map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				require.NoError(t, err)

				assert.Equal(t, "Internal Server Error", resp["error"])
				assert.Equal(t, "development error", resp["message"]) // Error details included in dev mode
			},
			checkLogContains: []string{
				"Panic recovered in HTTP handler",
				"development error",
			},
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the buffer
			buf.Reset()

			// Set environment variable if needed
			if tc.environment != "" {
				os.Setenv("ENVIRONMENT", tc.environment)
				defer os.Unsetenv("ENVIRONMENT")
			} else {
				os.Unsetenv("ENVIRONMENT")
			}

			// Create a handler that will panic
			panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic(tc.panicValue)
			})

			// Create a new request
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			if tc.requestID != "" {
				req.Header.Set("X-Request-ID", tc.requestID)
			}

			// Create a response recorder
			rec := httptest.NewRecorder()

			// Apply the middleware
			handler := recoveryMiddleware(panicHandler)

			// Execute the handler (should recover from panic)
			handler.ServeHTTP(rec, req)

			// Check the status code
			assert.Equal(t, tc.expectedStatus, rec.Result().StatusCode)

			// Check the response
			if tc.checkResponse != nil {
				tc.checkResponse(t, rec)
			}

			// Check the log output
			logOutput := buf.String()
			for _, expected := range tc.checkLogContains {
				assert.Contains(t, logOutput, expected)
			}
		})
	}
}

func TestRecoveryWithoutPanic(t *testing.T) {
	// Test that the middleware passes through when no panic occurs

	recoveryMiddleware := Recovery()

	// Create a handler that doesn't panic
	normalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Success"}`))
	})

	// Create a new request
	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	// Create a response recorder
	rec := httptest.NewRecorder()

	// Apply the middleware
	handler := recoveryMiddleware(normalHandler)

	// Execute the handler
	handler.ServeHTTP(rec, req)

	// Check the response
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Success", resp["message"])
}
