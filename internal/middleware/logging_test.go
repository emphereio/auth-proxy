package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestLogging(t *testing.T) {
	// Capture log output for testing
	var buf bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() {
		log.Logger = originalLogger
	}()

	// Create the logging middleware
	loggingMiddleware := Logging()

	// Test cases
	tests := []struct {
		name           string
		method         string
		path           string
		setupRequest   func(*http.Request)
		expectedStatus int
		checkLog       func(*testing.T, string)
	}{
		{
			name:           "SuccessfulRequest",
			method:         "GET",
			path:           "/success",
			expectedStatus: http.StatusOK,
			checkLog: func(t *testing.T, logOutput string) {
				assert.Contains(t, logOutput, `"method":"GET"`)
				assert.Contains(t, logOutput, `"path":"/success"`)
				assert.Contains(t, logOutput, `"status":200`)
				assert.Contains(t, logOutput, `"request_id":"`)
			},
		},
		{
			name:           "WithTenantID",
			method:         "GET",
			path:           "/with-tenant",
			expectedStatus: http.StatusOK,
			setupRequest: func(req *http.Request) {
				// Use actual context key from the middleware
				ctx := context.WithValue(req.Context(), tenantIDKey, "test-tenant-123")
				*req = *req.WithContext(ctx)
			},
			checkLog: func(t *testing.T, logOutput string) {
				var logEntry map[string]interface{}
				err := json.Unmarshal([]byte(logOutput), &logEntry)
				require.NoError(t, err)
				assert.Contains(t, logEntry, "tenant_id")
				assert.Equal(t, "test-tenant-123", logEntry["tenant_id"])
			},
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the buffer before each test
			buf.Reset()

			// Create a new request
			req := httptest.NewRequest(tc.method, "http://example.com"+tc.path, nil)

			// Apply any request setup
			if tc.setupRequest != nil {
				tc.setupRequest(req)
			}

			// Create a response recorder
			rec := httptest.NewRecorder()

			// Create a simple next handler
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.expectedStatus)
			})

			// Apply the middleware
			handler := loggingMiddleware(nextHandler)
			handler.ServeHTTP(rec, req)

			// Check the status code
			assert.Equal(t, tc.expectedStatus, rec.Result().StatusCode)

			// Check the log output
			logOutput := buf.String()
			if tc.checkLog != nil {
				tc.checkLog(t, logOutput)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	// Test the getClientIP function (exported via a test wrapper function)

	tests := []struct {
		name         string
		setupRequest func(*http.Request)
		expectedIP   string
	}{
		{
			name: "FromXForwardedFor",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
			},
			expectedIP: "203.0.113.195",
		},
		{
			name: "FromXRealIP",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-Real-IP", "203.0.113.195")
			},
			expectedIP: "203.0.113.195",
		},
		{
			name: "FromRemoteAddr",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "203.0.113.195:12345"
			},
			expectedIP: "203.0.113.195",
		},
		{
			name: "FromRemoteAddrNoPort",
			setupRequest: func(req *http.Request) {
				req.RemoteAddr = "203.0.113.195"
			},
			expectedIP: "203.0.113.195",
		},
		{
			name: "Precedence",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-Forwarded-For", "203.0.113.195")
				req.Header.Set("X-Real-IP", "70.41.3.18")
				req.RemoteAddr = "150.172.238.178:12345"
			},
			expectedIP: "203.0.113.195", // X-Forwarded-For takes precedence
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			tc.setupRequest(req)

			// We can test this through the logging middleware
			loggingMiddleware := Logging()

			// Capture log output
			var buf bytes.Buffer
			originalLogger := log.Logger
			log.Logger = zerolog.New(&buf)
			defer func() {
				log.Logger = originalLogger
			}()

			// Create a simple handler
			handler := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			// Make the request
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Check log output for the IP
			logOutput := buf.String()
			assert.Contains(t, logOutput, `"remote_ip":"`+tc.expectedIP+`"`)
		})
	}
}

func TestGenerateRequestID(t *testing.T) {
	// Test the generateRequestID function indirectly through the middleware

	loggingMiddleware := Logging()

	// Create multiple requests and ensure IDs are unique
	var requestIDs []string

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		rec := httptest.NewRecorder()

		handler := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			requestIDs = append(requestIDs, requestID)
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rec, req)
	}

	// Check that all request IDs are unique
	assert.Equal(t, 10, len(requestIDs))

	// Create a map to check for duplicates
	idMap := make(map[string]bool)
	for _, id := range requestIDs {
		assert.NotEmpty(t, id)
		assert.False(t, idMap[id], "Duplicate request ID found: %s", id)
		idMap[id] = true
	}
}

func TestSkipHealthCheck(t *testing.T) {
	// Capture log output for testing
	var buf bytes.Buffer
	originalLogger := log.Logger

	// Set log level to info to simulate production environment
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = zerolog.New(&buf)

	defer func() {
		log.Logger = originalLogger
		zerolog.SetGlobalLevel(zerolog.DebugLevel) // Reset to default
	}()

	// Create the logging middleware
	loggingMiddleware := Logging()

	// Create a health check request
	req := httptest.NewRequest("GET", "http://example.com/health", nil)
	rec := httptest.NewRecorder()

	// Create a handler that registers it was called
	handlerCalled := false
	handler := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	// Execute the handler
	handler.ServeHTTP(rec, req)

	// Verify the handler was called
	assert.True(t, handlerCalled, "Handler should be called for health check")

	// Check that the log output is empty since we're at INFO level and health checks shouldn't be logged
	logOutput := buf.String()
	assert.Empty(t, logOutput, "Health check should not be logged at INFO level")

	// Now set log level to DEBUG and check that health checks are logged
	buf.Reset()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	handler.ServeHTTP(rec, req)

	// Verify logs are generated at DEBUG level
	logOutput = buf.String()
	assert.NotEmpty(t, logOutput, "Health check should be logged at DEBUG level")
	assert.Contains(t, logOutput, "/health")
}
