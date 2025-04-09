package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsMiddleware(t *testing.T) {
	// Create the metrics middleware
	metricsMiddleware := Metrics()

	// Create a simple handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate different response scenarios based on path
		switch r.URL.Path {
		case "/api/users":
			w.WriteHeader(http.StatusOK)
		case "/api/posts":
			w.WriteHeader(http.StatusCreated)
		case "/api/error":
			w.WriteHeader(http.StatusBadRequest)
		case "/api/server-error":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/slow":
			// Simulate a slow response
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	// Apply the middleware
	handler := metricsMiddleware(testHandler)

	// Make several test requests to generate metrics
	testRequests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/users"},
		{"GET", "/api/users"},
		{"POST", "/api/users"},
		{"GET", "/api/posts"},
		{"PUT", "/api/users/123"},
		{"DELETE", "/api/users/456"},
		{"GET", "/api/error"},
		{"GET", "/api/server-error"},
		{"GET", "/api/slow"},
	}

	for _, req := range testRequests {
		request := httptest.NewRequest(req.method, "http://example.com"+req.path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
	}

	// Test the metrics handler
	t.Run("MetricsHandler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/metrics", nil)
		rec := httptest.NewRecorder()

		MetricsHandler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		// Parse the metrics response
		var metrics map[string]interface{}
		err := json.Unmarshal(rec.Body.Bytes(), &metrics)
		require.NoError(t, err)

		// Check for expected metrics
		assert.Equal(t, float64(9), metrics["total_requests"])
		assert.Contains(t, metrics, "uptime_seconds")
		assert.Contains(t, metrics, "avg_response_time_ms")
		assert.Contains(t, metrics, "requests_per_second")
		assert.Contains(t, metrics, "error_rate_percent")

		// Validate error counts
		assert.Equal(t, float64(1), metrics["client_errors"])
		assert.Equal(t, float64(1), metrics["server_errors"])

		// Check path metrics
		pathMetrics, ok := metrics["by_path"].(map[string]interface{})
		assert.True(t, ok)

		// Check that path normalization works
		assert.Contains(t, pathMetrics, "/api/users")
		assert.Contains(t, pathMetrics, "/api/users/{id}")

		// Method metrics
		methodMetrics, ok := metrics["by_method"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, float64(6), methodMetrics["GET"])
		assert.Equal(t, float64(1), methodMetrics["POST"])
		assert.Equal(t, float64(1), methodMetrics["PUT"])
		assert.Equal(t, float64(1), methodMetrics["DELETE"])

		// Status metrics
		_, ok = metrics["by_status"].(map[string]interface{})
		assert.True(t, ok)
		// The status keys are strings of numeric status codes
	})
}

func TestMetricsSkipsHealthAndMetricsEndpoints(t *testing.T) {
	// Test that requests to health and metrics endpoints are not counted in metrics

	// Create the metrics middleware
	metricsMiddleware := Metrics()

	// Create a simple handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply the middleware
	handler := metricsMiddleware(testHandler)

	// First get initial metrics
	initialReq := httptest.NewRequest("GET", "http://example.com/metrics", nil)
	initialRec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(initialRec, initialReq)

	var initialMetrics map[string]interface{}
	err := json.Unmarshal(initialRec.Body.Bytes(), &initialMetrics)
	require.NoError(t, err)
	initialCount := initialMetrics["total_requests"].(float64)

	// Make requests to health and metrics endpoints
	healthReq := httptest.NewRequest("GET", "http://example.com/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)

	metricsReq := httptest.NewRequest("GET", "http://example.com/metrics", nil)
	metricsRec := httptest.NewRecorder()
	handler.ServeHTTP(metricsRec, metricsReq)

	// Now check updated metrics
	updatedReq := httptest.NewRequest("GET", "http://example.com/metrics", nil)
	updatedRec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(updatedRec, updatedReq)

	var updatedMetrics map[string]interface{}
	err = json.Unmarshal(updatedRec.Body.Bytes(), &updatedMetrics)
	require.NoError(t, err)
	updatedCount := updatedMetrics["total_requests"].(float64)

	// Request count should not have changed
	assert.Equal(t, initialCount, updatedCount, "Health and metrics endpoints should be excluded from metrics")

	// Now make a regular request and confirm it's counted
	apiReq := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)

	// Check metrics again
	finalReq := httptest.NewRequest("GET", "http://example.com/metrics", nil)
	finalRec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(finalRec, finalReq)

	var finalMetrics map[string]interface{}
	err = json.Unmarshal(finalRec.Body.Bytes(), &finalMetrics)
	require.NoError(t, err)
	finalCount := finalMetrics["total_requests"].(float64)

	// Request count should have increased by 1
	assert.Equal(t, initialCount+1, finalCount, "Regular API request should be counted in metrics")
}

func TestResponseWriterWrapper(t *testing.T) {
	// Test the response writer wrapper used by the metrics middleware
	metricsMiddleware := Metrics()

	// Test with different status codes and response sizes
	tests := []struct {
		name           string
		handler        func(w http.ResponseWriter, r *http.Request)
		expectedStatus int
		expectedSize   int
	}{
		{
			name: "DefaultStatusOK",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Don't explicitly set status, should default to 200 OK
				w.Write([]byte("Success"))
			},
			expectedStatus: http.StatusOK,
			expectedSize:   7, // Length of "Success"
		},
		{
			name: "ExplicitStatus",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte("Created"))
			},
			expectedStatus: http.StatusCreated,
			expectedSize:   7, // Length of "Created"
		},
		{
			name: "MultipleWrites",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Part 1"))
				w.Write([]byte("Part 2"))
			},
			expectedStatus: http.StatusOK,
			expectedSize:   12, // Total length of both writes
		},
		{
			name: "HeaderAfterWrite",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// This is technically incorrect usage, but our wrapper should handle it
				w.Write([]byte("Data"))
				w.WriteHeader(http.StatusBadRequest) // This should be ignored as it's too late
			},
			expectedStatus: http.StatusOK, // First write implicitly sets 200 OK
			expectedSize:   4,             // Length of "Data"
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create handler with middleware
			handler := metricsMiddleware(http.HandlerFunc(tc.handler))

			// Make request
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Verify response
			result := rec.Result()
			assert.Equal(t, tc.expectedStatus, result.StatusCode)
			assert.Equal(t, tc.expectedSize, rec.Body.Len())

			// Now check metrics to verify they were recorded correctly
			metricsReq := httptest.NewRequest("GET", "http://example.com/metrics", nil)
			metricsRec := httptest.NewRecorder()
			MetricsHandler().ServeHTTP(metricsRec, metricsReq)

			var metrics map[string]interface{}
			err := json.Unmarshal(metricsRec.Body.Bytes(), &metrics)
			require.NoError(t, err)

			// Check if status was recorded correctly
			statusMetrics, ok := metrics["by_status"].(map[string]interface{})
			assert.True(t, ok)

			// Convert status code to string for map lookup
			// FIX: Use strconv.Itoa instead of string() conversion
			statusKey := strconv.Itoa(tc.expectedStatus)
			assert.Contains(t, statusMetrics, statusKey)
		})
	}
}

func TestNormalizePath(t *testing.T) {
	// Test the path normalization logic
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/users", "/api/users"},
		{"/api/users/123", "/api/users/{id}"},
		{"/api/users/abc", "/api/users/abc"}, // Not ID-like
		{"/api/posts/123/comments/456", "/api/posts/{id}/comments/{id}"},
		{"/api/users/00001", "/api/users/{id}"},
		{"/api/orders/f47ac10b-58cc-4372-a567-0e02b2c3d479", "/api/orders/{id}"},
		{"/", "/"},
		{"", ""},
		{"/api/users//", "/api/users//"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			// We can test this through metrics handler behavior
			// First, make requests to record metrics
			metricsMiddleware := Metrics()
			handler := metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "http://example.com"+tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Then check metrics
			metricsReq := httptest.NewRequest("GET", "http://example.com/metrics", nil)
			metricsRec := httptest.NewRecorder()
			MetricsHandler().ServeHTTP(metricsRec, metricsReq)

			var metrics map[string]interface{}
			err := json.Unmarshal(metricsRec.Body.Bytes(), &metrics)
			require.NoError(t, err)

			pathMetrics, ok := metrics["by_path"].(map[string]interface{})
			assert.True(t, ok)

			// Check if the expected normalized path exists in metrics
			if tc.path != "" { // Skip empty path
				found := false
				for path := range pathMetrics {
					if path == tc.expected {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected path '%s' to be normalized to '%s', but it wasn't found in metrics", tc.path, tc.expected)
			}
		})
	}
}
