// Package middleware provides HTTP middleware components
package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MetricsCollector collects HTTP request metrics
type MetricsCollector struct {
	mutex               sync.RWMutex
	totalRequests       int64
	requestsByPath      map[string]int64
	requestsByMethod    map[string]int64
	requestsByStatus    map[int]int64
	responseTimeTotal   int64
	responseTimeCount   int64
	responseTimeByPath  map[string]int64
	responseCountByPath map[string]int64
	errorCount          int64
	clientErrorCount    int64
	serverErrorCount    int64
	startTime           time.Time
}

// NewMetricsCollector creates a new metrics collector
var metricsCollector = &MetricsCollector{
	requestsByPath:      make(map[string]int64),
	requestsByMethod:    make(map[string]int64),
	requestsByStatus:    make(map[int]int64),
	responseTimeByPath:  make(map[string]int64),
	responseCountByPath: make(map[string]int64),
	startTime:           time.Now(),
}

// Metrics returns middleware for collecting HTTP request metrics
func Metrics() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip metrics for health checks if requested frequently
			if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Create response writer wrapper to capture status code
			rw := newResponseWriter(w)

			// Process the request
			next.ServeHTTP(rw, r)

			// Calculate request duration
			duration := time.Since(start)

			// Update metrics
			metricsCollector.recordMetrics(r, rw.status, duration)
		})
	}
}

// recordMetrics updates the metrics collector with request data
func (mc *MetricsCollector) recordMetrics(r *http.Request, status int, duration time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// Normalize path to avoid high cardinality in metrics
	path := normalizePath(r.URL.Path)

	// Update total requests
	mc.totalRequests++

	// Update requests by path
	mc.requestsByPath[path]++

	// Update requests by method
	mc.requestsByMethod[r.Method]++

	// Update requests by status code
	mc.requestsByStatus[status]++

	// Update response times
	durationMs := duration.Milliseconds()
	mc.responseTimeTotal += durationMs
	mc.responseTimeCount++

	// Update response times by path
	mc.responseTimeByPath[path] += durationMs
	mc.responseCountByPath[path]++

	// Update error counts
	if status >= 400 && status < 500 {
		mc.clientErrorCount++
	} else if status >= 500 {
		mc.serverErrorCount++
	}

	if status >= 400 {
		mc.errorCount++
	}
}

// GetMetrics returns the current metrics
func GetMetrics() map[string]interface{} {
	metricsCollector.mutex.RLock()
	defer metricsCollector.mutex.RUnlock()

	// Calculate average response time
	var avgResponseTime float64
	if metricsCollector.responseTimeCount > 0 {
		avgResponseTime = float64(metricsCollector.responseTimeTotal) / float64(metricsCollector.responseTimeCount)
	}

	// Calculate uptime
	uptime := time.Since(metricsCollector.startTime).Seconds()

	// Calculate request rate (requests per second)
	var requestRate float64
	if uptime > 0 {
		requestRate = float64(metricsCollector.totalRequests) / uptime
	}

	// Calculate error rate
	var errorRate float64
	if metricsCollector.totalRequests > 0 {
		errorRate = float64(metricsCollector.errorCount) / float64(metricsCollector.totalRequests) * 100
	}

	// Build path metrics
	pathMetrics := make(map[string]map[string]interface{})
	for path, count := range metricsCollector.requestsByPath {
		if count > 0 {
			var avgPathResponseTime float64
			if responseCount := metricsCollector.responseCountByPath[path]; responseCount > 0 {
				avgPathResponseTime = float64(metricsCollector.responseTimeByPath[path]) / float64(responseCount)
			}

			pathMetrics[path] = map[string]interface{}{
				"requests":             count,
				"avg_response_time_ms": avgPathResponseTime,
			}
		}
	}

	// Build status code metrics
	statusMetrics := make(map[string]int64)
	for status, count := range metricsCollector.requestsByStatus {
		statusMetrics[string(status)] = count
	}

	// Build method metrics
	methodMetrics := make(map[string]int64)
	for method, count := range metricsCollector.requestsByMethod {
		methodMetrics[method] = count
	}

	return map[string]interface{}{
		"total_requests":       metricsCollector.totalRequests,
		"uptime_seconds":       uptime,
		"avg_response_time_ms": avgResponseTime,
		"requests_per_second":  requestRate,
		"error_rate_percent":   errorRate,
		"client_errors":        metricsCollector.clientErrorCount,
		"server_errors":        metricsCollector.serverErrorCount,
		"by_path":              pathMetrics,
		"by_status":            statusMetrics,
		"by_method":            methodMetrics,
	}
}

// normalizePath converts dynamic path segments to placeholders
// For example: /users/123/posts/456 -> /users/{id}/posts/{id}
func normalizePath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		// Skip empty segments
		if segment == "" {
			continue
		}

		// Check if segment looks like a UUID or numeric ID
		if isIDLike(segment) {
			segments[i] = "{id}"
		}
	}

	return strings.Join(segments, "/")
}

// isIDLike checks if a segment looks like an ID (numeric or UUID)
func isIDLike(segment string) bool {
	// Check if numeric
	if len(segment) > 0 && (segment[0] >= '0' && segment[0] <= '9') {
		isNumeric := true
		for _, c := range segment {
			if c < '0' || c > '9' {
				isNumeric = false
				break
			}
		}
		if isNumeric {
			return true
		}
	}

	// Check if UUID-like (simple check)
	if len(segment) >= 32 && strings.Count(segment, "-") >= 4 {
		return true
	}

	return false
}

// MetricsHandler returns an HTTP handler for the /metrics endpoint
func MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		metrics := GetMetrics()
		json.NewEncoder(w).Encode(metrics)
	}
}
