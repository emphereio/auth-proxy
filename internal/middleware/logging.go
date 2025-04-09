// Package middleware provides HTTP middleware components
package middleware

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging returns middleware for logging HTTP requests
func Logging() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip logging for health checks to reduce noise if requested frequently
			if r.URL.Path == "/health" && zerolog.GlobalLevel() != zerolog.DebugLevel {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Generate or extract request ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
				r.Header.Set("X-Request-ID", requestID)
			}

			// Create response writer wrapper to capture status code and response size
			rw := newResponseWriter(w)
			rw.Header().Set("X-Request-ID", requestID)

			// Process the request
			next.ServeHTTP(rw, r)

			// Calculate duration after request is processed
			duration := time.Since(start)

			// Get tenant ID if available
			tenantID, _ := GetTenantID(r)

			// Create log event with appropriate level based on status code
			var event *zerolog.Event
			switch {
			case rw.status >= 500:
				event = log.Error()
			case rw.status >= 400:
				event = log.Warn()
			case rw.status >= 300:
				event = log.Info()
			default:
				event = log.Debug()
			}

			// Add request details to log event
			event.
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("query", r.URL.RawQuery).
				Str("remote_ip", getClientIP(r)).
				Str("user_agent", r.UserAgent()).
				Int("status", rw.status).
				Int64("size", rw.size).
				Dur("duration_ms", duration)

			// Add tenant ID if available
			if tenantID != "" {
				event.Str("tenant_id", tenantID)
			}

			// Log the request
			event.Msg("Request completed")
		})
	}
}

// responseWriter is a wrapper for http.ResponseWriter that captures status code and response size
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

// newResponseWriter creates a new responseWriter
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		status:         http.StatusOK, // Default status code
	}
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size
func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += int64(size)
	return size, err
}

// getClientIP extracts the client IP address from a request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// X-Forwarded-For can contain a comma-separated list of IPs
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			// The leftmost IP is the original client IP
			return strings.TrimSpace(ips[0])
		}
	}

	// Check for X-Real-IP header
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If there's an error splitting (e.g., no port in the address), use RemoteAddr as is
		return r.RemoteAddr
	}
	return ip
}

// generateRequestID creates a new unique request ID
func generateRequestID() string {
	// Simple implementation - in production, you might want a more
	// sophisticated approach like UUIDs
	now := time.Now().UnixNano()
	random := rand.Int63n(1000000)
	return fmt.Sprintf("%d-%d", now, random)
}
