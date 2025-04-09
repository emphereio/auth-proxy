// Package middleware provides HTTP middleware components
package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// Recovery returns middleware that recovers from panics
func Recovery() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					// Get the stack trace
					stack := debug.Stack()

					// Format the error message
					var err error
					switch v := rec.(type) {
					case error:
						err = v
					case string:
						err = fmt.Errorf("%s", v)
					default:
						err = fmt.Errorf("%v", v)
					}

					// Get request ID if available
					requestID := r.Header.Get("X-Request-ID")

					// Log the panic with detailed information
					log.Error().
						Err(err).
						Str("request_id", requestID).
						Str("method", r.Method).
						Str("path", r.URL.Path).
						Str("remote_ip", getClientIP(r)).
						Bytes("stack_trace", stack).
						Msg("Panic recovered in HTTP handler")

					// Determine if we should include technical details in response
					// In production, we typically don't want to expose these details
					isDevelopment := getEnv("ENVIRONMENT", "production") == "development"

					// Build error response
					statusCode := http.StatusInternalServerError
					errorResponse := map[string]interface{}{
						"error":  "Internal Server Error",
						"status": statusCode,
					}

					// Include request ID if available
					if requestID != "" {
						errorResponse["request_id"] = requestID
					}

					// Include error details in development mode
					if isDevelopment {
						errorResponse["message"] = err.Error()
					}

					// Send JSON response
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(statusCode)
					json.NewEncoder(w).Encode(errorResponse)
				}
			}()

			// Process request
			next.ServeHTTP(w, r)
		})
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
