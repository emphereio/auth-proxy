// Package middleware provides HTTP middleware components
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/jwt"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/rs/zerolog/log"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

// Context keys
const (
	tenantIDKey contextKey = "tenantID"
)

// Auth returns middleware for tenant authorization using embedded OPA
func Auth(opaEngine *opa.Engine, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for specific endpoints
			if shouldSkipAuth(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Handle preflight OPTIONS requests
			if r.Method == http.MethodOptions {
				handlePreflight(w)
				return
			}

			// Extract auth header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Debug().Str("path", r.URL.Path).Msg("Missing Authorization header")
				respondWithError(w, http.StatusUnauthorized, "Missing Authorization header")
				return
			}

			// Extract tenant ID
			tenantID := jwt.ExtractTenantID(r)
			if tenantID == "" {
				log.Debug().Str("path", r.URL.Path).Msg("Unable to determine tenant ID")
				respondWithError(w, http.StatusForbidden, "Unable to determine tenant ID")
				return
			}

			// Get expected tenant ID from environment
			expectedTenantID := os.Getenv("TENANT_ID")

			// Create input for OPA evaluation
			input := createOPAInput(r, authHeader, tenantID, expectedTenantID)

			// Validate with embedded OPA
			allowed, err := opaEngine.Evaluate(r.Context(), input)
			if err != nil {
				log.Error().Err(err).Str("path", r.URL.Path).Msg("Error evaluating OPA policy")
				respondWithError(w, http.StatusInternalServerError, "Authorization service error")
				return
			}

			if !allowed {
				log.Info().
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Str("tenantID", tenantID).
					Str("expectedTenantID", expectedTenantID).
					Str("host", r.Host).
					Msg("Tenant authorization denied")
				respondWithError(w, http.StatusForbidden, "Tenant authorization denied")
				return
			}

			// Authorization successful
			log.Debug().
				Str("path", r.URL.Path).
				Str("method", r.Method).
				Str("tenantID", tenantID).
				Msg("Tenant authorization successful")

			// Set tenant ID header for the backend
			r.Header.Set("X-Tenant-ID", tenantID)

			// Add tenant ID to request context
			ctx := context.WithValue(r.Context(), tenantIDKey, tenantID)

			// Continue to the next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// shouldSkipAuth returns true if auth should be skipped for the path
func shouldSkipAuth(path string) bool {
	// Skip auth for health, metrics, and debug endpoints
	noAuthPaths := []string{
		"/health",
		"/metrics",
		"/debug/",
	}

	for _, prefix := range noAuthPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// handlePreflight handles OPTIONS preflight requests
func handlePreflight(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.WriteHeader(http.StatusOK)
}

// respondWithError writes a JSON error response
func respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// createOPAInput creates the input object for OPA policy evaluation
func createOPAInput(r *http.Request, authHeader, tenantID, expectedTenantID string) map[string]interface{} {
	// Create headers map
	headers := make(map[string]string)
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}

	// Add/override specific headers
	headers["authorization"] = authHeader
	headers["x-tenant-id"] = tenantID

	// Extract host tenant ID
	hostTenantID := jwt.ExtractTenantIDFromHost(r.Host)

	// Build the input structure expected by OPA
	return map[string]interface{}{
		"attributes": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"headers": headers,
					"method":  r.Method,
					"path":    r.URL.Path,
					"query":   r.URL.RawQuery,
					"host":    r.Host,
				},
			},
		},
		"expected_tenant_id": expectedTenantID,
		"host_tenant_id":     hostTenantID,
	}
}

// GetTenantID retrieves the tenant ID from the request context
func GetTenantID(r *http.Request) (string, bool) {
	tenantID, ok := r.Context().Value(tenantIDKey).(string)
	return tenantID, ok
}

// RequireTenant is a helper that wraps handlers requiring a tenant ID
func RequireTenant(handler func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := GetTenantID(r)
		if !ok || tenantID == "" {
			respondWithError(w, http.StatusForbidden, "Tenant ID required")
			return
		}

		handler(w, r, tenantID)
	}
}
