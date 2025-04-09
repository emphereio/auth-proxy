package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/jwt"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	// Enable debug logging for the test
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Create temporary directory for policies
	tmpDir, err := os.MkdirTemp("", "middleware-auth-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Updated policyContent for auth_test.go without variable reassignment
	policyContent := `
package http.authz

default allow = false

# Allow if tenant IDs from JWT and host match
allow {
    # Get tenant ID from JWT userinfo
    jwt_payload := parse_jwt_payload(input.attributes.request.http.headers["x-endpoint-api-userinfo"])
    tenant_from_jwt := jwt_payload.tenantId
    
    # Get tenant ID from host
    host := input.attributes.request.http.host
    parts := split(host, ".")
    count(parts) >= 2
    tenant_from_host := parts[0]
    
    # Both tenant IDs exist and match
    tenant_from_jwt != ""
    tenant_from_host != "" 
    tenant_from_jwt == tenant_from_host
    
    # Also match against expected tenant ID
    input.expected_tenant_id == tenant_from_jwt
}

# Allow if tenant ID from header exactly matches expected
allow {
    # Both must exist and match exactly
    input.attributes.request.http.headers["x-tenant-id"] != ""
    input.expected_tenant_id != ""
    input.attributes.request.http.headers["x-tenant-id"] == input.expected_tenant_id
}

# Allow health and metrics endpoints
allow {
    path := input.attributes.request.http.path
    startswith(path, "/health")
}

allow {
    path := input.attributes.request.http.path
    startswith(path, "/metrics")
}

# Allow debug endpoints
allow {
    path := input.attributes.request.http.path
    startswith(path, "/debug/")
}

# Parse JWT payload from a header
parse_jwt_payload(header) = payload {
    header != ""
    decoded := base64_decode(header)
    payload := json.unmarshal(decoded)
} else = {}

# Helper function to decode base64 - fixed version without variable reassignment
base64_decode(encoded) = decoded {
    # No padding needed (multiple of 4)
    remainder := count(encoded) % 4
    remainder == 0
    decoded := base64.decode(encoded)
} else = decoded {
    # Need 1 padding character
    remainder := count(encoded) % 4
    remainder == 3
    decoded := base64.decode(concat("", [encoded, "="]))
} else = decoded {
    # Need 2 padding characters
    remainder := count(encoded) % 4
    remainder == 2
    decoded := base64.decode(concat("", [encoded, "=="]))
} else = decoded {
    # Need 3 padding characters
    remainder := count(encoded) % 4
    remainder == 1
    decoded := base64.decode(concat("", [encoded, "==="]))
}
`

	err = os.WriteFile(filepath.Join(tmpDir, "test_policy.rego"), []byte(policyContent), 0644)
	require.NoError(t, err)

	// Create OPA engine
	engine, err := opa.NewEngine(tmpDir)
	require.NoError(t, err)

	// Create config
	cfg := &config.Config{
		PolicyDir: tmpDir,
	}

	// Set tenant ID environment variable for testing
	os.Setenv("TENANT_ID", "test-tenant-123")
	defer os.Unsetenv("TENANT_ID")

	// Create the auth middleware
	authMiddleware := Auth(engine, cfg)

	// Helper function to create test JWT with tenant ID
	createJWT := func(tenantID string) string {
		// Create a payload
		payload := jwt.Payload{
			Subject:  "user123",
			TenantID: tenantID,
		}
		payloadJSON, _ := json.Marshal(payload)

		// Base64 encode the payload
		encodedPayload := base64.StdEncoding.EncodeToString(payloadJSON)

		// Add dummy header and signature to make it look like a JWT
		return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + encodedPayload + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	}

	// Test cases
	tests := []struct {
		name             string
		setupReq         func(*http.Request)
		expectCode       int
		checkTenant      bool
		expectedTenantID string
		checkHeaders     func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "HealthEndpointBypassesAuth",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/health"
			},
			expectCode: http.StatusOK,
		},
		{
			name: "MetricsEndpointBypassesAuth",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/metrics"
			},
			expectCode: http.StatusOK,
		},
		{
			name: "DebugEndpointBypassesAuth",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/debug/policies"
			},
			expectCode: http.StatusOK,
		},
		{
			name: "OptionsRequestHandlesPreflight",
			setupReq: func(req *http.Request) {
				req.Method = "OPTIONS"
				req.URL.Path = "/secure-endpoint"
			},
			expectCode: http.StatusOK,
			checkHeaders: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "GET")
			},
		},
		{
			name: "MissingAuthHeaderReturns401",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
			},
			expectCode: http.StatusUnauthorized,
		},
		{
			name: "MissingTenantIDReturns403",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				req.Header.Set("Authorization", "Bearer token123")
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "WrongTenantIDReturns403",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				req.Header.Set("Authorization", "Bearer token123")
				req.Header.Set("X-Tenant-ID", "wrong-tenant")
				userInfo := createJWT("wrong-tenant")
				req.Header.Set("x-endpoint-api-userinfo", userInfo)
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "CorrectTenantIDAllowsAccess",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				req.Header.Set("Authorization", "Bearer token123")
				req.Header.Set("X-Tenant-ID", "test-tenant-123")
				userInfo := createJWT("test-tenant-123")
				req.Header.Set("x-endpoint-api-userinfo", userInfo)
			},
			expectCode:       http.StatusOK,
			checkTenant:      true,
			expectedTenantID: "test-tenant-123",
		},
		{
			name: "TenantIDsFromJWTAndHostMismatch",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				req.Header.Set("Authorization", "Bearer token123")

				// Set tenant ID in header that matches expected
				req.Header.Set("X-Tenant-ID", "test-tenant-123")

				// Create JWT with a different tenant ID than the host
				userInfo := createJWT("tenant123")
				req.Header.Set("x-endpoint-api-userinfo", userInfo)

				// Set host with a different tenant ID
				req.Host = "different-tenant.api.example.com"
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "TenantIDsFromJWTAndHostMatch",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				req.Header.Set("Authorization", "Bearer token123")

				// Set tenant ID in header that matches expected
				req.Header.Set("X-Tenant-ID", "test-tenant-123")

				// Create JWT with tenant ID matching host
				userInfo := createJWT("test-tenant-123")
				req.Header.Set("x-endpoint-api-userinfo", userInfo)

				// Set host with matching tenant
				req.Host = "test-tenant-123.api.example.com"
			},
			expectCode:       http.StatusOK,
			checkTenant:      true,
			expectedTenantID: "test-tenant-123",
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Debug log for test case
			log.Debug().Str("test", tc.name).Msg("Running test case")

			// Use a custom handler that will capture the tenant ID
			var capturedTenantID string
			var tenantIDFound bool

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Capture tenant ID directly from the request context
				if tc.checkTenant {
					capturedTenantID, tenantIDFound = GetTenantID(r)
				}
				w.WriteHeader(http.StatusOK)
			})

			// Create a new request
			req := httptest.NewRequest("GET", "http://example.com", nil)
			tc.setupReq(req)

			// Log request details for debugging
			log.Debug().
				Str("path", req.URL.Path).
				Str("method", req.Method).
				Str("host", req.Host).
				Str("auth", req.Header.Get("Authorization")).
				Str("tenant", req.Header.Get("X-Tenant-ID")).
				Str("userinfo", req.Header.Get("x-endpoint-api-userinfo")).
				Msg("Test request details")

			// Create a response recorder
			rec := httptest.NewRecorder()

			// Apply the middleware
			handler := authMiddleware(nextHandler)
			handler.ServeHTTP(rec, req)

			// Log response for debugging
			log.Debug().
				Int("status", rec.Result().StatusCode).
				Str("expected", http.StatusText(tc.expectCode)).
				Str("actual", http.StatusText(rec.Result().StatusCode)).
				Msg("Test response")

			// Check the status code
			assert.Equal(t, tc.expectCode, rec.Result().StatusCode,
				"Test: %s - Expected status %d but got %d",
				tc.name, tc.expectCode, rec.Result().StatusCode)

			// Check tenant ID if needed
			if tc.checkTenant && tc.expectCode == http.StatusOK {
				assert.True(t, tenantIDFound, "Expected tenant ID to be found")
				assert.Equal(t, tc.expectedTenantID, capturedTenantID)
			}

			// Check headers if needed
			if tc.checkHeaders != nil {
				tc.checkHeaders(t, rec)
			}
		})
	}
}

type ContextKey string

const (
	TenantIDKey ContextKey = "tenantID"
)
