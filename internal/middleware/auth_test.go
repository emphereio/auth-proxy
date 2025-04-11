package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/jwt"
	"github.com/emphereio/auth-proxy/internal/opa"
	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestRSAKey generates a test RSA key pair for JWT signing
func generateTestRSAKey() (*rsa.PrivateKey, string, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	// Create PEM block for the public key
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(publicKeyBlock))

	return privateKey, publicKeyPem, nil
}

// mockTransport intercepts HTTP requests and redirects them to our test server
type mockTransport struct {
	server *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only intercept requests to the Firebase public keys URL
	if req.URL.String() == jwt.FirebasePublicKeysURL {
		// Create a new request to our test server
		newReq, err := http.NewRequest(req.Method, m.server.URL, req.Body)
		if err != nil {
			return nil, err
		}

		// Copy headers
		newReq.Header = req.Header

		// Send the request to our test server
		return m.server.Client().Do(newReq)
	}

	// For other requests, use the default transport
	return http.DefaultTransport.RoundTrip(req)
}

// generateTestToken generates a signed JWT token for testing
func generateTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims *jwt.CustomClaims) string {
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to sign test token")
	return tokenString
}

// setupMockFirebaseServer sets up a mock server to simulate Firebase's public key endpoint
func setupMockFirebaseServer(t *testing.T) (*httptest.Server, string, *rsa.PrivateKey) {
	// Generate a test RSA key pair
	privateKey, publicKeyPem, err := generateTestRSAKey()
	require.NoError(t, err, "Failed to generate test RSA key")

	// Create a mock key ID
	kid := "test-key-id-1"

	// Setup a mock server that returns our test public key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a response similar to Firebase's format
		keys := map[string]string{
			kid: publicKeyPem,
		}

		// Set cache-control header to test expiry handling
		w.Header().Set("Cache-Control", "public, max-age=21600")
		w.Header().Set("Content-Type", "application/json")

		// Write the response
		json.NewEncoder(w).Encode(keys)
	}))

	return server, kid, privateKey
}

func TestAuth(t *testing.T) {
	// Enable debug logging for the test
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Create temporary directory for policies
	tmpDir, err := os.MkdirTemp("", "middleware-auth-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Updated policyContent for auth_test.go
	policyContent := `
package http.authz

default allow = false

# Allow if tenant IDs match the expected tenant ID
allow {
    # Get tenant ID from header
    tenant_id := input.attributes.request.http.headers["x-tenant-id"]
    
    # Check against expected tenant ID
    input.expected_tenant_id == tenant_id
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

	// Setup mock Firebase server
	server, kid, privateKey := setupMockFirebaseServer(t)
	defer server.Close()

	// Save original HTTP client and restore after test
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// Create a custom client that redirects to our test server
	http.DefaultClient = &http.Client{
		Transport: &mockTransport{
			server: server,
		},
	}

	// Initialize JWT verification
	err = jwt.InitJWTVerification()
	require.NoError(t, err, "Failed to initialize JWT verification")

	// Create the auth middleware
	authMiddleware := Auth(engine, cfg)

	// Helper function to create test JWT with tenant ID
	createJWT := func(tenantID string, firebaseTenant string) string {
		claims := &jwt.CustomClaims{
			RegisteredClaims: jwtlib.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwtlib.NewNumericDate(time.Now()),
			},
			TenantID: tenantID,
		}

		if firebaseTenant != "" {
			claims.Firebase.Tenant = firebaseTenant
		}

		return generateTestToken(t, privateKey, kid, claims)
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
			name: "InvalidTokenReturns401",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				req.Header.Set("Authorization", "Bearer invalid-token")
			},
			expectCode: http.StatusUnauthorized,
		},
		{
			name: "ExpiredTokenReturns401",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"

				// Create an expired token
				expiredClaims := &jwt.CustomClaims{
					RegisteredClaims: jwtlib.RegisteredClaims{
						Subject:   "user123",
						ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
						IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					},
					TenantID: "test-tenant-123",
				}
				expiredToken := generateTestToken(t, privateKey, kid, expiredClaims)
				req.Header.Set("Authorization", "Bearer "+expiredToken)
			},
			expectCode: http.StatusUnauthorized,
		},
		{
			name: "NoTenantIDReturns403",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"

				// Token with no tenant ID
				noTenantClaims := &jwt.CustomClaims{
					RegisteredClaims: jwtlib.RegisteredClaims{
						Subject:   "user123",
						ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
						IssuedAt:  jwtlib.NewNumericDate(time.Now()),
					},
				}
				noTenantToken := generateTestToken(t, privateKey, kid, noTenantClaims)
				req.Header.Set("Authorization", "Bearer "+noTenantToken)
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "WrongTenantIDReturns403",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				// Set a valid JWT with wrong tenant ID
				token := createJWT("wrong-tenant", "")
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "CorrectTenantIDAllowsAccess",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				// Set a valid JWT with correct tenant ID
				token := createJWT("test-tenant-123", "")
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectCode:       http.StatusOK,
			checkTenant:      true,
			expectedTenantID: "test-tenant-123",
		},
		{
			name: "FirebaseTenantAllowsAccess",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				// Set a valid JWT with firebase tenant
				token := createJWT("", "test-tenant-123")
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectCode:       http.StatusOK,
			checkTenant:      true,
			expectedTenantID: "test-tenant-123",
		},
		{
			name: "BothTenantFieldsPreferRegular",
			setupReq: func(req *http.Request) {
				req.URL.Path = "/secure-endpoint"
				// Set a valid JWT with both tenant fields
				token := createJWT("test-tenant-123", "different-tenant")
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectCode:       http.StatusOK,
			checkTenant:      true,
			expectedTenantID: "test-tenant-123", // Should prefer TenantID over Firebase.Tenant
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
