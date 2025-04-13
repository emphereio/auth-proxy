package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/emphereio/auth-proxy/internal/apikey"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/jwt"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/emphereio/auth-proxy/internal/proxy"
	jwtlib "github.com/golang-jwt/jwt/v4"
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

// Generate a token for testing
func generateTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims *jwt.CustomClaims) string {
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to sign test token")
	return tokenString
}

func TestServerStart(t *testing.T) {
	// Create temporary directory for policies
	tmpDir, err := os.MkdirTemp("", "server-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test configuration
	cfg := &config.Config{
		Port:                  "0", // Use any available port
		BackendHost:           "localhost",
		BackendPort:           "8000",
		PolicyDir:             tmpDir,
		RequestTimeout:        5 * time.Second,
		ShutdownTimeout:       1 * time.Second,
		PolicyRefreshInterval: 30 * time.Second,
	}

	// Create OPA engine
	engine, err := opa.NewEngine(tmpDir)
	require.NoError(t, err)

	// Create a simple key manager for testing
	keyManager := apikey.NewStaticKeyManager(map[string]string{
		"test-tenant": "test-api-key",
	})

	// Create reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg, keyManager)
	require.NoError(t, err)

	// Create server
	srv := New(cfg, reverseProxy, engine)
	require.NotNil(t, srv)

	// Start server in a goroutine
	go func() {
		err := srv.Start()
		// It's expected to get an error when shutting down
		if err != http.ErrServerClosed {
			t.Errorf("Unexpected server error: %v", err)
		}
	}()

	// Wait a moment for server to start
	time.Sleep(500 * time.Millisecond)

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = srv.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestHealthCheckEndpoint(t *testing.T) {
	// Create temporary directory for policies
	tmpDir, err := os.MkdirTemp("", "server-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test configuration with a random port
	port := "0" // Use system-assigned port
	cfg := &config.Config{
		Port:                  port,
		BackendHost:           "localhost",
		BackendPort:           "8000",
		PolicyDir:             tmpDir,
		RequestTimeout:        5 * time.Second,
		ShutdownTimeout:       1 * time.Second,
		PolicyRefreshInterval: 30 * time.Second,
	}

	// Create OPA engine
	engine, err := opa.NewEngine(tmpDir)
	require.NoError(t, err)

	// Create a simple key manager for testing
	keyManager := apikey.NewStaticKeyManager(map[string]string{
		"test-tenant": "test-api-key",
	})

	// Create mock reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg, keyManager)
	require.NoError(t, err)

	// Create server
	srv := New(cfg, reverseProxy, engine)
	require.NotNil(t, srv)

	// Get port dynamically from server
	listener, err := srv.GetListener()
	require.NoError(t, err)

	// Get the dynamically assigned port
	port = listener.Addr().String()
	t.Logf("Test server using port: %s", port)

	// Start a real HTTP server for testing
	go srv.StartWithListener(listener)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Base URL for requests
	baseURL := "http://" + port

	// Test health check endpoint
	t.Run("HealthCheck", func(t *testing.T) {
		// Make request to health endpoint
		resp, err := http.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Parse JSON response
		var healthData map[string]string
		err = json.Unmarshal(body, &healthData)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "healthy", healthData["status"])
		assert.NotEmpty(t, healthData["version"])
	})
}

func TestMetricsEndpoint(t *testing.T) {
	// Create temporary directory for policies
	tmpDir, err := os.MkdirTemp("", "server-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test configuration with a random port
	port := "0" // Use system-assigned port
	cfg := &config.Config{
		Port:                  port,
		BackendHost:           "localhost",
		BackendPort:           "8000",
		PolicyDir:             tmpDir,
		RequestTimeout:        5 * time.Second,
		ShutdownTimeout:       1 * time.Second,
		PolicyRefreshInterval: 30 * time.Second,
	}

	// Create OPA engine
	engine, err := opa.NewEngine(tmpDir)
	require.NoError(t, err)

	// Create a simple key manager for testing
	keyManager := apikey.NewStaticKeyManager(map[string]string{
		"test-tenant": "test-api-key",
	})

	// Create mock reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg, keyManager)
	require.NoError(t, err)

	// Create server
	srv := New(cfg, reverseProxy, engine)
	require.NotNil(t, srv)

	// Get port dynamically from server
	listener, err := srv.GetListener()
	require.NoError(t, err)

	// Get the dynamically assigned port
	port = listener.Addr().String()
	t.Logf("Test server using port: %s", port)

	// Start a real HTTP server for testing
	go srv.StartWithListener(listener)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Base URL for requests
	baseURL := "http://" + port

	// Test metrics endpoint
	t.Run("Metrics", func(t *testing.T) {
		// Make request to metrics endpoint
		resp, err := http.Get(baseURL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Parse JSON response
		var metricsData map[string]interface{}
		err = json.Unmarshal(body, &metricsData)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, metricsData, "total_requests")
		assert.Contains(t, metricsData, "uptime_seconds")
		assert.Contains(t, metricsData, "by_path")
		assert.Contains(t, metricsData, "by_method")
	})
}

func TestMiddlewareChain(t *testing.T) {
	// This test simulates the auth flow with middlewares

	// Create temporary directory for policies
	tmpDir, err := os.MkdirTemp("", "server-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a policy that allows access for a specific tenant
	policyContent := `
	package http.authz
	
	default allow = false
	
	# Allow if tenant matches
	allow {
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
	`

	err = os.WriteFile(filepath.Join(tmpDir, "tenant_policy.rego"), []byte(policyContent), 0644)
	require.NoError(t, err)

	// Set tenant ID environment variable for testing
	expectedTenantID := "test-tenant-123"
	os.Setenv("TENANT_ID", expectedTenantID)
	defer os.Unsetenv("TENANT_ID")

	// Setup Firebase JWT verification
	// Setup mock Firebase server
	privateKey, publicKeyPem, err := generateTestRSAKey()
	require.NoError(t, err, "Failed to generate test RSA key")

	kid := "test-key-id-1"
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := map[string]string{
			kid: publicKeyPem,
		}
		w.Header().Set("Cache-Control", "public, max-age=21600")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	}))
	defer mockServer.Close()

	// Save original HTTP client and restore after test
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// Create a custom client that redirects to our test server
	http.DefaultClient = &http.Client{
		Transport: &mockTransport{
			server: mockServer,
		},
	}

	// Initialize JWT verification
	err = jwt.InitJWTVerification()
	require.NoError(t, err, "Failed to initialize JWT verification")

	// Create test configuration with a random port
	port := "0" // Use system-assigned port
	cfg := &config.Config{
		Port:                  port,
		BackendHost:           "localhost",
		BackendPort:           "8000",
		PolicyDir:             tmpDir,
		RequestTimeout:        5 * time.Second,
		ShutdownTimeout:       1 * time.Second,
		PolicyRefreshInterval: 30 * time.Second,
	}

	// Create OPA engine
	engine, err := opa.NewEngine(tmpDir)
	require.NoError(t, err)

	// Create a simple key manager for testing
	keyManager := apikey.NewStaticKeyManager(map[string]string{
		"test-tenant": "test-api-key",
	})

	// Create mock reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg, keyManager)
	require.NoError(t, err)

	// Create server
	srv := New(cfg, reverseProxy, engine)
	require.NotNil(t, srv)

	// Get port dynamically from server
	listener, err := srv.GetListener()
	require.NoError(t, err)

	// Get the dynamically assigned port
	port = listener.Addr().String()
	t.Logf("Test server using port: %s", port)

	// Start a real HTTP server for testing
	go srv.StartWithListener(listener)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Base URL for requests
	baseURL := "http://" + port

	// Generate a valid token for testing
	validClaims := &jwt.CustomClaims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwtlib.NewNumericDate(time.Now()),
		},
		TenantID: expectedTenantID,
	}
	validToken := generateTestToken(t, privateKey, kid, validClaims)

	// Test health check endpoint (should bypass auth)
	t.Run("HealthCheckBypassesAuth", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Test missing auth header
	t.Run("MissingAuthHeaderReturns401", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be unauthorized because no auth header
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Test auth denied with invalid token
	t.Run("AuthDeniedWithInvalidToken", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set invalid authorization header
		req.Header.Set("Authorization", "Bearer invalid-token")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be unauthorized (401) because token is invalid
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Test auth denied with wrong tenant in token
	t.Run("AuthDeniedWithWrongTenantToken", func(t *testing.T) {
		wrongTenantClaims := &jwt.CustomClaims{
			RegisteredClaims: jwtlib.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwtlib.NewNumericDate(time.Now()),
			},
			TenantID: "wrong-tenant",
		}
		wrongTenantToken := generateTestToken(t, privateKey, kid, wrongTenantClaims)

		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set authorization header with wrong tenant
		req.Header.Set("Authorization", "Bearer "+wrongTenantToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be forbidden (403) because tenant ID doesn't match expected
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Test auth allowed with correct tenant token
	t.Run("AuthAllowedWithCorrectTenantToken", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set authorization header with valid token that has correct tenant ID
		req.Header.Set("Authorization", "Bearer "+validToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read response body for debugging
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response (status %d): %s", resp.StatusCode, string(body))

		// We'll get either a 502 Bad Gateway or 503 Service Unavailable because there's no actual backend server
		// The important part is that it passed auth middleware and attempted to proxy to the backend
		assert.True(t, resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable,
			"Expected either 502 Bad Gateway or 503 Service Unavailable status code when backend is unavailable, got %d", resp.StatusCode)
	})

	// Test token without tenant ID
	t.Run("NoTenantIDReturns403", func(t *testing.T) {
		noTenantClaims := &jwt.CustomClaims{
			RegisteredClaims: jwtlib.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwtlib.NewNumericDate(time.Now()),
			},
			// No tenant ID
		}
		noTenantToken := generateTestToken(t, privateKey, kid, noTenantClaims)

		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set authorization header with token that has no tenant ID
		req.Header.Set("Authorization", "Bearer "+noTenantToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be forbidden (403) because token has no tenant ID
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Test expired token
	t.Run("ExpiredTokenReturns401", func(t *testing.T) {
		expiredClaims := &jwt.CustomClaims{
			RegisteredClaims: jwtlib.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
				IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
			TenantID: expectedTenantID,
		}
		expiredToken := generateTestToken(t, privateKey, kid, expiredClaims)

		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set authorization header with expired token
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be unauthorized (401) because token is expired
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Test CORS preflight handling
	t.Run("CORSPreflightHandling", func(t *testing.T) {
		req, err := http.NewRequest("OPTIONS", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Authorization")
	})
}
