package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/emphereio/auth-proxy/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	// Create reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg)
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

	// Create mock reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg)
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

	// Create mock reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg)
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
	`

	err = os.WriteFile(filepath.Join(tmpDir, "tenant_policy.rego"), []byte(policyContent), 0644)
	require.NoError(t, err)

	// Set tenant ID environment variable for testing
	os.Setenv("TENANT_ID", "test-tenant-123")
	defer os.Unsetenv("TENANT_ID")

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

	// Create mock reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg)
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

	// Test health check endpoint (should bypass auth)
	t.Run("HealthCheckBypassesAuth", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Test auth denied with wrong tenant
	t.Run("AuthDeniedWithWrongTenant", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set authorization header
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-Tenant-ID", "wrong-tenant")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Test auth allowed with correct tenant
	t.Run("AuthAllowedWithCorrectTenant", func(t *testing.T) {
		req, err := http.NewRequest("GET", baseURL+"/secure-endpoint", nil)
		require.NoError(t, err)

		// Set authorization header and correct tenant ID
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-Tenant-ID", "test-tenant-123")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// We'll get either a 502 Bad Gateway or 503 Service Unavailable because there's no actual backend server
		// The important part is that it passed auth middleware and attempted to proxy to the backend
		assert.True(t, resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable,
			"Expected either 502 Bad Gateway or 503 Service Unavailable status code when backend is unavailable")

		// Read and log the response body for debugging
		body, err := io.ReadAll(resp.Body)
		if err == nil && len(body) > 0 {
			t.Logf("Response body: %s", string(body))
		}
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
