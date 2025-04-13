package main

import (
	"context"
	"github.com/emphereio/auth-proxy/internal/apikey"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/emphereio/auth-proxy/internal/proxy"
	"github.com/emphereio/auth-proxy/internal/server"
	"github.com/emphereio/auth-proxy/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMainIntegration tests the main functionality as an integration test
func TestMainIntegration(t *testing.T) {
	// Skip in short test mode as this is an integration test
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test environment
	tmpDir, err := os.MkdirTemp("", "auth-proxy-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Set environment variables for the test
	os.Setenv("PORT", "0") // Use any available port
	os.Setenv("BACKEND_HOST", "localhost")
	os.Setenv("BACKEND_PORT", "8000")
	os.Setenv("POLICY_DIR", tmpDir)
	os.Setenv("LOG_LEVEL", "error")    // Minimize logging for tests
	os.Setenv("SHUTDOWN_TIMEOUT", "1") // Quick shutdown for tests
	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("BACKEND_HOST")
		os.Unsetenv("BACKEND_PORT")
		os.Unsetenv("POLICY_DIR")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("SHUTDOWN_TIMEOUT")
	}()

	// Create a simple policy for testing
	policyContent := `
	package http.authz
	default allow = false
	allow { input.attributes.request.http.path == "/health" }
	allow { input.attributes.request.http.path == "/metrics" }
	`

	err = os.WriteFile(tmpDir+"/test_policy.rego", []byte(policyContent), 0644)
	require.NoError(t, err)

	// Following the structure of main() but with test adaptations
	logging.Setup()

	// Load configuration
	cfg, err := config.Load()
	require.NoError(t, err)

	// Test should specify its own port
	cfg.Port = "8765" // Use specific port for test

	// Initialize OPA engine
	opaEngine, err := opa.NewEngine(cfg.PolicyDir)
	require.NoError(t, err)

	// Start policy watcher in background
	watcher, err := opa.NewWatcher(opaEngine, cfg.PolicyDir)
	require.NoError(t, err)
	go watcher.Start()
	defer watcher.Stop()

	// Create a simple key manager for testing
	keyManager := apikey.NewStaticKeyManager(map[string]string{
		"test-tenant": "test-api-key",
	})

	// Create reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg, keyManager)
	require.NoError(t, err)

	// Create and start HTTP server
	srv := server.New(cfg, reverseProxy, opaEngine)
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server failed to start: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Test the server is running by making a request to health endpoint
	resp, err := http.Get("http://localhost:8765/health")
	if err != nil {
		t.Fatalf("Failed to reach server: %v", err)
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test securing endpoint (should be rejected without auth)
	resp, err = http.Get("http://localhost:8765/secure-api")
	if err != nil {
		t.Fatalf("Failed to reach secure endpoint: %v", err)
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Simulate SIGINT to test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown the server
	err = srv.Shutdown(ctx)
	require.NoError(t, err)

	// Verify the server is shut down by attempting another request
	// This should fail or timeout since the server is shut down
	client := &http.Client{
		Timeout: 500 * time.Millisecond,
	}
	_, err = client.Get("http://localhost:8765/health")
	assert.Error(t, err, "Server should be shut down")
}

// TestMainSignalHandling tests signal handling
func TestMainSignalHandling(t *testing.T) {
	// Create a channel to simulate signals
	quit := make(chan os.Signal, 1)

	// Create a done channel to indicate test completion
	done := make(chan bool, 1)

	// Start a goroutine that waits for signals similar to main()
	go func() {
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		// We received the signal
		done <- true
	}()

	// Send a signal
	quit <- syscall.SIGINT

	// Wait for the signal handler to process it or timeout
	select {
	case <-done:
		// Signal was processed successfully
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for signal to be processed")
	}
}

// TestMainIntegrationWithServerError tests handling of server start failures
func TestMainIntegrationWithServerError(t *testing.T) {
	// Setup test environment
	tmpDir, err := os.MkdirTemp("", "auth-proxy-test-error")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Set environment variables for the test
	os.Setenv("PORT", "12345678") // Invalid port should cause an error
	os.Setenv("POLICY_DIR", tmpDir)
	os.Setenv("LOG_LEVEL", "error")
	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("POLICY_DIR")
		os.Unsetenv("LOG_LEVEL")
	}()

	logging.Setup()

	// Load configuration should succeed but server start should fail
	cfg, err := config.Load()
	require.NoError(t, err)

	// Create a simple key manager for testing
	keyManager := apikey.NewStaticKeyManager(map[string]string{
		"test-tenant": "test-api-key",
	})

	// Initialize OPA engine
	opaEngine, err := opa.NewEngine(cfg.PolicyDir)
	require.NoError(t, err)

	// Create reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg, keyManager)
	require.NoError(t, err)

	// Create server
	srv := server.New(cfg, reverseProxy, opaEngine)

	// Starting the server should fail due to invalid port
	err = srv.Start()
	assert.Error(t, err, "Server should fail to start with invalid port")
}
