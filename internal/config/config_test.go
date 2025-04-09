package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	// Test default configuration
	t.Run("DefaultConfig", func(t *testing.T) {
		// Clear environment variables that might affect the test
		os.Clearenv()

		cfg, err := config.Load()
		assert.NoError(t, err)
		assert.Equal(t, "8080", cfg.Port)
		assert.Equal(t, "localhost", cfg.BackendHost)
		assert.Equal(t, "8000", cfg.BackendPort)
		assert.Equal(t, "/policies", cfg.PolicyDir)
		assert.Equal(t, 10*time.Second, cfg.RequestTimeout)
		assert.Equal(t, 10*time.Second, cfg.ShutdownTimeout)
		assert.Equal(t, 30*time.Second, cfg.PolicyRefreshInterval)
		assert.Equal(t, zerolog.InfoLevel, cfg.LogLevel)
		assert.Equal(t, "json", cfg.LogFormat)
	})

	// Test custom configuration from environment variables
	t.Run("CustomConfig", func(t *testing.T) {
		// Clear environment variables and set custom ones
		os.Clearenv()
		os.Setenv("PORT", "9090")
		os.Setenv("BACKEND_HOST", "api.example.com")
		os.Setenv("BACKEND_PORT", "9000")
		os.Setenv("POLICY_DIR", "/custom/policies")
		os.Setenv("REQUEST_TIMEOUT", "15")
		os.Setenv("SHUTDOWN_TIMEOUT", "20")
		os.Setenv("POLICY_REFRESH_INTERVAL", "60")
		os.Setenv("LOG_LEVEL", "DEBUG")
		os.Setenv("LOG_FORMAT", "console")

		cfg, err := config.Load()
		assert.NoError(t, err)
		assert.Equal(t, "9090", cfg.Port)
		assert.Equal(t, "api.example.com", cfg.BackendHost)
		assert.Equal(t, "9000", cfg.BackendPort)
		assert.Equal(t, "/custom/policies", cfg.PolicyDir)
		assert.Equal(t, 15*time.Second, cfg.RequestTimeout)
		assert.Equal(t, 20*time.Second, cfg.ShutdownTimeout)
		assert.Equal(t, 60*time.Second, cfg.PolicyRefreshInterval)
		assert.Equal(t, zerolog.DebugLevel, cfg.LogLevel)
		assert.Equal(t, "console", cfg.LogFormat)
	})

	// Test invalid port
	t.Run("InvalidPort", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("PORT", "invalid")

		cfg, err := config.Load()
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "invalid port number")
	})

	// Test invalid backend port
	t.Run("InvalidBackendPort", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("BACKEND_PORT", "invalid")

		cfg, err := config.Load()
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "invalid backend port number")
	})

	// Test empty backend host
	t.Run("EmptyBackendHost", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("BACKEND_HOST", "")

		// Should use default, which is "localhost"
		cfg, err := config.Load()
		assert.NoError(t, err)
		assert.Equal(t, "localhost", cfg.BackendHost)
	})

	// Test invalid duration values
	t.Run("InvalidDurationValues", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("REQUEST_TIMEOUT", "abc")

		// Should use default value when invalid
		cfg, err := config.Load()
		assert.NoError(t, err)
		assert.Equal(t, 10*time.Second, cfg.RequestTimeout)
	})

	// Test log level parsing
	t.Run("LogLevelParsing", func(t *testing.T) {
		testCases := []struct {
			level    string
			expected zerolog.Level
		}{
			{"TRACE", zerolog.TraceLevel},
			{"DEBUG", zerolog.DebugLevel},
			{"INFO", zerolog.InfoLevel},
			{"WARN", zerolog.WarnLevel},
			{"ERROR", zerolog.ErrorLevel},
			{"invalid", zerolog.InfoLevel}, // Default to INFO for invalid
		}

		for _, tc := range testCases {
			os.Clearenv()
			os.Setenv("LOG_LEVEL", tc.level)

			cfg, err := config.Load()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.LogLevel)
		}
	})
}
