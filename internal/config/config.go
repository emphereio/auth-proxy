package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultPort            = "8080"
	defaultBackendHost     = "localhost"
	defaultBackendPort     = "8000"
	defaultPolicyDir       = "/policies"
	defaultRequestTimeout  = 10
	defaultShutdownTimeout = 10
)

// Config holds the application configuration
type Config struct {
	// Server settings
	Port            string
	ShutdownTimeout time.Duration

	// Backend service settings
	BackendHost    string
	BackendPort    string
	RequestTimeout time.Duration

	// OPA settings
	PolicyDir             string
	PolicyRefreshInterval time.Duration

	// Logging settings
	LogLevel  zerolog.Level
	LogFormat string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Parse timeouts
	requestTimeout := getEnvDuration("REQUEST_TIMEOUT", defaultRequestTimeout, time.Second)
	shutdownTimeout := getEnvDuration("SHUTDOWN_TIMEOUT", defaultShutdownTimeout, time.Second)
	policyRefreshInterval := getEnvDuration("POLICY_REFRESH_INTERVAL", 30, time.Second)

	// Parse log level
	logLevel := parseLogLevel(getEnv("LOG_LEVEL", "info"))

	cfg := &Config{
		Port:                  getEnv("PORT", defaultPort),
		ShutdownTimeout:       shutdownTimeout,
		BackendHost:           getEnv("BACKEND_HOST", defaultBackendHost),
		BackendPort:           getEnv("BACKEND_PORT", defaultBackendPort),
		RequestTimeout:        requestTimeout,
		PolicyDir:             getEnv("POLICY_DIR", defaultPolicyDir),
		PolicyRefreshInterval: policyRefreshInterval,
		LogLevel:              logLevel,
		LogFormat:             getEnv("LOG_FORMAT", "json"),
	}

	// Validate configuration
	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate validates the configuration
func validate(cfg *Config) error {
	// Validate port
	if _, err := strconv.Atoi(cfg.Port); err != nil {
		return fmt.Errorf("invalid port number: %s", cfg.Port)
	}

	// Validate backend port
	if _, err := strconv.Atoi(cfg.BackendPort); err != nil {
		return fmt.Errorf("invalid backend port number: %s", cfg.BackendPort)
	}

	// Validate backend host
	if cfg.BackendHost == "" {
		return fmt.Errorf("backend host cannot be empty")
	}

	// Log configuration details
	log.Info().
		Str("port", cfg.Port).
		Str("backendHost", cfg.BackendHost).
		Str("backendPort", cfg.BackendPort).
		Dur("requestTimeout", cfg.RequestTimeout).
		Dur("shutdownTimeout", cfg.ShutdownTimeout).
		Str("policyDir", cfg.PolicyDir).
		Dur("policyRefreshInterval", cfg.PolicyRefreshInterval).
		Str("logLevel", logLevel(cfg.LogLevel)).
		Str("logFormat", cfg.LogFormat).
		Msg("Configuration loaded")

	return nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvDuration gets an environment variable as a duration or returns a default value
func getEnvDuration(key string, defaultValue int, unit time.Duration) time.Duration {
	strValue := getEnv(key, "")
	if strValue == "" {
		return time.Duration(defaultValue) * unit
	}

	intValue, err := strconv.Atoi(strValue)
	if err != nil {
		log.Warn().
			Err(err).
			Str("key", key).
			Str("value", strValue).
			Int("default", defaultValue).
			Msg("Invalid duration value, using default")
		return time.Duration(defaultValue) * unit
	}

	return time.Duration(intValue) * unit
}

// parseLogLevel parses a string log level into a zerolog.Level
func parseLogLevel(level string) zerolog.Level {
	switch strings.ToUpper(level) {
	case "TRACE":
		return zerolog.TraceLevel
	case "DEBUG":
		return zerolog.DebugLevel
	case "INFO":
		return zerolog.InfoLevel
	case "WARN":
		return zerolog.WarnLevel
	case "ERROR":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// logLevel converts a zerolog.Level to a string
func logLevel(level zerolog.Level) string {
	switch level {
	case zerolog.TraceLevel:
		return "TRACE"
	case zerolog.DebugLevel:
		return "DEBUG"
	case zerolog.InfoLevel:
		return "INFO"
	case zerolog.WarnLevel:
		return "WARN"
	case zerolog.ErrorLevel:
		return "ERROR"
	default:
		return "INFO"
	}
}
