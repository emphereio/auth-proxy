// Package logging provides zerolog configuration and setup
package logging

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup initializes the zerolog logger with appropriate settings
func Setup() {
	// Configure timestamp format
	zerolog.TimeFieldFormat = time.RFC3339

	// Set log level
	setLogLevel(getEnv("LOG_LEVEL", "info"))

	// Determine log format (json or console)
	logFormat := strings.ToLower(getEnv("LOG_FORMAT", "json"))

	if logFormat == "console" {
		// Create console writer
		noColor := getEnv("LOG_NO_COLOR", "") != ""
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
			NoColor:    noColor,
		}
		// Create logger with console writer
		log.Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	} else {
		// Default to JSON format with timestamps
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}

	// Add service name to all logs
	serviceName := getEnv("SERVICE_NAME", "auth-proxy")
	log.Logger = log.With().Str("service", serviceName).Logger()
}

// setLogLevel sets the global log level based on a string level
func setLogLevel(level string) {
	switch strings.ToUpper(level) {
	case "TRACE":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "DEBUG":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "INFO":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "WARN":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "ERROR":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
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

// AddFields adds fields to the logger
func AddFields(fields map[string]interface{}) {
	ctx := log.With()

	for k, v := range fields {
		switch val := v.(type) {
		case string:
			ctx = ctx.Str(k, val)
		case int:
			ctx = ctx.Int(k, val)
		case bool:
			ctx = ctx.Bool(k, val)
		case time.Time:
			ctx = ctx.Time(k, val)
		case time.Duration:
			ctx = ctx.Dur(k, val)
		default:
			ctx = ctx.Interface(k, val)
		}
	}

	log.Logger = ctx.Logger()
}
