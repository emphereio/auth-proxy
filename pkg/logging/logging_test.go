package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetup(t *testing.T) {
	// Save original values to restore later
	originalStdout := os.Stdout
	originalLogger := log.Logger
	originalGlobalLevel := zerolog.GlobalLevel()

	// Restore original state after the test
	defer func() {
		os.Stdout = originalStdout
		log.Logger = originalLogger
		zerolog.SetGlobalLevel(originalGlobalLevel)
	}()

	// Test JSON format
	t.Run("JSONFormat", func(t *testing.T) {
		// Override stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Reset environment
		os.Clearenv()
		os.Setenv("LOG_FORMAT", "json")
		os.Setenv("LOG_LEVEL", "info")
		os.Setenv("SERVICE_NAME", "test-service")

		// Run setup
		Setup()

		// Write a log entry that should go to our pipe
		log.Info().Str("key", "value").Msg("Test message")

		// Close the writer to flush the pipe
		w.Close()

		// Read from the pipe
		output, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NotEmpty(t, output)

		// Trim any trailing newlines or whitespace
		jsonStr := strings.TrimSpace(string(output))

		// Parse JSON
		var logData map[string]interface{}
		err = json.Unmarshal([]byte(jsonStr), &logData)
		require.NoError(t, err, "Failed to parse JSON: %s", jsonStr)

		// Check expected fields
		assert.Equal(t, "info", logData["level"])
		assert.Equal(t, "Test message", logData["message"])
		assert.Equal(t, "value", logData["key"])
		assert.Equal(t, "test-service", logData["service"])
		assert.Contains(t, logData, "time")
	})

	// Test console format
	t.Run("ConsoleFormat", func(t *testing.T) {
		// Setup buffer to capture output
		var buf bytes.Buffer

		// Set environment variables
		os.Clearenv()
		os.Setenv("LOG_FORMAT", "console")
		os.Setenv("LOG_LEVEL", "info")
		os.Setenv("SERVICE_NAME", "test-service")
		os.Setenv("LOG_NO_COLOR", "true") // Disable color for consistent testing

		// Set up custom logger with the buffer
		log.Logger = zerolog.New(&buf).With().Timestamp().Logger()

		// Force our logger to have a ConsoleWriter
		cw := zerolog.ConsoleWriter{
			Out:        &buf,
			TimeFormat: time.RFC3339,
			NoColor:    true,
		}
		log.Logger = zerolog.New(cw).With().Timestamp().Logger()

		// Run setup (which should replace our logger)
		r, w, _ := os.Pipe()
		os.Stdout = w
		Setup()

		// Log a message to the new logger
		log.Info().Str("key", "value").Msg("Test message")

		// Close the pipe to flush
		w.Close()
		output, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NotEmpty(t, output)

		// Get the output string
		outputStr := string(output)

		// Check for expected components
		assert.Contains(t, outputStr, "Test message")
		assert.Contains(t, outputStr, "key=value")
		assert.Contains(t, outputStr, "service=test-service")
	})
}

func TestLogLevelSetting(t *testing.T) {
	// Save original values
	originalLogger := log.Logger
	originalGlobalLevel := zerolog.GlobalLevel()

	// Restore after test
	defer func() {
		log.Logger = originalLogger
		zerolog.SetGlobalLevel(originalGlobalLevel)
	}()

	tests := []struct {
		level          string
		expectedLevel  zerolog.Level
		shouldLogDebug bool
		shouldLogInfo  bool
		shouldLogWarn  bool
		shouldLogError bool
	}{
		{
			level:          "TRACE",
			expectedLevel:  zerolog.TraceLevel,
			shouldLogDebug: true,
			shouldLogInfo:  true,
			shouldLogWarn:  true,
			shouldLogError: true,
		},
		{
			level:          "DEBUG",
			expectedLevel:  zerolog.DebugLevel,
			shouldLogDebug: true,
			shouldLogInfo:  true,
			shouldLogWarn:  true,
			shouldLogError: true,
		},
		{
			level:          "INFO",
			expectedLevel:  zerolog.InfoLevel,
			shouldLogDebug: false,
			shouldLogInfo:  true,
			shouldLogWarn:  true,
			shouldLogError: true,
		},
		{
			level:          "WARN",
			expectedLevel:  zerolog.WarnLevel,
			shouldLogDebug: false,
			shouldLogInfo:  false,
			shouldLogWarn:  true,
			shouldLogError: true,
		},
		{
			level:          "ERROR",
			expectedLevel:  zerolog.ErrorLevel,
			shouldLogDebug: false,
			shouldLogInfo:  false,
			shouldLogWarn:  false,
			shouldLogError: true,
		},
		{
			level:          "INVALID", // Should default to INFO
			expectedLevel:  zerolog.InfoLevel,
			shouldLogDebug: false,
			shouldLogInfo:  true,
			shouldLogWarn:  true,
			shouldLogError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			// Clear environment
			os.Clearenv()
			os.Setenv("LOG_LEVEL", tc.level)
			os.Setenv("LOG_FORMAT", "json") // Use JSON for easier parsing

			// Set up a buffer for capturing log output
			var buf bytes.Buffer
			log.Logger = zerolog.New(&buf)

			// Call the function to set the log level
			setLogLevel(tc.level)

			// Verify the log level was set correctly
			assert.Equal(t, tc.expectedLevel, zerolog.GlobalLevel())

			// Test debug logs
			buf.Reset()
			log.Debug().Msg("Debug message")
			debugOut := buf.String()
			if tc.shouldLogDebug {
				assert.Contains(t, debugOut, "Debug message", "Debug logs should be enabled at %s level", tc.level)
			} else {
				assert.Empty(t, debugOut, "Debug logs should be disabled at %s level", tc.level)
			}

			// Test info logs
			buf.Reset()
			log.Info().Msg("Info message")
			infoOut := buf.String()
			if tc.shouldLogInfo {
				assert.Contains(t, infoOut, "Info message", "Info logs should be enabled at %s level", tc.level)
			} else {
				assert.Empty(t, infoOut, "Info logs should be disabled at %s level", tc.level)
			}

			// Test warn logs
			buf.Reset()
			log.Warn().Msg("Warn message")
			warnOut := buf.String()
			if tc.shouldLogWarn {
				assert.Contains(t, warnOut, "Warn message", "Warn logs should be enabled at %s level", tc.level)
			} else {
				assert.Empty(t, warnOut, "Warn logs should be disabled at %s level", tc.level)
			}

			// Test error logs
			buf.Reset()
			log.Error().Msg("Error message")
			errorOut := buf.String()
			if tc.shouldLogError {
				assert.Contains(t, errorOut, "Error message", "Error logs should be enabled at %s level", tc.level)
			} else {
				assert.Empty(t, errorOut, "Error logs should be disabled at %s level", tc.level)
			}
		})
	}
}

func TestAddFields(t *testing.T) {
	// Setup
	var buf bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() {
		log.Logger = originalLogger
	}()

	// Test adding various field types
	fields := map[string]interface{}{
		"string_key":   "string_value",
		"int_key":      42,
		"bool_key":     true,
		"time_key":     time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		"duration_key": 5 * time.Second,
		"complex_key":  map[string]string{"nested": "value"},
	}

	// Add fields
	AddFields(fields)

	// Write a log
	log.Info().Msg("Test message with fields")

	// Parse the output
	var logData map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logData)
	require.NoError(t, err)

	// Check fields
	assert.Equal(t, "string_value", logData["string_key"])
	assert.Equal(t, float64(42), logData["int_key"])
	assert.Equal(t, true, logData["bool_key"])
	assert.Contains(t, logData["time_key"], "2023-01-01T12:00:00")
	assert.Equal(t, float64(5000), logData["duration_key"])

	// Complex objects are serialized as JSON strings
	assert.Contains(t, logData["complex_key"], "nested")
}
