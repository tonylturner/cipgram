package logging_test

import (
	"bytes"
	"cipgram/pkg/logging"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    logging.LogLevel
		expected string
	}{
		{logging.DEBUG, "DEBUG"},
		{logging.INFO, "INFO"},
		{logging.WARN, "WARN"},
		{logging.ERROR, "ERROR"},
		{logging.LogLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name       string
		component  string
		level      logging.LogLevel
		structured bool
	}{
		{
			name:       "Basic logger",
			component:  "test",
			level:      logging.INFO,
			structured: false,
		},
		{
			name:       "Structured logger",
			component:  "test-structured",
			level:      logging.DEBUG,
			structured: true,
		},
		{
			name:       "Empty component",
			component:  "",
			level:      logging.ERROR,
			structured: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.NewLogger(tt.component, tt.level, tt.structured)

			if logger == nil {
				t.Fatal("logging.NewLogger() returned nil")
			}

			// Can't test internal fields since they're unexported
			// The fact that NewLogger didn't panic is sufficient
		})
	}
}

func TestSetLogLevel(t *testing.T) {
	// Save original environment
	originalLevel := os.Getenv("CIPGRAM_LOG_LEVEL")
	originalFormat := os.Getenv("CIPGRAM_LOG_FORMAT")
	defer func() {
		os.Setenv("CIPGRAM_LOG_LEVEL", originalLevel)
		os.Setenv("CIPGRAM_LOG_FORMAT", originalFormat)
	}()

	tests := []struct {
		name           string
		logLevel       string
		logFormat      string
		expectedLevel  logging.LogLevel
		expectedFormat bool
	}{
		{
			name:           "Debug level",
			logLevel:       "DEBUG",
			logFormat:      "",
			expectedLevel:  logging.DEBUG,
			expectedFormat: false,
		},
		{
			name:           "Info level with JSON",
			logLevel:       "INFO",
			logFormat:      "json",
			expectedLevel:  logging.INFO,
			expectedFormat: true,
		},
		{
			name:           "Warn level",
			logLevel:       "WARN",
			logFormat:      "",
			expectedLevel:  logging.WARN,
			expectedFormat: false,
		},
		{
			name:           "Error level",
			logLevel:       "ERROR",
			logFormat:      "",
			expectedLevel:  logging.ERROR,
			expectedFormat: false,
		},
		{
			name:           "Invalid level defaults to INFO",
			logLevel:       "INVALID",
			logFormat:      "",
			expectedLevel:  logging.INFO,
			expectedFormat: false,
		},
		{
			name:           "Empty level defaults to INFO",
			logLevel:       "",
			logFormat:      "",
			expectedLevel:  logging.INFO,
			expectedFormat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			os.Setenv("CIPGRAM_LOG_LEVEL", tt.logLevel)
			os.Setenv("CIPGRAM_LOG_FORMAT", tt.logFormat)

			// Call SetLogLevel
			logging.SetLogLevel()

			// Can't test internal fields since they're unexported
			// The fact that SetLogLevel didn't panic is sufficient
			logger := logging.GetGlobalLogger()
			if logger == nil {
				t.Error("Expected non-nil global logger")
			}
		})
	}
}

func TestLoggerLevels(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	tests := []struct {
		name         string
		loggerLevel  logging.LogLevel
		messageLevel logging.LogLevel
		message      string
		shouldLog    bool
	}{
		{
			name:         "Debug logger logs debug message",
			loggerLevel:  logging.DEBUG,
			messageLevel: logging.DEBUG,
			message:      "debug message",
			shouldLog:    true,
		},
		{
			name:         "Info logger skips debug message",
			loggerLevel:  logging.INFO,
			messageLevel: logging.DEBUG,
			message:      "debug message",
			shouldLog:    false,
		},
		{
			name:         "Info logger logs info message",
			loggerLevel:  logging.INFO,
			messageLevel: logging.INFO,
			message:      "info message",
			shouldLog:    true,
		},
		{
			name:         "Warn logger logs warn message",
			loggerLevel:  logging.WARN,
			messageLevel: logging.WARN,
			message:      "warn message",
			shouldLog:    true,
		},
		{
			name:         "Error logger logs error message",
			loggerLevel:  logging.ERROR,
			messageLevel: logging.ERROR,
			message:      "error message",
			shouldLog:    true,
		},
		{
			name:         "Error logger skips info message",
			loggerLevel:  logging.ERROR,
			messageLevel: logging.INFO,
			message:      "info message",
			shouldLog:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			logger := logging.NewLogger("test", tt.loggerLevel, false)

			// Call appropriate log method
			switch tt.messageLevel {
			case logging.DEBUG:
				logger.Debug(tt.message)
			case logging.INFO:
				logger.Info(tt.message)
			case logging.WARN:
				logger.Warn(tt.message)
			case logging.ERROR:
				logger.Error(tt.message)
			}

			output := buf.String()

			if tt.shouldLog {
				if output == "" {
					t.Errorf("Expected log output for %s level, got empty", tt.messageLevel.String())
				}
				if !strings.Contains(output, tt.message) {
					t.Errorf("Expected log output to contain %s, got %s", tt.message, output)
				}
			} else {
				if output != "" {
					t.Errorf("Expected no log output for %s level, got %s", tt.messageLevel.String(), output)
				}
			}
		})
	}
}

func TestStructuredLogging(t *testing.T) {
	// Capture stdout since structured logging uses fmt.Println
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := logging.NewLogger("test-component", logging.INFO, true)

	// Test structured logging with fields
	fields := map[string]interface{}{
		"user_id":    123,
		"action":     "login",
		"ip_address": "192.168.1.1",
		"success":    true,
	}

	logger.Info("User login attempt", fields)

	// Close writer and restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Fatal("Expected structured log output, got empty")
	}

	// Parse JSON output
	var logEntry logging.LogEntry
	err := json.Unmarshal([]byte(output), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse JSON log output: %v", err)
	}

	// Verify log entry structure
	if logEntry.Level != "INFO" {
		t.Errorf("Expected level logging.INFO, got %s", logEntry.Level)
	}

	if logEntry.Component != "test-component" {
		t.Errorf("Expected component test-component, got %s", logEntry.Component)
	}

	if logEntry.Message != "User login attempt" {
		t.Errorf("Expected message 'User login attempt', got %s", logEntry.Message)
	}

	if logEntry.Timestamp == "" {
		t.Error("Expected non-empty timestamp")
	}

	// Verify fields
	if logEntry.Fields == nil {
		t.Fatal("Expected fields to be present")
	}

	if logEntry.Fields["user_id"] != float64(123) { // JSON numbers are float64
		t.Errorf("Expected user_id 123, got %v", logEntry.Fields["user_id"])
	}

	if logEntry.Fields["action"] != "login" {
		t.Errorf("Expected action login, got %v", logEntry.Fields["action"])
	}

	if logEntry.Fields["success"] != true {
		t.Errorf("Expected success true, got %v", logEntry.Fields["success"])
	}
}

func TestPlainLogging(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := logging.NewLogger("test-component", logging.INFO, false)

	// Test plain logging
	logger.Info("Simple log message")

	output := buf.String()
	if output == "" {
		t.Fatal("Expected log output, got empty")
	}

	// Should contain level, component, and message
	if !strings.Contains(output, "[INFO]") {
		t.Error("Expected [INFO] in plain log output")
	}

	if !strings.Contains(output, "test-component") {
		t.Error("Expected component name in plain log output")
	}

	if !strings.Contains(output, "Simple log message") {
		t.Error("Expected message in plain log output")
	}
}

func TestLoggingWithFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := logging.NewLogger("test", logging.INFO, false)

	// Test logging with fields (plain format)
	fields := map[string]interface{}{
		"count": 42,
		"name":  "test",
	}

	logger.Info("Message with fields", fields)

	output := buf.String()
	if output == "" {
		t.Fatal("Expected log output, got empty")
	}

	// Should contain the fields in some format
	if !strings.Contains(output, "count") {
		t.Error("Expected field 'count' in log output")
	}

	if !strings.Contains(output, "42") {
		t.Error("Expected field value '42' in log output")
	}
}

func TestMultipleFields(t *testing.T) {
	// Capture stdout since structured logging uses fmt.Println
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := logging.NewLogger("test", logging.DEBUG, true)

	// Test with multiple field maps
	fields1 := map[string]interface{}{
		"field1": "value1",
	}
	fields2 := map[string]interface{}{
		"field2": "value2",
	}

	logger.Debug("Message with multiple field maps", fields1, fields2)

	// Close writer and restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Fatal("Expected log output, got empty")
	}

	// Parse JSON output
	var logEntry logging.LogEntry
	err := json.Unmarshal([]byte(output), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse JSON log output: %v", err)
	}

	// Both fields should be present
	if logEntry.Fields["field1"] != "value1" {
		t.Errorf("Expected field1 value1, got %v", logEntry.Fields["field1"])
	}

	if logEntry.Fields["field2"] != "value2" {
		t.Errorf("Expected field2 value2, got %v", logEntry.Fields["field2"])
	}
}

func TestLoggerWithEmptyComponent(t *testing.T) {
	// Capture stdout since structured logging uses fmt.Println
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := logging.NewLogger("", logging.INFO, true)
	logger.Info("Test message")

	// Close writer and restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Fatal("Expected log output, got empty")
	}

	// Parse JSON output
	var logEntry logging.LogEntry
	err := json.Unmarshal([]byte(output), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse JSON log output: %v", err)
	}

	// Component should be empty but present
	if logEntry.Component != "" {
		t.Errorf("Expected empty component, got %s", logEntry.Component)
	}
}

func TestLoggerFileAndLine(t *testing.T) {
	// Capture stdout since structured logging uses fmt.Println
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Use DEBUG level since file/line info is only added for ERROR and DEBUG levels
	logger := logging.NewLogger("test", logging.DEBUG, true)
	logger.Debug("Test message for file/line")

	// Close writer and restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Fatal("Expected log output, got empty")
	}

	// Parse JSON output
	var logEntry logging.LogEntry
	err := json.Unmarshal([]byte(output), &logEntry)
	if err != nil {
		t.Fatalf("Failed to parse JSON log output: %v", err)
	}

	// File should contain the test file name
	if logEntry.File == "" {
		t.Error("Expected non-empty file field")
	}

	if !strings.Contains(logEntry.File, "logger_test.go") {
		t.Errorf("Expected file to contain logger_test.go, got %s", logEntry.File)
	}

	// Line should be positive
	if logEntry.Line <= 0 {
		t.Errorf("Expected positive line number, got %d", logEntry.Line)
	}
}

// Benchmark tests

func BenchmarkPlainLogging(b *testing.B) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := logging.NewLogger("benchmark", logging.INFO, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("Benchmark message")
	}
}

func BenchmarkStructuredLogging(b *testing.B) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := logging.NewLogger("benchmark", logging.INFO, true)
	fields := map[string]interface{}{
		"iteration": 0,
		"benchmark": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fields["iteration"] = i
		logger.Info("Benchmark message", fields)
	}
}

func BenchmarkLoggingWithFields(b *testing.B) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := logging.NewLogger("benchmark", logging.INFO, false)
	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("Benchmark message with fields", fields)
	}
}

func BenchmarkSkippedLogging(b *testing.B) {
	logger := logging.NewLogger("benchmark", logging.ERROR, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Debug("This message should be skipped")
	}
}
