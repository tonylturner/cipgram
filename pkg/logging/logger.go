package logging

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging capabilities
type Logger struct {
	level      LogLevel
	structured bool
	component  string
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Component string                 `json:"component,omitempty"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	File      string                 `json:"file,omitempty"`
	Line      int                    `json:"line,omitempty"`
}

// NewLogger creates a new logger instance
func NewLogger(component string, level LogLevel, structured bool) *Logger {
	return &Logger{
		level:      level,
		structured: structured,
		component:  component,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields ...map[string]interface{}) {
	if l.level <= DEBUG {
		l.log(DEBUG, message, fields...)
	}
}

// Info logs an info message
func (l *Logger) Info(message string, fields ...map[string]interface{}) {
	if l.level <= INFO {
		l.log(INFO, message, fields...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields ...map[string]interface{}) {
	if l.level <= WARN {
		l.log(WARN, message, fields...)
	}
}

// Error logs an error message
func (l *Logger) Error(message string, fields ...map[string]interface{}) {
	if l.level <= ERROR {
		l.log(ERROR, message, fields...)
	}
}

// log handles the actual logging
func (l *Logger) log(level LogLevel, message string, fields ...map[string]interface{}) {
	if l.structured {
		l.logStructured(level, message, fields...)
	} else {
		l.logPlain(level, message, fields...)
	}
}

// logStructured outputs JSON structured logs
func (l *Logger) logStructured(level LogLevel, message string, fields ...map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Component: l.component,
		Message:   message,
	}

	// Add caller information for ERROR and DEBUG levels
	if level == ERROR || level == DEBUG {
		if _, file, line, ok := runtime.Caller(3); ok {
			entry.File = file
			entry.Line = line
		}
	}

	// Merge all field maps
	if len(fields) > 0 {
		entry.Fields = make(map[string]interface{})
		for _, fieldMap := range fields {
			for k, v := range fieldMap {
				entry.Fields[k] = v
			}
		}
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		// Fallback to plain logging if JSON marshaling fails
		log.Printf("[%s] %s: %s (JSON marshal error: %v)", level.String(), l.component, message, err)
		return
	}

	fmt.Println(string(jsonData))
}

// logPlain outputs human-readable logs without emojis
func (l *Logger) logPlain(level LogLevel, message string, fields ...map[string]interface{}) {
	prefix := fmt.Sprintf("[%s]", level.String())
	if l.component != "" {
		prefix += fmt.Sprintf(" %s:", l.component)
	}

	// Format fields if provided
	var fieldStr string
	if len(fields) > 0 {
		var parts []string
		for _, fieldMap := range fields {
			for k, v := range fieldMap {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
		}
		if len(parts) > 0 {
			fieldStr = fmt.Sprintf(" [%s]", strings.Join(parts, ", "))
		}
	}

	log.Printf("%s %s%s", prefix, message, fieldStr)
}

// Global logger instance
var globalLogger *Logger

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(component string, level LogLevel, structured bool) {
	globalLogger = NewLogger(component, level, structured)
}

// GetGlobalLogger returns the global logger, creating a default one if needed
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Default logger with INFO level and plain formatting
		globalLogger = NewLogger("cipgram", INFO, false)
	}
	return globalLogger
}

// Convenience functions for global logging
func Debug(message string, fields ...map[string]interface{}) {
	GetGlobalLogger().Debug(message, fields...)
}

func Info(message string, fields ...map[string]interface{}) {
	GetGlobalLogger().Info(message, fields...)
}

func Warn(message string, fields ...map[string]interface{}) {
	GetGlobalLogger().Warn(message, fields...)
}

func Error(message string, fields ...map[string]interface{}) {
	GetGlobalLogger().Error(message, fields...)
}

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN", "WARNING":
		return WARN
	case "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// SetLogLevel sets the global logger level from environment variable
func SetLogLevel() {
	levelStr := os.Getenv("CIPGRAM_LOG_LEVEL")
	if levelStr == "" {
		levelStr = "INFO" // Default level
	}

	structured := os.Getenv("CIPGRAM_LOG_FORMAT") == "json"

	level := ParseLogLevel(levelStr)
	InitGlobalLogger("cipgram", level, structured)
}
