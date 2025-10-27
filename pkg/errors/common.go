package errors

import (
	"fmt"
	"os"
)

// Common error scenarios with pre-defined messages and context

// File and IO related errors

// ErrFileNotFound creates a file not found error
func ErrFileNotFound(filepath string) *CIPGramError {
	return NewIOError(CodeFileNotFound, "file not found").
		WithContext("filepath", filepath).
		WithDetails(fmt.Sprintf("The file '%s' does not exist or is not accessible", filepath))
}

// ErrFilePermissionDenied creates a permission denied error
func ErrFilePermissionDenied(filepath string) *CIPGramError {
	return NewSystemError(CodePermissionDenied, "permission denied").
		WithContext("filepath", filepath).
		WithDetails(fmt.Sprintf("Insufficient permissions to access '%s'", filepath))
}

// ErrFileReadFailed creates a file read error
func ErrFileReadFailed(filepath string, cause error) *CIPGramError {
	return NewIOError(CodeReadFailed, "failed to read file").
		WithContext("filepath", filepath).
		WithCause(cause).
		WithDetails(fmt.Sprintf("Unable to read from file '%s'", filepath))
}

// ErrFileWriteFailed creates a file write error
func ErrFileWriteFailed(filepath string, cause error) *CIPGramError {
	return NewIOError(CodeWriteFailed, "failed to write file").
		WithContext("filepath", filepath).
		WithCause(cause).
		WithDetails(fmt.Sprintf("Unable to write to file '%s'", filepath))
}

// ErrDirectoryCreateFailed creates a directory creation error
func ErrDirectoryCreateFailed(dirpath string, cause error) *CIPGramError {
	return NewIOError(CodeCreateFailed, "failed to create directory").
		WithContext("directory", dirpath).
		WithCause(cause).
		WithDetails(fmt.Sprintf("Unable to create directory '%s'", dirpath))
}

// Validation related errors

// ErrInvalidCIDR creates an invalid CIDR error
func ErrInvalidCIDR(cidr string, reason string) *CIPGramError {
	err := NewValidationError(CodeInvalidCIDR, "invalid CIDR notation").
		WithContext("cidr", cidr)

	if reason != "" {
		err = err.WithDetails(fmt.Sprintf("CIDR '%s' is invalid: %s", cidr, reason))
	} else {
		err = err.WithDetails(fmt.Sprintf("CIDR '%s' is not in valid format", cidr))
	}

	return err
}

// ErrInvalidMAC creates an invalid MAC address error
func ErrInvalidMAC(mac string) *CIPGramError {
	return NewValidationError(CodeInvalidMAC, "invalid MAC address").
		WithContext("mac", mac).
		WithDetails(fmt.Sprintf("MAC address '%s' is not in valid format", mac))
}

// ErrInvalidProtocol creates an invalid protocol error
func ErrInvalidProtocol(protocol string, reason string) *CIPGramError {
	err := NewValidationError(CodeInvalidProtocol, "invalid protocol").
		WithContext("protocol", protocol)

	if reason != "" {
		err = err.WithDetails(fmt.Sprintf("Protocol '%s' is invalid: %s", protocol, reason))
	} else {
		err = err.WithDetails(fmt.Sprintf("Protocol '%s' is not recognized", protocol))
	}

	return err
}

// ErrInvalidPurdueLevel creates an invalid Purdue level error
func ErrInvalidPurdueLevel(level string) *CIPGramError {
	return NewValidationError(CodeInvalidLevel, "invalid Purdue level").
		WithContext("level", level).
		WithDetails(fmt.Sprintf("Purdue level '%s' is not valid (must be L0-L5, L3.5, or Unknown)", level))
}

// Configuration related errors

// ErrMissingRequiredField creates a missing required field error
func ErrMissingRequiredField(fieldName string) *CIPGramError {
	return NewUserError(CodeMissingRequired, "missing required field").
		WithContext("field", fieldName).
		WithDetails(fmt.Sprintf("Required field '%s' is missing or empty", fieldName))
}

// ErrInvalidConfiguration creates an invalid configuration error
func ErrInvalidConfiguration(configType string, reason string) *CIPGramError {
	err := NewConfigError(CodeInvalidConfig, "invalid configuration").
		WithContext("config_type", configType)

	if reason != "" {
		err = err.WithDetails(fmt.Sprintf("Configuration '%s' is invalid: %s", configType, reason))
	} else {
		err = err.WithDetails(fmt.Sprintf("Configuration '%s' contains invalid settings", configType))
	}

	return err
}

// ErrMissingConfiguration creates a missing configuration error
func ErrMissingConfiguration(configType string) *CIPGramError {
	return NewConfigError(CodeMissingConfig, "missing configuration").
		WithContext("config_type", configType).
		WithDetails(fmt.Sprintf("Required configuration '%s' is not provided", configType))
}

// Parse related errors

// ErrMalformedPCAP creates a malformed PCAP error
func ErrMalformedPCAP(filepath string, cause error) *CIPGramError {
	return NewParseError(CodeMalformedPCAP, "malformed PCAP file").
		WithContext("filepath", filepath).
		WithCause(cause).
		WithDetails(fmt.Sprintf("PCAP file '%s' is corrupted or not in valid format", filepath))
}

// ErrMalformedConfig creates a malformed configuration error
func ErrMalformedConfig(filepath string, configType string, cause error) *CIPGramError {
	return NewParseError(CodeMalformedConfig, "malformed configuration file").
		WithContext("filepath", filepath).
		WithContext("config_type", configType).
		WithCause(cause).
		WithDetails(fmt.Sprintf("%s configuration file '%s' is not in valid format", configType, filepath))
}

// ErrUnsupportedFormat creates an unsupported format error
func ErrUnsupportedFormat(format string, supportedFormats []string) *CIPGramError {
	err := NewParseError(CodeUnsupportedFormat, "unsupported file format").
		WithContext("format", format).
		WithContext("supported_formats", supportedFormats)

	if len(supportedFormats) > 0 {
		err = err.WithDetails(fmt.Sprintf("Format '%s' is not supported. Supported formats: %v", format, supportedFormats))
	} else {
		err = err.WithDetails(fmt.Sprintf("Format '%s' is not supported", format))
	}

	return err
}

// Network related errors

// ErrConnectionFailed creates a connection failed error
func ErrConnectionFailed(host string, port int, cause error) *CIPGramError {
	return NewNetworkError(CodeConnectionFailed, "connection failed").
		WithContext("host", host).
		WithContext("port", port).
		WithCause(cause).
		WithDetails(fmt.Sprintf("Failed to connect to %s:%d", host, port))
}

// ErrTimeout creates a timeout error
func ErrTimeout(operation string, timeoutSeconds int) *CIPGramError {
	return NewNetworkError(CodeTimeout, "operation timed out").
		WithContext("operation", operation).
		WithContext("timeout_seconds", timeoutSeconds).
		WithDetails(fmt.Sprintf("Operation '%s' timed out after %d seconds", operation, timeoutSeconds))
}

// User input related errors

// ErrInvalidInput creates an invalid input error
func ErrInvalidInput(inputName string, value interface{}, reason string) *CIPGramError {
	err := NewUserError(CodeInvalidInput, "invalid input").
		WithContext("input_name", inputName).
		WithContext("value", value)

	if reason != "" {
		err = err.WithDetails(fmt.Sprintf("Input '%s' with value '%v' is invalid: %s", inputName, value, reason))
	} else {
		err = err.WithDetails(fmt.Sprintf("Input '%s' with value '%v' is not valid", inputName, value))
	}

	return err
}

// ErrInvalidFormat creates an invalid format error
func ErrInvalidFormat(inputName string, value string, expectedFormat string) *CIPGramError {
	return NewUserError(CodeInvalidFormat, "invalid format").
		WithContext("input_name", inputName).
		WithContext("value", value).
		WithContext("expected_format", expectedFormat).
		WithDetails(fmt.Sprintf("Input '%s' with value '%s' does not match expected format: %s", inputName, value, expectedFormat))
}

// Internal errors

// ErrUnexpected creates an unexpected error (should be used sparingly)
func ErrUnexpected(operation string, cause error) *CIPGramError {
	return NewInternalError(CodeUnexpected, "unexpected error").
		WithContext("operation", operation).
		WithCause(cause).
		WithDetails(fmt.Sprintf("An unexpected error occurred during '%s'", operation))
}

// ErrNotImplemented creates a not implemented error
func ErrNotImplemented(feature string) *CIPGramError {
	return NewInternalError(CodeNotImplemented, "feature not implemented").
		WithContext("feature", feature).
		WithDetails(fmt.Sprintf("Feature '%s' is not yet implemented", feature))
}

// Helper functions for common checks

// CheckFileExists checks if a file exists and returns appropriate error
func CheckFileExists(filepath string) error {
	if filepath == "" {
		return ErrMissingRequiredField("filepath")
	}

	info, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrFileNotFound(filepath)
		}
		if os.IsPermission(err) {
			return ErrFilePermissionDenied(filepath)
		}
		return WrapSystem(err, CodeFileNotFound, "failed to access file").
			WithContext("filepath", filepath)
	}

	if info.IsDir() {
		return ErrInvalidInput("filepath", filepath, "expected file but got directory")
	}

	return nil
}

// CheckDirectoryExists checks if a directory exists and returns appropriate error
func CheckDirectoryExists(dirpath string) error {
	if dirpath == "" {
		return ErrMissingRequiredField("directory")
	}

	info, err := os.Stat(dirpath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewIOError(CodeFileNotFound, "directory not found").
				WithContext("directory", dirpath).
				WithDetails(fmt.Sprintf("Directory '%s' does not exist", dirpath))
		}
		if os.IsPermission(err) {
			return ErrFilePermissionDenied(dirpath)
		}
		return WrapSystem(err, CodeFileNotFound, "failed to access directory").
			WithContext("directory", dirpath)
	}

	if !info.IsDir() {
		return ErrInvalidInput("directory", dirpath, "expected directory but got file")
	}

	return nil
}

// CheckRequiredString checks if a string field is provided
func CheckRequiredString(fieldName string, value string) error {
	if value == "" {
		return ErrMissingRequiredField(fieldName)
	}
	return nil
}

// CheckRequiredField checks if a field is not nil
func CheckRequiredField(fieldName string, value interface{}) error {
	if value == nil {
		return ErrMissingRequiredField(fieldName)
	}
	return nil
}

// CheckRequiredPointer checks if a pointer field is not nil (for struct pointers)
func CheckRequiredPointer(fieldName string, value interface{}) error {
	if value == nil {
		return ErrMissingRequiredField(fieldName)
	}
	return nil
}
