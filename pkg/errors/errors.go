package errors

import (
	"fmt"
	"runtime"
)

// ErrorType represents the category of error
type ErrorType string

const (
	// User errors - caused by invalid user input or configuration
	ErrorTypeUser ErrorType = "USER"

	// System errors - caused by system/OS issues
	ErrorTypeSystem ErrorType = "SYSTEM"

	// Network errors - caused by network connectivity issues
	ErrorTypeNetwork ErrorType = "NETWORK"

	// Validation errors - caused by invalid data or configuration
	ErrorTypeValidation ErrorType = "VALIDATION"

	// Parse errors - caused by malformed input files or data
	ErrorTypeParse ErrorType = "PARSE"

	// IO errors - caused by file system operations
	ErrorTypeIO ErrorType = "IO"

	// Configuration errors - caused by invalid configuration
	ErrorTypeConfig ErrorType = "CONFIG"

	// Internal errors - caused by programming errors or unexpected conditions
	ErrorTypeInternal ErrorType = "INTERNAL"
)

// ErrorCode represents specific error codes for programmatic handling
type ErrorCode string

const (
	// User Error Codes
	CodeInvalidInput    ErrorCode = "E001"
	CodeMissingRequired ErrorCode = "E002"
	CodeInvalidFormat   ErrorCode = "E003"

	// System Error Codes
	CodeFileNotFound     ErrorCode = "E101"
	CodePermissionDenied ErrorCode = "E102"
	CodeDiskFull         ErrorCode = "E103"

	// Network Error Codes
	CodeConnectionFailed ErrorCode = "E201"
	CodeTimeout          ErrorCode = "E202"
	CodeDNSResolution    ErrorCode = "E203"

	// Validation Error Codes
	CodeInvalidCIDR     ErrorCode = "E301"
	CodeInvalidMAC      ErrorCode = "E302"
	CodeInvalidProtocol ErrorCode = "E303"
	CodeInvalidLevel    ErrorCode = "E304"

	// Parse Error Codes
	CodeMalformedPCAP     ErrorCode = "E401"
	CodeMalformedConfig   ErrorCode = "E402"
	CodeUnsupportedFormat ErrorCode = "E403"

	// IO Error Codes
	CodeReadFailed   ErrorCode = "E501"
	CodeWriteFailed  ErrorCode = "E502"
	CodeCreateFailed ErrorCode = "E503"

	// Configuration Error Codes
	CodeMissingConfig  ErrorCode = "E601"
	CodeInvalidConfig  ErrorCode = "E602"
	CodeConfigConflict ErrorCode = "E603"

	// Internal Error Codes
	CodeUnexpected      ErrorCode = "E901"
	CodeNotImplemented  ErrorCode = "E902"
	CodeAssertionFailed ErrorCode = "E903"
)

// CIPGramError represents a structured error with context
type CIPGramError struct {
	Type        ErrorType              `json:"type"`
	Code        ErrorCode              `json:"code"`
	Message     string                 `json:"message"`
	Details     string                 `json:"details,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Cause       error                  `json:"cause,omitempty"`
	File        string                 `json:"file,omitempty"`
	Line        int                    `json:"line,omitempty"`
	Function    string                 `json:"function,omitempty"`
	Recoverable bool                   `json:"recoverable"`
}

// Error implements the error interface
func (e *CIPGramError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s:%s] %s: %s", e.Type, e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Code, e.Message)
}

// Unwrap returns the underlying cause error for error wrapping
func (e *CIPGramError) Unwrap() error {
	return e.Cause
}

// Is implements error comparison for errors.Is
func (e *CIPGramError) Is(target error) bool {
	if t, ok := target.(*CIPGramError); ok {
		return e.Code == t.Code && e.Type == t.Type
	}
	return false
}

// WithContext adds context information to the error
func (e *CIPGramError) WithContext(key string, value interface{}) *CIPGramError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithDetails adds detailed information to the error
func (e *CIPGramError) WithDetails(details string) *CIPGramError {
	e.Details = details
	return e
}

// WithCause wraps another error as the cause
func (e *CIPGramError) WithCause(cause error) *CIPGramError {
	e.Cause = cause
	return e
}

// IsRecoverable returns whether the error is recoverable
func (e *CIPGramError) IsRecoverable() bool {
	return e.Recoverable
}

// GetType returns the error type
func (e *CIPGramError) GetType() ErrorType {
	return e.Type
}

// GetCode returns the error code
func (e *CIPGramError) GetCode() ErrorCode {
	return e.Code
}

// GetContext returns the error context
func (e *CIPGramError) GetContext() map[string]interface{} {
	return e.Context
}

// NewError creates a new CIPGramError with caller information
func NewError(errorType ErrorType, code ErrorCode, message string) *CIPGramError {
	err := &CIPGramError{
		Type:        errorType,
		Code:        code,
		Message:     message,
		Context:     make(map[string]interface{}),
		Recoverable: isRecoverableByDefault(errorType),
	}

	// Capture caller information
	if pc, file, line, ok := runtime.Caller(1); ok {
		err.File = file
		err.Line = line
		if fn := runtime.FuncForPC(pc); fn != nil {
			err.Function = fn.Name()
		}
	}

	return err
}

// isRecoverableByDefault determines if an error type is recoverable by default
func isRecoverableByDefault(errorType ErrorType) bool {
	switch errorType {
	case ErrorTypeUser, ErrorTypeValidation, ErrorTypeConfig:
		return true // User can fix these
	case ErrorTypeNetwork:
		return true // Network issues might be temporary
	case ErrorTypeSystem, ErrorTypeIO:
		return false // System issues usually require intervention
	case ErrorTypeParse:
		return false // Parse errors indicate bad input
	case ErrorTypeInternal:
		return false // Internal errors indicate bugs
	default:
		return false
	}
}

// Convenience functions for common error types

// NewUserError creates a new user error
func NewUserError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeUser, code, message)
}

// NewSystemError creates a new system error
func NewSystemError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeSystem, code, message)
}

// NewNetworkError creates a new network error
func NewNetworkError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeNetwork, code, message)
}

// NewValidationError creates a new validation error
func NewValidationError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeValidation, code, message)
}

// NewParseError creates a new parse error
func NewParseError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeParse, code, message)
}

// NewIOError creates a new IO error
func NewIOError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeIO, code, message)
}

// NewConfigError creates a new configuration error
func NewConfigError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeConfig, code, message)
}

// NewInternalError creates a new internal error
func NewInternalError(code ErrorCode, message string) *CIPGramError {
	return NewError(ErrorTypeInternal, code, message)
}

// Wrap wraps an existing error with CIPGram error context
func Wrap(err error, errorType ErrorType, code ErrorCode, message string) *CIPGramError {
	cipErr := NewError(errorType, code, message)
	cipErr.Cause = err
	return cipErr
}

// WrapUser wraps an error as a user error
func WrapUser(err error, code ErrorCode, message string) *CIPGramError {
	return Wrap(err, ErrorTypeUser, code, message)
}

// WrapSystem wraps an error as a system error
func WrapSystem(err error, code ErrorCode, message string) *CIPGramError {
	return Wrap(err, ErrorTypeSystem, code, message)
}

// WrapValidation wraps an error as a validation error
func WrapValidation(err error, code ErrorCode, message string) *CIPGramError {
	return Wrap(err, ErrorTypeValidation, code, message)
}

// WrapParse wraps an error as a parse error
func WrapParse(err error, code ErrorCode, message string) *CIPGramError {
	return Wrap(err, ErrorTypeParse, code, message)
}

// WrapIO wraps an error as an IO error
func WrapIO(err error, code ErrorCode, message string) *CIPGramError {
	return Wrap(err, ErrorTypeIO, code, message)
}

// Helper functions for error checking

// IsUserError checks if an error is a user error
func IsUserError(err error) bool {
	if cipErr, ok := err.(*CIPGramError); ok {
		return cipErr.Type == ErrorTypeUser
	}
	return false
}

// IsSystemError checks if an error is a system error
func IsSystemError(err error) bool {
	if cipErr, ok := err.(*CIPGramError); ok {
		return cipErr.Type == ErrorTypeSystem
	}
	return false
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	if cipErr, ok := err.(*CIPGramError); ok {
		return cipErr.Type == ErrorTypeValidation
	}
	return false
}

// IsRecoverable checks if an error is recoverable
func IsRecoverable(err error) bool {
	if cipErr, ok := err.(*CIPGramError); ok {
		return cipErr.Recoverable
	}
	return false
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) ErrorCode {
	if cipErr, ok := err.(*CIPGramError); ok {
		return cipErr.Code
	}
	return ""
}

// GetErrorType extracts the error type from an error
func GetErrorType(err error) ErrorType {
	if cipErr, ok := err.(*CIPGramError); ok {
		return cipErr.Type
	}
	return ""
}
