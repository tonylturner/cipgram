package errors_test

import (
	"errors"
	"testing"

	ciperrors "cipgram/pkg/errors"
)

func TestNewError(t *testing.T) {
	err := ciperrors.NewError(ciperrors.ErrorTypeUser, ciperrors.CodeInvalidInput, "test message")

	if err.GetType() != ciperrors.ErrorTypeUser {
		t.Errorf("Expected type %s, got %s", ciperrors.ErrorTypeUser, err.GetType())
	}

	if err.GetCode() != ciperrors.CodeInvalidInput {
		t.Errorf("Expected code %s, got %s", ciperrors.CodeInvalidInput, err.GetCode())
	}

	if err.Error() != "[USER:E001] test message" {
		t.Errorf("Unexpected error string: %s", err.Error())
	}

	// Check that caller information is captured
	if err.File == "" || err.Line == 0 {
		t.Error("Caller information not captured")
	}
}

func TestErrorWithDetails(t *testing.T) {
	err := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "test message").
		WithDetails("additional details")

	expected := "[USER:E001] test message: additional details"
	if err.Error() != expected {
		t.Errorf("Expected %s, got %s", expected, err.Error())
	}
}

func TestErrorWithContext(t *testing.T) {
	err := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "test message").
		WithContext("file", "test.pcap").
		WithContext("line", 42)

	context := err.GetContext()
	if context["file"] != "test.pcap" {
		t.Errorf("Expected file context 'test.pcap', got %v", context["file"])
	}

	if context["line"] != 42 {
		t.Errorf("Expected line context 42, got %v", context["line"])
	}
}

func TestErrorWithCause(t *testing.T) {
	originalErr := errors.New("original error")
	err := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "wrapped error").
		WithCause(originalErr)

	if err.Unwrap() != originalErr {
		t.Error("Cause not properly wrapped")
	}
}

func TestConvenienceConstructors(t *testing.T) {
	testCases := []struct {
		name         string
		constructor  func() *ciperrors.CIPGramError
		expectedType ciperrors.ErrorType
	}{
		{"UserError", func() *ciperrors.CIPGramError { return ciperrors.NewUserError(ciperrors.CodeInvalidInput, "test") }, ciperrors.ErrorTypeUser},
		{"SystemError", func() *ciperrors.CIPGramError { return ciperrors.NewSystemError(ciperrors.CodeFileNotFound, "test") }, ciperrors.ErrorTypeSystem},
		{"NetworkError", func() *ciperrors.CIPGramError {
			return ciperrors.NewNetworkError(ciperrors.CodeConnectionFailed, "test")
		}, ciperrors.ErrorTypeNetwork},
		{"ValidationError", func() *ciperrors.CIPGramError { return ciperrors.NewValidationError(ciperrors.CodeInvalidCIDR, "test") }, ciperrors.ErrorTypeValidation},
		{"ParseError", func() *ciperrors.CIPGramError { return ciperrors.NewParseError(ciperrors.CodeMalformedPCAP, "test") }, ciperrors.ErrorTypeParse},
		{"IOError", func() *ciperrors.CIPGramError { return ciperrors.NewIOError(ciperrors.CodeReadFailed, "test") }, ciperrors.ErrorTypeIO},
		{"ConfigError", func() *ciperrors.CIPGramError { return ciperrors.NewConfigError(ciperrors.CodeMissingConfig, "test") }, ciperrors.ErrorTypeConfig},
		{"InternalError", func() *ciperrors.CIPGramError { return ciperrors.NewInternalError(ciperrors.CodeUnexpected, "test") }, ciperrors.ErrorTypeInternal},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.constructor()
			if err.GetType() != tc.expectedType {
				t.Errorf("Expected type %s, got %s", tc.expectedType, err.GetType())
			}
		})
	}
}

func TestWrapFunctions(t *testing.T) {
	originalErr := errors.New("original error")

	testCases := []struct {
		name         string
		wrapper      func() *ciperrors.CIPGramError
		expectedType ciperrors.ErrorType
	}{
		{"WrapUser", func() *ciperrors.CIPGramError {
			return ciperrors.WrapUser(originalErr, ciperrors.CodeInvalidInput, "wrapped")
		}, ciperrors.ErrorTypeUser},
		{"WrapSystem", func() *ciperrors.CIPGramError {
			return ciperrors.WrapSystem(originalErr, ciperrors.CodeFileNotFound, "wrapped")
		}, ciperrors.ErrorTypeSystem},
		{"WrapValidation", func() *ciperrors.CIPGramError {
			return ciperrors.WrapValidation(originalErr, ciperrors.CodeInvalidCIDR, "wrapped")
		}, ciperrors.ErrorTypeValidation},
		{"WrapParse", func() *ciperrors.CIPGramError {
			return ciperrors.WrapParse(originalErr, ciperrors.CodeMalformedPCAP, "wrapped")
		}, ciperrors.ErrorTypeParse},
		{"WrapIO", func() *ciperrors.CIPGramError {
			return ciperrors.WrapIO(originalErr, ciperrors.CodeReadFailed, "wrapped")
		}, ciperrors.ErrorTypeIO},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.wrapper()
			if err.GetType() != tc.expectedType {
				t.Errorf("Expected type %s, got %s", tc.expectedType, err.GetType())
			}
			if err.Unwrap() != originalErr {
				t.Error("Original error not properly wrapped")
			}
		})
	}
}

func TestErrorTypeCheckers(t *testing.T) {
	userErr := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "user error")
	systemErr := ciperrors.NewSystemError(ciperrors.CodeFileNotFound, "system error")
	validationErr := ciperrors.NewValidationError(ciperrors.CodeInvalidCIDR, "validation error")
	regularErr := errors.New("regular error")

	// Test IsUserError
	if !ciperrors.IsUserError(userErr) {
		t.Error("IsUserError should return true for user error")
	}
	if ciperrors.IsUserError(systemErr) {
		t.Error("IsUserError should return false for system error")
	}
	if ciperrors.IsUserError(regularErr) {
		t.Error("IsUserError should return false for regular error")
	}

	// Test IsSystemError
	if !ciperrors.IsSystemError(systemErr) {
		t.Error("IsSystemError should return true for system error")
	}
	if ciperrors.IsSystemError(userErr) {
		t.Error("IsSystemError should return false for user error")
	}

	// Test IsValidationError
	if !ciperrors.IsValidationError(validationErr) {
		t.Error("IsValidationError should return true for validation error")
	}
	if ciperrors.IsValidationError(userErr) {
		t.Error("IsValidationError should return false for user error")
	}
}

func TestRecoverability(t *testing.T) {
	// Recoverable by default
	userErr := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "user error")
	networkErr := ciperrors.NewNetworkError(ciperrors.CodeConnectionFailed, "network error")
	validationErr := ciperrors.NewValidationError(ciperrors.CodeInvalidCIDR, "validation error")
	configErr := ciperrors.NewConfigError(ciperrors.CodeMissingConfig, "config error")

	// Not recoverable by default
	systemErr := ciperrors.NewSystemError(ciperrors.CodeFileNotFound, "system error")
	parseErr := ciperrors.NewParseError(ciperrors.CodeMalformedPCAP, "parse error")
	internalErr := ciperrors.NewInternalError(ciperrors.CodeUnexpected, "internal error")
	ioErr := ciperrors.NewIOError(ciperrors.CodeReadFailed, "io error")

	recoverableErrors := []*ciperrors.CIPGramError{userErr, networkErr, validationErr, configErr}
	nonRecoverableErrors := []*ciperrors.CIPGramError{systemErr, parseErr, internalErr, ioErr}

	for _, err := range recoverableErrors {
		if !err.IsRecoverable() {
			t.Errorf("Error %s should be recoverable", err.GetType())
		}
		if !ciperrors.IsRecoverable(err) {
			t.Errorf("IsRecoverable should return true for %s", err.GetType())
		}
	}

	for _, err := range nonRecoverableErrors {
		if err.IsRecoverable() {
			t.Errorf("Error %s should not be recoverable", err.GetType())
		}
		if ciperrors.IsRecoverable(err) {
			t.Errorf("IsRecoverable should return false for %s", err.GetType())
		}
	}
}

func TestErrorIs(t *testing.T) {
	err1 := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "error 1")
	err2 := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "error 2")
	err3 := ciperrors.NewUserError(ciperrors.CodeMissingRequired, "error 3")

	if !errors.Is(err1, err2) {
		t.Error("Errors with same type and code should be equal")
	}

	if errors.Is(err1, err3) {
		t.Error("Errors with different codes should not be equal")
	}
}

func TestGetErrorInfo(t *testing.T) {
	err := ciperrors.NewUserError(ciperrors.CodeInvalidInput, "test error")

	if ciperrors.GetErrorCode(err) != ciperrors.CodeInvalidInput {
		t.Errorf("Expected code %s, got %s", ciperrors.CodeInvalidInput, ciperrors.GetErrorCode(err))
	}

	if ciperrors.GetErrorType(err) != ciperrors.ErrorTypeUser {
		t.Errorf("Expected type %s, got %s", ciperrors.ErrorTypeUser, ciperrors.GetErrorType(err))
	}

	// Test with regular error
	regularErr := errors.New("regular error")
	if ciperrors.GetErrorCode(regularErr) != "" {
		t.Error("GetErrorCode should return empty string for regular error")
	}

	if ciperrors.GetErrorType(regularErr) != "" {
		t.Error("GetErrorType should return empty string for regular error")
	}
}

func TestErrorCodes(t *testing.T) {
	// Test that all error codes are unique and follow the pattern
	codes := []ciperrors.ErrorCode{
		ciperrors.CodeInvalidInput,
		ciperrors.CodeMissingRequired,
		ciperrors.CodeInvalidFormat,
		ciperrors.CodeFileNotFound,
		ciperrors.CodePermissionDenied,
		ciperrors.CodeDiskFull,
		ciperrors.CodeConnectionFailed,
		ciperrors.CodeTimeout,
		ciperrors.CodeDNSResolution,
		ciperrors.CodeInvalidCIDR,
		ciperrors.CodeInvalidMAC,
		ciperrors.CodeInvalidProtocol,
		ciperrors.CodeInvalidLevel,
		ciperrors.CodeMalformedPCAP,
		ciperrors.CodeMalformedConfig,
		ciperrors.CodeUnsupportedFormat,
		ciperrors.CodeReadFailed,
		ciperrors.CodeWriteFailed,
		ciperrors.CodeCreateFailed,
		ciperrors.CodeMissingConfig,
		ciperrors.CodeInvalidConfig,
		ciperrors.CodeConfigConflict,
		ciperrors.CodeUnexpected,
		ciperrors.CodeNotImplemented,
		ciperrors.CodeAssertionFailed,
	}

	seen := make(map[ciperrors.ErrorCode]bool)
	for _, code := range codes {
		if seen[code] {
			t.Errorf("Duplicate error code: %s", code)
		}
		seen[code] = true

		// Check format (should be E followed by 3 digits)
		if len(string(code)) != 4 || string(code)[0] != 'E' {
			t.Errorf("Invalid error code format: %s", code)
		}
	}
}
