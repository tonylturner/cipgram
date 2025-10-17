package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateFilePath performs comprehensive security validation on file paths
func validateFilePath(filePath, fileType string) error {
	if filePath == "" {
		return fmt.Errorf("%s file path cannot be empty", fileType)
	}

	// Convert to absolute path for consistent validation
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("invalid %s file path: %v", fileType, err)
	}

	// Check for directory traversal attempts
	cleanPath := filepath.Clean(filePath)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("directory traversal detected in %s file path: %s", fileType, filePath)
	}

	// Validate file extension based on type
	if err := validateFileExtension(absPath, fileType); err != nil {
		return err
	}

	// Check if file exists and is readable
	if err := validateFileAccess(absPath, fileType); err != nil {
		return err
	}

	// Check file size is reasonable (prevent resource exhaustion)
	if err := validateFileSize(absPath, fileType); err != nil {
		return err
	}

	return nil
}

// validateFileExtension ensures files have expected extensions
func validateFileExtension(filePath, fileType string) error {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch fileType {
	case "PCAP":
		validExts := []string{".pcap", ".pcapng", ".cap"}
		if !contains(validExts, ext) {
			return fmt.Errorf("invalid PCAP file extension: %s (expected: %v)", ext, validExts)
		}
	case "config":
		validExts := []string{".xml", ".conf", ".cfg", ".config"}
		if !contains(validExts, ext) {
			return fmt.Errorf("invalid config file extension: %s (expected: %v)", ext, validExts)
		}
	case "YAML":
		validExts := []string{".yaml", ".yml"}
		if !contains(validExts, ext) {
			return fmt.Errorf("invalid YAML file extension: %s (expected: %v)", ext, validExts)
		}
	}

	return nil
}

// validateFileAccess checks if file exists and is readable
func validateFileAccess(filePath, fileType string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s file not found: %s", fileType, filePath)
		}
		return fmt.Errorf("cannot access %s file: %s (%v)", fileType, filePath, err)
	}

	// Check if it's a regular file (not directory or device)
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s path is not a regular file: %s", fileType, filePath)
	}

	// Check file permissions (must be readable)
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("%s file is not readable: %s (%v)", fileType, filePath, err)
	}
	file.Close()

	return nil
}

// validateFileSize ensures file size is reasonable
func validateFileSize(filePath, fileType string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err // Already handled in validateFileAccess
	}

	size := info.Size()

	// Set reasonable limits based on file type
	var maxSize int64
	switch fileType {
	case "PCAP":
		maxSize = 10 * 1024 * 1024 * 1024 // 10GB for PCAP files
	case "config":
		maxSize = 100 * 1024 * 1024 // 100MB for config files
	case "YAML":
		maxSize = 10 * 1024 * 1024 // 10MB for YAML files
	default:
		maxSize = 100 * 1024 * 1024 // 100MB default
	}

	if size > maxSize {
		return fmt.Errorf("%s file too large: %d bytes (max: %d bytes)",
			fileType, size, maxSize)
	}

	if size == 0 {
		return fmt.Errorf("%s file is empty: %s", fileType, filePath)
	}

	return nil
}

// validateOutputPath ensures output directories are safe
func validateOutputPath(outputPath string) error {
	if outputPath == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("invalid output path: %v", err)
	}

	// Check for directory traversal
	cleanPath := filepath.Clean(outputPath)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("directory traversal detected in output path: %s", outputPath)
	}

	// Ensure we can create/write to the directory
	parentDir := filepath.Dir(absPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("cannot create output directory: %s (%v)", parentDir, err)
	}

	// Test write permissions
	testFile := filepath.Join(parentDir, ".cipgram_write_test")
	file, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("no write permission in output directory: %s", parentDir)
	}
	file.Close()
	os.Remove(testFile) // Clean up test file

	return nil
}

// validateProjectName ensures project names are safe for filesystem
func validateProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("project name cannot be empty")
	}

	// Check length
	if len(name) > 100 {
		return fmt.Errorf("project name too long (max 100 characters): %s", name)
	}

	// Check for invalid characters in filesystem names
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "\n", "\r", "\t"}
	for _, char := range invalidChars {
		if strings.Contains(name, char) {
			return fmt.Errorf("project name contains invalid character '%s': %s", char, name)
		}
	}

	// Check for reserved names (Windows/Unix)
	reservedNames := []string{".", "..", "con", "prn", "aux", "nul",
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"}

	lowerName := strings.ToLower(name)
	for _, reserved := range reservedNames {
		if lowerName == reserved {
			return fmt.Errorf("project name is reserved: %s", name)
		}
	}

	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
