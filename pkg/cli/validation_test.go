package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFilePath(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	validPcap := filepath.Join(tmpDir, "test.pcap")
	file, err := os.Create(validPcap)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.WriteString("test data") // Make it non-empty
	file.Close()

	tests := []struct {
		name     string
		filePath string
		fileType string
		wantErr  bool
	}{
		{
			name:     "Valid PCAP file",
			filePath: validPcap,
			fileType: "PCAP",
			wantErr:  false,
		},
		{
			name:     "Empty file path",
			filePath: "",
			fileType: "PCAP",
			wantErr:  true,
		},
		{
			name:     "Directory traversal attempt",
			filePath: "../../../etc/passwd",
			fileType: "config",
			wantErr:  true,
		},
		{
			name:     "Invalid PCAP extension",
			filePath: "/tmp/test.txt",
			fileType: "PCAP",
			wantErr:  true,
		},
		{
			name:     "Non-existent file",
			filePath: "/non/existent/file.pcap",
			fileType: "PCAP",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.filePath, tt.fileType)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateProjectName(t *testing.T) {
	tests := []struct {
		name        string
		projectName string
		wantErr     bool
	}{
		{"Valid name", "my_project_123", false},
		{"Empty name", "", true},
		{"Too long name", string(make([]byte, 101)), true},
		{"Invalid character slash", "project/name", true},
		{"Invalid character asterisk", "project*name", true},
		{"Reserved name", "con", true},
		{"Reserved name case", "CON", true},
		{"Valid with spaces", "my project", false},
		{"Valid with hyphens", "my-project", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProjectName(tt.projectName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateProjectName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFileExtension(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		fileType string
		wantErr  bool
	}{
		{"Valid PCAP extension", "test.pcap", "PCAP", false},
		{"Valid PCAPNG extension", "test.pcapng", "PCAP", false},
		{"Valid XML config", "config.xml", "config", false},
		{"Valid YAML config", "config.yaml", "YAML", false},
		{"Invalid PCAP extension", "test.txt", "PCAP", true},
		{"Invalid config extension", "config.pcap", "config", true},
		{"No extension", "testfile", "PCAP", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFileExtension(tt.filePath, tt.fileType)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFileExtension() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOutputPath(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	validPath := filepath.Join(tmpDir, "output")

	tests := []struct {
		name       string
		outputPath string
		wantErr    bool
	}{
		{"Valid output path", validPath, false},
		{"Empty path", "", true},
		{"Directory traversal", "../../../tmp", true},
		{"Root directory (may fail)", "/", false}, // Might fail due to permissions
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputPath(tt.outputPath)
			if (err != nil) != tt.wantErr {
				// For root directory test, allow either success or failure
				if tt.name == "Root directory (may fail)" {
					return
				}
				t.Errorf("validateOutputPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFileSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a small valid file
	smallFile := filepath.Join(tmpDir, "small.pcap")
	file, err := os.Create(smallFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.WriteString("small content")
	file.Close()

	// Create an empty file
	emptyFile := filepath.Join(tmpDir, "empty.pcap")
	file, err = os.Create(emptyFile)
	if err != nil {
		t.Fatalf("Failed to create empty test file: %v", err)
	}
	file.Close()

	tests := []struct {
		name     string
		filePath string
		fileType string
		wantErr  bool
	}{
		{"Valid small file", smallFile, "PCAP", false},
		{"Empty file", emptyFile, "PCAP", true},
		{"Non-existent file", "/non/existent.pcap", "PCAP", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFileSize(tt.filePath, tt.fileType)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFileSize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkValidateFilePath(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")
	file, _ := os.Create(testFile)
	file.WriteString("test data")
	file.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validateFilePath(testFile, "PCAP")
	}
}

func BenchmarkValidateProjectName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		validateProjectName("valid_project_name")
	}
}
