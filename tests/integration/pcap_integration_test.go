package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPCAPIntegration tests the main PCAP processing functionality
func TestPCAPIntegration(t *testing.T) {
	// Build the binary first
	if err := buildCIPgram(); err != nil {
		t.Fatalf("Failed to build cipgram: %v", err)
	}

	// Test cases for different PCAP files
	testCases := []struct {
		name     string
		pcapFile string
		args     []string
		expected []string // Expected output files
	}{
		{
			name:     "Cyberville PCAP - Basic Analysis",
			pcapFile: "../../pcaps/Cyberville.pcap",
			args:     []string{},
			expected: []string{
				"firewall_analysis/network_topology.dot",
				"firewall_analysis/network_topology.png",
				"firewall_analysis/network_topology.svg",
				"iec62443_diagrams/iec62443_zones.dot",
				"iec62443_diagrams/iec62443_zones.png",
				"iec62443_diagrams/iec62443_zones.svg",
				"data/network_model.json",
			},
		},
		{
			name:     "EtherNet/IP PCAP - Protocol Analysis",
			pcapFile: "../../pcaps/ENIP.pcap",
			args:     []string{},
			expected: []string{
				"firewall_analysis/network_topology.dot",
				"firewall_analysis/network_topology.png",
				"iec62443_diagrams/iec62443_zones.dot",
				"iec62443_diagrams/iec62443_zones.png",
				"data/network_model.json",
			},
		},
		{
			name:     "PROFINET PCAP - Industrial Protocol",
			pcapFile: "../../pcaps/PROFINET.pcap",
			args:     []string{},
			expected: []string{
				"firewall_analysis/network_topology.dot",
				"iec62443_diagrams/iec62443_zones.dot",
				"data/network_model.json",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Check if PCAP file exists
			if !fileExists(tc.pcapFile) {
				t.Skipf("PCAP file not found: %s", tc.pcapFile)
			}

			// Create temporary output directory
			outputDir := createTempOutputDir(t, tc.name)
			defer cleanupOutputDir(outputDir)

			// Run cipgram with the PCAP file
			args := []string{"-pcap", tc.pcapFile, "-project", filepath.Base(outputDir)}
			args = append(args, tc.args...)

			if err := runCIPgram(args...); err != nil {
				t.Fatalf("Failed to run cipgram: %v", err)
			}

			// Verify expected output files exist
			for _, expectedFile := range tc.expected {
				fullPath := filepath.Join("output", filepath.Base(outputDir), expectedFile)
				if !fileExists(fullPath) {
					t.Errorf("Expected output file not found: %s", fullPath)
				} else {
					t.Logf("✓ Found expected file: %s", expectedFile)
				}
			}

			// Verify diagram content
			verifyDiagramContent(t, outputDir, tc.name)
		})
	}
}

// TestConfigurationOptions tests different configuration options
func TestConfigurationOptions(t *testing.T) {
	if err := buildCIPgram(); err != nil {
		t.Fatalf("Failed to build cipgram: %v", err)
	}

	pcapFile := "../../pcaps/Cyberville.pcap"
	if !fileExists(pcapFile) {
		t.Skip("Cyberville.pcap not found, skipping configuration tests")
	}

	testCases := []struct {
		name        string
		configFile  string
		args        []string
		expectFiles []string
	}{
		{
			name:       "With Purdue Config",
			configFile: "../../configs/purdue_config.yaml",
			args:       []string{},
			expectFiles: []string{
				"iec62443_diagrams/iec62443_zones.dot",
				"firewall_analysis/network_topology.dot",
			},
		},
		{
			name: "Network Diagram Only",
			args: []string{"-diagram", "network"},
			expectFiles: []string{
				"firewall_analysis/network_topology.dot",
			},
		},
		{
			name: "IEC62443 Diagram Only",
			args: []string{"-diagram", "iec62443"},
			expectFiles: []string{
				"iec62443_diagrams/iec62443_zones.dot",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputDir := createTempOutputDir(t, tc.name)
			defer cleanupOutputDir(outputDir)

			args := []string{"-pcap", pcapFile, "-project", filepath.Base(outputDir)}

			if tc.configFile != "" && fileExists(tc.configFile) {
				args = append(args, "-config", tc.configFile)
			}

			args = append(args, tc.args...)

			if err := runCIPgram(args...); err != nil {
				t.Fatalf("Failed to run cipgram: %v", err)
			}

			// Verify expected files
			for _, expectedFile := range tc.expectFiles {
				fullPath := filepath.Join("output", filepath.Base(outputDir), expectedFile)
				if !fileExists(fullPath) {
					t.Errorf("Expected file not found: %s", fullPath)
				} else {
					t.Logf("✓ Found expected file: %s", expectedFile)
				}
			}
		})
	}
}

// TestDiagramGeneration specifically tests diagram generation quality
func TestDiagramGeneration(t *testing.T) {
	if err := buildCIPgram(); err != nil {
		t.Fatalf("Failed to build cipgram: %v", err)
	}

	pcapFile := "../../pcaps/Cyberville.pcap"
	if !fileExists(pcapFile) {
		t.Skip("Cyberville.pcap not found, skipping diagram tests")
	}

	outputDir := createTempOutputDir(t, "DiagramGeneration")
	defer cleanupOutputDir(outputDir)

	// Run cipgram to generate diagrams
	args := []string{"-pcap", pcapFile, "-project", filepath.Base(outputDir)}
	if err := runCIPgram(args...); err != nil {
		t.Fatalf("Failed to run cipgram: %v", err)
	}

	// Test network topology diagram
	t.Run("Network Topology Diagram", func(t *testing.T) {
		dotFile := filepath.Join("output", filepath.Base(outputDir), "firewall_analysis", "network_topology.dot")
		if !fileExists(dotFile) {
			t.Fatal("Network topology DOT file not generated")
		}

		content, err := os.ReadFile(dotFile)
		if err != nil {
			t.Fatalf("Failed to read DOT file: %v", err)
		}

		dotContent := string(content)

		// Verify DOT file structure
		if !strings.Contains(dotContent, "digraph") {
			t.Error("DOT file should contain 'digraph' declaration")
		}

		// Verify it contains network elements
		expectedElements := []string{"node", "edge", "->"}
		for _, element := range expectedElements {
			if !strings.Contains(dotContent, element) {
				t.Errorf("DOT file should contain '%s'", element)
			}
		}

		t.Logf("✓ Network topology DOT file is valid (%d bytes)", len(content))
	})

	// Test IEC62443 zones diagram
	t.Run("IEC62443 Zones Diagram", func(t *testing.T) {
		dotFile := filepath.Join("output", filepath.Base(outputDir), "iec62443_diagrams", "iec62443_zones.dot")
		if !fileExists(dotFile) {
			t.Fatal("IEC62443 zones DOT file not generated")
		}

		content, err := os.ReadFile(dotFile)
		if err != nil {
			t.Fatalf("Failed to read DOT file: %v", err)
		}

		dotContent := string(content)

		// Verify DOT file structure
		if !strings.Contains(dotContent, "digraph") {
			t.Error("DOT file should contain 'digraph' declaration")
		}

		t.Logf("✓ IEC62443 zones DOT file is valid (%d bytes)", len(content))
	})

	// Test image generation
	t.Run("Image Generation", func(t *testing.T) {
		imageFiles := []string{
			"firewall_analysis/network_topology.png",
			"firewall_analysis/network_topology.svg",
			"iec62443_diagrams/iec62443_zones.png",
			"iec62443_diagrams/iec62443_zones.svg",
		}

		for _, imageFile := range imageFiles {
			fullPath := filepath.Join("output", filepath.Base(outputDir), imageFile)
			if fileExists(fullPath) {
				stat, err := os.Stat(fullPath)
				if err != nil {
					t.Errorf("Failed to stat image file %s: %v", imageFile, err)
				} else if stat.Size() == 0 {
					t.Errorf("Image file %s is empty", imageFile)
				} else {
					t.Logf("✓ Generated image: %s (%d bytes)", imageFile, stat.Size())
				}
			} else {
				t.Logf("⚠ Image file not generated (may be skipped): %s", imageFile)
			}
		}
	})
}

// TestOutputStructure verifies the output directory structure
func TestOutputStructure(t *testing.T) {
	if err := buildCIPgram(); err != nil {
		t.Fatalf("Failed to build cipgram: %v", err)
	}

	pcapFile := "../../pcaps/ENIP.pcap"
	if !fileExists(pcapFile) {
		t.Skip("ENIP.pcap not found, skipping output structure test")
	}

	outputDir := createTempOutputDir(t, "OutputStructure")
	defer cleanupOutputDir(outputDir)

	// Run cipgram
	args := []string{"-pcap", pcapFile, "-project", filepath.Base(outputDir)}
	if err := runCIPgram(args...); err != nil {
		t.Fatalf("Failed to run cipgram: %v", err)
	}

	// Verify directory structure
	expectedDirs := []string{
		"output/" + filepath.Base(outputDir),
		"output/" + filepath.Base(outputDir) + "/firewall_analysis",
		"output/" + filepath.Base(outputDir) + "/iec62443_diagrams",
		"output/" + filepath.Base(outputDir) + "/data",
	}

	for _, dir := range expectedDirs {
		if !dirExists(dir) {
			t.Errorf("Expected directory not found: %s", dir)
		} else {
			t.Logf("✓ Found expected directory: %s", dir)
		}
	}

	// Verify data files
	dataFile := filepath.Join("output", filepath.Base(outputDir), "data", "network_model.json")
	if fileExists(dataFile) {
		stat, err := os.Stat(dataFile)
		if err != nil {
			t.Errorf("Failed to stat data file: %v", err)
		} else if stat.Size() == 0 {
			t.Error("Network model JSON file is empty")
		} else {
			t.Logf("✓ Generated network model JSON: %d bytes", stat.Size())
		}
	}
}

// Helper functions

func buildCIPgram() error {
	cmd := exec.Command("go", "build", "-o", "cipgram", "cmd/cipgram/main.go")
	cmd.Dir = "../.."
	return cmd.Run()
}

func runCIPgram(args ...string) error {
	cmd := exec.Command("./cipgram", args...)
	cmd.Dir = "../.."
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dirExists(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.IsDir()
}

func createTempOutputDir(t *testing.T, testName string) string {
	// Create a unique directory name
	timestamp := time.Now().Format("20060102_150405")
	dirName := fmt.Sprintf("test_%s_%s", strings.ReplaceAll(testName, " ", "_"), timestamp)
	return dirName
}

func cleanupOutputDir(dirName string) {
	outputPath := filepath.Join("../../output", dirName)
	os.RemoveAll(outputPath)
}

func verifyDiagramContent(t *testing.T, outputDir, testName string) {
	// Check if network topology diagram contains expected content
	dotFile := filepath.Join("../../output", outputDir, "firewall_analysis", "network_topology.dot")
	if fileExists(dotFile) {
		content, err := os.ReadFile(dotFile)
		if err != nil {
			t.Errorf("Failed to read network topology DOT file: %v", err)
			return
		}

		dotContent := string(content)
		if len(dotContent) < 100 {
			t.Errorf("Network topology diagram seems too small (%d bytes)", len(content))
		}

		// Basic validation
		if !strings.Contains(dotContent, "digraph") {
			t.Error("Network topology DOT file should contain 'digraph'")
		}

		t.Logf("✓ Network topology diagram validated for %s", testName)
	}
}
