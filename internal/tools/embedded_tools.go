package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Embed external tools for self-contained operation
// Note: These will be added to make the project completely self-contained

// TODO: Add actual binaries here
// //go:embed assets/tools/dot-darwin
// var dotDarwin []byte

// //go:embed assets/tools/dot-linux
// var dotLinux []byte

// //go:embed assets/tools/dot.exe
// var dotWindows []byte

// getEmbeddedDotPath extracts the appropriate dot binary and returns its path
func getEmbeddedDotPath() (string, error) {
	// For now, use system dot if available, but this will be replaced with embedded version
	if path, err := exec.LookPath("dot"); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("dot binary not found - will be embedded in future version")
}

// ConvertSVGToPNGEmbedded converts SVG to PNG using embedded tools
func ConvertSVGToPNGEmbedded(svgPath, pngPath string) error {
	// Try embedded rsvg-convert first (will be implemented)
	// For now, fall back to system tools
	return fmt.Errorf("convertSVGToPNG not implemented in this package - use pkg/diagram instead")
}

// generateImageEmbedded generates images using embedded Graphviz
func generateImageEmbedded(dotPath string) error {
	dotBinary, err := getEmbeddedDotPath()
	if err != nil {
		return fmt.Errorf("embedded dot not available: %v", err)
	}

	if dotPath == "" {
		return fmt.Errorf("empty DOT path")
	}

	dir := filepath.Dir(dotPath)
	base := strings.TrimSuffix(filepath.Base(dotPath), ".dot")

	// Generate PNG
	pngPath := filepath.Join(dir, base+".png")
	// Generate SVG
	svgPath := filepath.Join(dir, base+".svg")
	// Generate high-res PNG
	hiresPngPath := filepath.Join(dir, base+"_hires.png")

	// Use embedded dot binary
	commands := []struct {
		format string
		output string
	}{
		{"png", pngPath},
		{"svg", svgPath},
		{"png", hiresPngPath},
	}

	for _, cmd := range commands {
		var args []string
		if cmd.output == hiresPngPath {
			args = []string{"-T" + cmd.format, "-Gdpi=300", dotPath, "-o", cmd.output}
		} else {
			args = []string{"-T" + cmd.format, dotPath, "-o", cmd.output}
		}

		if err := exec.Command(dotBinary, args...).Run(); err != nil {
			return fmt.Errorf("failed to generate %s: %v", cmd.output, err)
		} else {
			fmt.Printf("Generated: %s\n", cmd.output)
		}
	}

	return nil
}

// extractEmbeddedBinary extracts an embedded binary to a temporary location
func extractEmbeddedBinary(data []byte, name string) (string, error) {
	tempDir, err := os.MkdirTemp("", "cipgram-tools")
	if err != nil {
		return "", err
	}

	binaryPath := filepath.Join(tempDir, name)
	err = os.WriteFile(binaryPath, data, 0755)
	if err != nil {
		return "", err
	}

	return binaryPath, nil
}

// getEmbeddedBinary returns the appropriate binary for the current platform
func getEmbeddedBinary() ([]byte, string, error) {
	switch runtime.GOOS {
	case "darwin":
		// return dotDarwin, "dot-darwin", nil
		return nil, "", fmt.Errorf("darwin binary not embedded yet")
	case "linux":
		// return dotLinux, "dot-linux", nil
		return nil, "", fmt.Errorf("linux binary not embedded yet")
	case "windows":
		// return dotWindows, "dot.exe", nil
		return nil, "", fmt.Errorf("windows binary not embedded yet")
	default:
		return nil, "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
