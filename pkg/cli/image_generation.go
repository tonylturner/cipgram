package cli

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
)

// generateImageEmbedded generates images from DOT files using system Graphviz
func (a *App) generateImageEmbedded(dotPath string) error {
	// Check if dot is available
	if _, err := exec.LookPath("dot"); err != nil {
		log.Printf("Warning: Graphviz 'dot' not found - skipping image generation")
		log.Printf("💡 Install Graphviz to generate PNG/SVG images: https://graphviz.org/download/")
		return nil // Don't return error, just skip
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

	// Generate images using dot command
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
			// High resolution PNG
			args = []string{"-T" + cmd.format, "-Gdpi=300", dotPath, "-o", cmd.output}
		} else {
			args = []string{"-T" + cmd.format, dotPath, "-o", cmd.output}
		}

		// Execute dot command
		if err := exec.Command("dot", args...).Run(); err != nil {
			log.Printf("Warning: Failed to generate %s: %v", cmd.output, err)
		} else {
			log.Printf("📸 Generated: %s", cmd.output)
		}
	}

	return nil
}

// checkGraphvizInstallation checks if Graphviz is available and provides helpful feedback
func checkGraphvizInstallation() {
	if _, err := exec.LookPath("dot"); err != nil {
		log.Printf("⚠️  Graphviz not found - diagrams will be generated as DOT files only")
		log.Printf("💡 To generate PNG/SVG images, install Graphviz:")
		log.Printf("   • macOS: brew install graphviz")
		log.Printf("   • Ubuntu/Debian: sudo apt install graphviz")
		log.Printf("   • Windows: Download from https://graphviz.org/download/")
		log.Printf("   • Or use online converter: https://dreampuf.github.io/GraphvizOnline/")
	} else {
		log.Printf("✅ Graphviz found - will generate PNG/SVG images")
	}
}
