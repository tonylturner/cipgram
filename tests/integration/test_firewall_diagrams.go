package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"cipgram/internal/parsers/opnsense"
	"cipgram/internal/writers"
)

func main() {
	configPath := "test_opnsense_config.xml"

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("Config file not found: %s", configPath)
	}

	fmt.Printf("🔧 **Firewall Diagram Generation Test**\n")
	fmt.Printf("═══════════════════════════════════════\n")

	// Parse OPNsense configuration
	parser := opnsense.NewOPNsenseParser(configPath)
	model, err := parser.Parse()
	if err != nil {
		log.Fatalf("Failed to parse OPNsense config: %v", err)
	}

	fmt.Printf("📊 Parsed: %d networks, %d policies\n", len(model.Networks), len(model.Policies))

	// Create output directory
	outputDir := "firewall_diagrams"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate firewall diagrams
	generator := writers.NewFirewallDiagramGenerator(model)

	// 1. Network Topology Diagram
	topologyPath := filepath.Join(outputDir, "network_topology.dot")
	fmt.Printf("🌐 Generating network topology diagram: %s\n", topologyPath)
	if err := generator.GenerateNetworkTopologyDiagram(topologyPath); err != nil {
		log.Printf("Warning: Failed to generate topology diagram: %v", err)
	} else {
		fmt.Printf("   ✓ Network topology diagram created\n")
		generateImage(topologyPath, "network_topology")
	}

	// 2. IEC 62443 Zone Diagram
	zonePath := filepath.Join(outputDir, "iec62443_zones.dot")
	fmt.Printf("🏭 Generating IEC 62443 zone diagram: %s\n", zonePath)
	if err := generator.GenerateIEC62443ZoneDiagram(zonePath); err != nil {
		log.Printf("Warning: Failed to generate zone diagram: %v", err)
	} else {
		fmt.Printf("   ✓ IEC 62443 zone diagram created\n")
		generateImage(zonePath, "iec62443_zones")
	}

	fmt.Printf("\n🎯 **Firewall Diagram Generation Complete!**\n")
	fmt.Printf("📁 Output directory: %s/\n", outputDir)
	fmt.Printf("🖼️  DOT files generated - use Graphviz to create images\n")
	fmt.Printf("💡 Example: dot -Tpng network_topology.dot -o network_topology.png\n")
}

// generateImage attempts to create PNG from DOT file using Graphviz
func generateImage(dotPath, baseName string) {
	outputDir := filepath.Dir(dotPath)
	pngPath := filepath.Join(outputDir, baseName+".png")

	// Try to generate PNG using dot command
	if err := exec.Command("dot", "-Tpng", dotPath, "-o", pngPath).Run(); err != nil {
		fmt.Printf("   ⚠️  Could not generate PNG (install Graphviz): %v\n", err)
	} else {
		fmt.Printf("   ✓ PNG image created: %s\n", pngPath)
	}
}
