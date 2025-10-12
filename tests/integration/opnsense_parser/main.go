package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"cipgram/pkg/firewall/parsers/opnsense"
)

func main() {
	testOPNsenseParser()
}

// testOPNsenseParser demonstrates the OPNsense parser with a real config file
func testOPNsenseParser() {
	configPath := "test_opnsense_config.xml"

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("Config file not found: %s", configPath)
	}

	// Create and run parser
	parser := opnsense.NewOPNsenseParser(configPath)

	fmt.Printf("🔧 Parsing OPNsense configuration: %s\n", configPath)

	model, err := parser.Parse()
	if err != nil {
		log.Fatalf("Failed to parse OPNsense config: %v", err)
	}

	// Display results
	fmt.Printf("\n📊 **OPNsense Analysis Results**\n")
	fmt.Printf("═══════════════════════════════════\n")

	fmt.Printf("📁 **Input Source**: %s (%s)\n", model.Metadata.Source, model.Metadata.Type)
	fmt.Printf("📅 **Timestamp**: %s\n", model.Metadata.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("💾 **File Size**: %d bytes\n", model.Metadata.Size)

	fmt.Printf("\n🌐 **Network Segments**: %d\n", len(model.Networks))
	for id, segment := range model.Networks {
		fmt.Printf("  • **%s** (%s)\n", id, segment.Name)
		fmt.Printf("    📍 CIDR: %s\n", segment.CIDR)
		fmt.Printf("    🏷️  Zone: %s\n", segment.Zone)
		fmt.Printf("    🎯 Purpose: %s\n", segment.Purpose)
		fmt.Printf("    ⚠️  Risk: %s\n", segment.Risk)
		fmt.Printf("\n")
	}

	fmt.Printf("🔒 **Security Policies**: %d\n", len(model.Policies))
	for i, policy := range model.Policies {
		if i >= 5 { // Show only first 5 rules
			fmt.Printf("  ... and %d more rules\n", len(model.Policies)-5)
			break
		}
		fmt.Printf("  • **Rule %d**: %s\n", i+1, policy.Description)
		fmt.Printf("    🎯 Action: %s\n", policy.Action)
		fmt.Printf("    📤 Source: %s\n", policy.Source.CIDR)
		fmt.Printf("    📥 Destination: %s\n", policy.Destination.CIDR)
		fmt.Printf("    🔌 Protocol: %s\n", policy.Protocol)
		fmt.Printf("\n")
	}

	// Export detailed JSON for further analysis
	jsonData, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		log.Printf("Warning: Failed to marshal JSON: %v", err)
	} else {
		jsonFile := "opnsense_analysis.json"
		if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
			log.Printf("Warning: Failed to write JSON file: %v", err)
		} else {
			fmt.Printf("💾 **Detailed Analysis**: Exported to %s\n", jsonFile)
		}
	}

	fmt.Printf("\n🎯 **OPNsense Integration Ready!**\n")
	fmt.Printf("Network segments and security policies successfully parsed.\n")
	fmt.Printf("Ready for integration with PCAP analysis and diagram generation.\n")
}
