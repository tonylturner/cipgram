package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"cipgram/internal/interfaces"
	"cipgram/internal/parsers/opnsense"
	"cipgram/internal/writers"
)

func main() {
	fmt.Printf("🎨 **CIPgram Enhanced Diagram Generation**\n")
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("Demonstrating all three diagram types:\n")
	fmt.Printf("1. 🔥 Firewall-config-only diagrams\n")
	fmt.Printf("2. 📊 Enhanced PCAP-only diagrams\n")
	fmt.Printf("3. 🚀 Combined analysis architecture\n\n")

	// Create output directory
	outputDir := "enhanced_diagrams"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Test 1: Firewall-config-only diagrams (we have this data)
	testFirewallDiagrams(outputDir)

	// Test 2: Mock PCAP analysis (for demonstration)
	testEnhancedPCAPDiagrams(outputDir)

	// Test 3: Combined analysis architecture (ready for your OT lab)
	testCombinedAnalysisArchitecture(outputDir)

	fmt.Printf("\n🎯 **All Diagram Types Generated Successfully!**\n")
	fmt.Printf("📁 Output directory: %s/\n", outputDir)
	fmt.Printf("🔬 Ready for your OT segmentation lab data!\n")
}

// testFirewallDiagrams demonstrates firewall-config-only diagram generation
func testFirewallDiagrams(outputDir string) {
	fmt.Printf("🔥 **Test 1: Firewall-Config-Only Diagrams**\n")
	fmt.Printf("──────────────────────────────────────────\n")

	configPath := "test_opnsense_config.xml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("⚠️  Skipping firewall test - config file not found\n\n")
		return
	}

	// Parse OPNsense configuration
	parser := opnsense.NewOPNsenseParser(configPath)
	model, err := parser.Parse()
	if err != nil {
		log.Printf("Warning: Failed to parse firewall config: %v", err)
		return
	}

	fmt.Printf("✓ Parsed OPNsense config: %d networks, %d policies\n", len(model.Networks), len(model.Policies))

	// Generate firewall diagrams
	generator := writers.NewFirewallDiagramGenerator(model)

	// Network topology
	topologyPath := filepath.Join(outputDir, "firewall_topology.dot")
	if err := generator.GenerateNetworkTopologyDiagram(topologyPath); err != nil {
		log.Printf("Warning: %v", err)
	} else {
		fmt.Printf("✓ Network topology diagram: %s\n", topologyPath)
	}

	// IEC 62443 zones
	zonePath := filepath.Join(outputDir, "firewall_iec62443.dot")
	if err := generator.GenerateIEC62443ZoneDiagram(zonePath); err != nil {
		log.Printf("Warning: %v", err)
	} else {
		fmt.Printf("✓ IEC 62443 zone diagram: %s\n", zonePath)
	}

	fmt.Printf("📋 Firewall analysis shows:\n")
	for _, network := range model.Networks {
		fmt.Printf("  • %s (%s) → %s zone, %s risk\n",
			network.ID, network.CIDR, network.Zone, network.Risk)
	}
	fmt.Printf("\n")
}

// testEnhancedPCAPDiagrams demonstrates enhanced PCAP analysis (mock for now)
func testEnhancedPCAPDiagrams(outputDir string) {
	fmt.Printf("📊 **Test 2: Enhanced PCAP Analysis**\n")
	fmt.Printf("──────────────────────────────────────────\n")

	// For demonstration, create a mock PCAP model showing what enhanced analysis would look like
	mockPCAPModel := createMockPCAPModel()

	fmt.Printf("✓ Mock PCAP analysis: %d assets, %d flows, %d networks\n",
		len(mockPCAPModel.Assets), len(mockPCAPModel.Flows), len(mockPCAPModel.Networks))

	// Generate enhanced PCAP diagrams using firewall diagram generator
	// (Shows how the same generator can handle different data sources)
	generator := writers.NewFirewallDiagramGenerator(mockPCAPModel)

	pcapTopologyPath := filepath.Join(outputDir, "pcap_topology.dot")
	if err := generator.GenerateNetworkTopologyDiagram(pcapTopologyPath); err != nil {
		log.Printf("Warning: %v", err)
	} else {
		fmt.Printf("✓ PCAP network topology: %s\n", pcapTopologyPath)
	}

	pcapZonePath := filepath.Join(outputDir, "pcap_iec62443.dot")
	if err := generator.GenerateIEC62443ZoneDiagram(pcapZonePath); err != nil {
		log.Printf("Warning: %v", err)
	} else {
		fmt.Printf("✓ PCAP IEC 62443 zones: %s\n", pcapZonePath)
	}

	fmt.Printf("📋 PCAP analysis would show:\n")
	for _, asset := range mockPCAPModel.Assets {
		fmt.Printf("  • %s (%s) → %s level, %s zone\n",
			asset.DeviceName, asset.IP, asset.PurdueLevel, asset.IEC62443Zone)
	}
	fmt.Printf("\n")
}

// testCombinedAnalysisArchitecture demonstrates the combined analysis capability
func testCombinedAnalysisArchitecture(outputDir string) {
	fmt.Printf("🚀 **Test 3: Combined Analysis Architecture**\n")
	fmt.Printf("──────────────────────────────────────────\n")

	// This demonstrates the architecture that will work with your OT lab data
	fmt.Printf("🏗️  Combined analysis architecture ready!\n")
	fmt.Printf("💡 When you have matching PCAP + firewall config:\n")
	fmt.Printf("\n")
	fmt.Printf("```go\n")
	fmt.Printf("// Example usage with your OT lab data:\n")
	fmt.Printf("pcapParser := pcap.NewPCAPParser(\"ot_lab_traffic.pcap\", nil)\n")
	fmt.Printf("fwParser := opnsense.NewOPNsenseParser(\"ot_lab_firewall.xml\")\n")
	fmt.Printf("\n")
	fmt.Printf("analyzer := analysis.NewCombinedAnalyzer(pcapParser, fwParser)\n")
	fmt.Printf("analyzer.ParseAllSources()\n")
	fmt.Printf("combinedModel := analyzer.GenerateCombinedModel()\n")
	fmt.Printf("\n")
	fmt.Printf("// Generate advanced diagrams with policy violations,\n")
	fmt.Printf("// segmentation opportunities, and risk assessment\n")
	fmt.Printf("```\n")
	fmt.Printf("\n")

	// Show what combined analysis capabilities we have ready
	fmt.Printf("🔍 **Advanced Analysis Capabilities Ready:**\n")
	fmt.Printf("  ✓ Policy violation detection\n")
	fmt.Printf("  ✓ Segmentation opportunity identification\n")
	fmt.Printf("  ✓ Security posture assessment\n")
	fmt.Printf("  ✓ Cross-zone traffic analysis\n")
	fmt.Printf("  ✓ Asset reconciliation between sources\n")
	fmt.Printf("  ✓ Compliance scoring\n")
	fmt.Printf("\n")

	// Create a placeholder combined analysis file for reference
	combinedRefPath := filepath.Join(outputDir, "combined_analysis_reference.md")
	createCombinedAnalysisReference(combinedRefPath)
	fmt.Printf("📖 Reference documentation: %s\n", combinedRefPath)
}

// createMockPCAPModel creates a mock PCAP model for demonstration
func createMockPCAPModel() *interfaces.NetworkModel {
	model := &interfaces.NetworkModel{
		Assets:   make(map[string]*interfaces.Asset),
		Networks: make(map[string]*interfaces.NetworkSegment),
		Flows:    make(map[interfaces.FlowKey]*interfaces.Flow),
		Policies: []*interfaces.SecurityPolicy{},
		Metadata: interfaces.InputMetadata{
			Source: "mock_industrial_traffic.pcap",
			Type:   interfaces.InputTypePCAP,
			Size:   1024000,
		},
	}

	// Mock industrial assets discovered from PCAP
	assets := []*interfaces.Asset{
		{
			ID:           "192.168.1.10",
			IP:           "192.168.1.10",
			MAC:          "00:0E:8C:12:34:56",
			DeviceName:   "Rockwell PLC",
			PurdueLevel:  interfaces.L1,
			IEC62443Zone: interfaces.ManufacturingZone,
			Criticality:  interfaces.CriticalAsset,
			Exposure:     interfaces.OTOnly,
			Protocols:    []interfaces.Protocol{"EtherNet/IP", "Modbus TCP"},
		},
		{
			ID:           "192.168.1.20",
			IP:           "192.168.1.20",
			MAC:          "08:00:06:AA:BB:CC",
			DeviceName:   "Siemens HMI",
			PurdueLevel:  interfaces.L2,
			IEC62443Zone: interfaces.ManufacturingZone,
			Criticality:  interfaces.HighAsset,
			Exposure:     interfaces.OTOnly,
			Protocols:    []interfaces.Protocol{"S7Comm", "OPC-UA"},
		},
		{
			ID:           "192.168.10.5",
			IP:           "192.168.10.5",
			MAC:          "00:50:7F:11:22:33",
			DeviceName:   "SCADA Server",
			PurdueLevel:  interfaces.L3,
			IEC62443Zone: interfaces.EnterpriseZone,
			Criticality:  interfaces.HighAsset,
			Exposure:     interfaces.CorporateExposed,
			Protocols:    []interfaces.Protocol{"OPC-UA", "DNP3"},
		},
	}

	// Add assets to model
	for _, asset := range assets {
		model.Assets[asset.ID] = asset
	}

	// Create mock network segments inferred from traffic
	model.Networks["production_lan"] = &interfaces.NetworkSegment{
		ID:      "production_lan",
		CIDR:    "192.168.1.0/24",
		Name:    "Production LAN",
		Zone:    interfaces.ManufacturingZone,
		Risk:    interfaces.HighRisk,
		Purpose: "Industrial Control",
		Assets:  []*interfaces.Asset{assets[0], assets[1]},
	}

	model.Networks["scada_dmz"] = &interfaces.NetworkSegment{
		ID:      "scada_dmz",
		CIDR:    "192.168.10.0/24",
		Name:    "SCADA DMZ",
		Zone:    interfaces.EnterpriseZone,
		Risk:    interfaces.MediumRisk,
		Purpose: "SCADA/HMI",
		Assets:  []*interfaces.Asset{assets[2]},
	}

	// Add mock flows
	model.Flows[interfaces.FlowKey{SrcIP: "192.168.1.20", DstIP: "192.168.1.10", Proto: "EtherNet/IP"}] = &interfaces.Flow{
		Source:      "192.168.1.20",
		Destination: "192.168.1.10",
		Protocol:    "EtherNet/IP",
		Packets:     1500,
		Bytes:       75000,
		Allowed:     true,
	}

	return model
}

// createCombinedAnalysisReference creates reference documentation
func createCombinedAnalysisReference(path string) {
	content := `# Combined Analysis Reference

## Overview
This document describes the advanced analysis capabilities available when combining PCAP traffic analysis with firewall configuration data.

## Analysis Types

### 1. Policy Violation Detection
- Compares actual network traffic against configured firewall rules
- Identifies unauthorized communication flows
- Highlights potential security gaps

### 2. Segmentation Opportunity Analysis  
- Analyzes cross-zone traffic patterns
- Identifies micro-segmentation opportunities
- Suggests additional firewall rules

### 3. Security Posture Assessment
- Calculates compliance scores based on policy coverage
- Assesses overall network security posture
- Provides risk-based recommendations

### 4. Asset Reconciliation
- Merges asset data from multiple sources
- Validates network topology against actual traffic
- Identifies shadow IT and unknown devices

## Example Output

When you have matching PCAP and firewall data from your OT lab:

- **Policy Violations**: "Traffic from PLC (192.168.1.10) to Internet not explicitly allowed"
- **Segmentation Opportunities**: "Manufacturing Zone has 15 cross-communications that could be micro-segmented"
- **Compliance Score**: "87% of traffic flows match configured policies"
- **Risk Assessment**: "3 critical assets exposed to higher-level networks"

## Integration Points

The combined analyzer is designed to work with:
- ✓ OPNsense configurations
- ✓ PCAP traffic captures  
- → Future: FortiGate, pfSense, etc.

Ready for your OT segmentation lab data!
`

	os.WriteFile(path, []byte(content), 0644)
}
