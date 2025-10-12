package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cipgram/internal/output"
	"cipgram/internal/parsers/opnsense"
	"cipgram/internal/writers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func generateImage(dotPath string) error {
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

	// Actually generate the images using dot command
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

		// Execute dot command (silently, check if it exists)
		if err := exec.Command("dot", args...).Run(); err != nil {
			log.Printf("Warning: Failed to generate %s (is Graphviz installed?): %v", cmd.output, err)
		} else {
			log.Printf("Generated: %s", cmd.output)
		}
	}

	return nil
}

// processFirewallConfig analyzes firewall configuration and generates diagrams
func processFirewallConfig(configPath string, paths *output.OutputPaths, projectName string) error {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", configPath)
	}

	log.Printf("🔧 Parsing OPNsense configuration...")

	// Parse OPNsense configuration
	parser := opnsense.NewOPNsenseParser(configPath)
	model, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse OPNsense config: %v", err)
	}

	log.Printf("✅ Parsed configuration: %d networks, %d policies", len(model.Networks), len(model.Policies))

	// Create firewall diagram generator
	generator := writers.NewFirewallDiagramGenerator(model)

	// Generate network topology diagram
	topologyPath := filepath.Join(paths.FirewallAnalysis, "network_topology.dot")
	log.Printf("🌐 Generating network topology diagram...")
	if err := generator.GenerateNetworkTopologyDiagram(topologyPath); err != nil {
		log.Printf("Warning: Failed to generate topology diagram: %v", err)
	} else {
		log.Printf("✅ Network topology: %s", topologyPath)

		// Generate image if requested
		if err := generateImageEmbedded(topologyPath); err != nil {
			log.Printf("Image generation warning: %v", err)
		}
	}

	// Generate firewall rules summary
	rulesPath := filepath.Join(paths.FirewallAnalysis, "firewall_rules.txt")
	log.Printf("📋 Generating firewall rules summary...")
	if err := generator.GenerateFirewallRulesSummary(rulesPath); err != nil {
		log.Printf("Warning: Failed to generate rules summary: %v", err)
	} else {
		log.Printf("✅ Firewall rules: %s", rulesPath)
	}

	// Generate IEC 62443 zone diagram
	zonePath := filepath.Join(paths.IEC62443Diagrams, "iec62443_zones.dot")
	log.Printf("🏭 Generating IEC 62443 zone diagram...")
	if err := generator.GenerateIEC62443ZoneDiagram(zonePath); err != nil {
		log.Printf("Warning: Failed to generate zone diagram: %v", err)
	} else {
		log.Printf("✅ IEC 62443 zones: %s", zonePath)

		// Generate image if requested
		if err := generateImageEmbedded(zonePath); err != nil {
			log.Printf("Image generation warning: %v", err)
		}
	}

	// Display analysis summary
	log.Printf("\n🎓 Firewall Analysis Summary:")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(model.Networks) > 0 {
		log.Printf("📊 Network Segments:")
		for _, network := range model.Networks {
			log.Printf("  • %s (%s) → %s zone, %s risk",
				network.ID, network.CIDR, network.Zone, network.Risk)
		}
	}

	if len(model.Policies) > 0 {
		log.Printf("🔒 Security Policies:")
		for i, policy := range model.Policies {
			if i < 5 { // Show first 5 policies
				log.Printf("  • %s → %s (%s)",
					policy.Source, policy.Destination, policy.Action)
			}
		}
		if len(model.Policies) > 5 {
			log.Printf("  ... and %d more policies", len(model.Policies)-5)
		}
	}

	return nil
}

func main() {
	pcapPath := flag.String("pcap", "", "Path to pcap/pcapng file")
	firewallConfig := flag.String("firewall-config", "", "Path to firewall configuration file (OPNsense XML)")
	outDOT := flag.String("out", "", "Output Graphviz DOT path (default: output/PROJECT/network_diagrams/diagram.dot)")
	outJSON := flag.String("json", "", "Output JSON path (default: output/PROJECT/data/diagram.json)")
	cfgPath := flag.String("config", "", "Optional YAML with subnet→Purdue mappings")
	generateImages := flag.Bool("images", true, "Generate PNG/SVG images from DOT file (requires Graphviz)")
	projectName := flag.String("project", "", "Project name for organized output (default: auto-generated from input)")

	// Diagram options
	summaryMode := flag.Bool("summary", false, "Generate simplified summary diagram (groups similar connections)")
	hideUnknown := flag.Bool("hide-unknown", false, "Hide devices with unknown Purdue levels")
	maxNodes := flag.Int("max-nodes", 0, "Maximum nodes to show (0 = unlimited, shows top communicators)")
	showHostnames := flag.Bool("hostnames", false, "Attempt to resolve and show hostnames for devices (slower due to DNS)")
	fastMode := flag.Bool("fast", false, "Fast mode: skip vendor lookups and hostname resolution for speed")
	diagramType := flag.String("diagram", "both", "Diagram type: 'purdue' for functional modeling, 'network' for segmentation planning, 'both' for both types (default)")
	bothDiagrams := flag.Bool("both", false, "Generate both Purdue and Network diagrams (same as -diagram both)")

	flag.Parse()

	// Validate input arguments
	if *pcapPath == "" && *firewallConfig == "" {
		log.Printf("❌ Error: Must provide either -pcap or -firewall-config")
		log.Printf("💡 Examples:")
		log.Printf("   PCAP analysis:     ./cipgram -pcap traffic.pcap -project 'demo'")
		log.Printf("   Firewall analysis: ./cipgram -firewall-config config.xml -project 'firewall_audit'")
		log.Printf("   Combined analysis: ./cipgram -pcap traffic.pcap -firewall-config config.xml -project 'full_analysis'")
		return
	}

	// Create output manager with project name
	if *projectName == "" {
		// Auto-generate project name from input file
		if *pcapPath != "" {
			base := filepath.Base(*pcapPath)
			*projectName = strings.TrimSuffix(base, filepath.Ext(base))
		} else if *firewallConfig != "" {
			base := filepath.Base(*firewallConfig)
			*projectName = strings.TrimSuffix(base, filepath.Ext(base)) + "_firewall"
		} else {
			*projectName = "analysis_" + fmt.Sprintf("%d", time.Now().Unix())
		}
	}

	outputMgr := output.NewOutputManager(*projectName)
	paths, err := outputMgr.CreateProjectStructure()
	if err != nil {
		log.Fatalf("output directory creation error: %v", err)
	}

	// Set default output paths if not specified
	if *outDOT == "" {
		*outDOT = filepath.Join(paths.NetworkDiagrams, "diagram.dot")
	}
	if *outJSON == "" {
		*outJSON = filepath.Join(paths.DataOutput, "diagram.json")
	}

	// Handle both diagrams option (now default)
	if *bothDiagrams || *diagramType == "both" || *diagramType == "" {
		*diagramType = "both"
	}

	log.Printf("🎯 CIPgram Analysis - Project: %s", *projectName)
	log.Printf("📁 Output directory: %s", paths.ProjectRoot)

	// Determine analysis type and process accordingly
	if *pcapPath != "" && *firewallConfig != "" {
		log.Printf("🚀 Combined Analysis: PCAP + Firewall Config")
		log.Printf("📊 PCAP file: %s", *pcapPath)
		log.Printf("🔧 Firewall config: %s", *firewallConfig)
		// TODO: Implement combined analysis
		log.Printf("❌ Combined analysis not yet implemented - use separate analyses for now")
		return
	} else if *firewallConfig != "" {
		log.Printf("🔧 Firewall Configuration Analysis")
		log.Printf("📊 Config file: %s", *firewallConfig)

		// Process firewall configuration
		err := processFirewallConfig(*firewallConfig, paths, *projectName)
		if err != nil {
			log.Printf("❌ Error analyzing firewall config: %v", err)
			return
		}

		log.Printf("\n🎯 Firewall analysis complete! Check the %s directory for results.", paths.ProjectRoot)
		return
	} else if *pcapPath != "" {
		log.Printf("📊 PCAP Traffic Analysis")
		log.Printf("📊 PCAP file: %s", *pcapPath)
		log.Printf("💾 JSON file: %s", *outJSON)

		// Continue with existing PCAP processing...
	}

	mapping, err := loadMapping(*cfgPath)
	if err != nil {
		if *cfgPath != "" {
			log.Printf("Warning: config load error: %v", err)
			log.Printf("Continuing with intelligent heuristic-based classification...")
		}
		mapping = &MappingTable{} // Use empty mapping table
	}

	g := newGraph()

	// Open PCAP file for analysis
	handle, err := pcap.OpenOffline(*pcapPath)
	if err != nil {
		log.Printf("❌ Error opening PCAP file: %v", err)
		log.Printf("💡 Tip: Check file path and format (should be .pcap or .pcapng)")
		log.Printf("📁 Attempted path: %s", *pcapPath)
		return
	}
	defer handle.Close()

	log.Printf("Analyzing pcap file: %s", *pcapPath)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	startTime := time.Now()
	for pkt := range src.Packets() {
		packetCount++
		if packetCount%1000 == 0 {
			elapsed := time.Since(startTime)
			rate := float64(packetCount) / elapsed.Seconds()
			log.Printf("📊 Processed %d packets (%.0f pkt/sec)", packetCount, rate)
		}

		ethLayer := pkt.Layer(layers.LayerTypeEthernet)
		ip4 := pkt.Layer(layers.LayerTypeIPv4)
		ip6 := pkt.Layer(layers.LayerTypeIPv6)
		tcpL := pkt.Layer(layers.LayerTypeTCP)
		udpL := pkt.Layer(layers.LayerTypeUDP)

		var eth *layers.Ethernet
		if ethLayer != nil {
			eth = ethLayer.(*layers.Ethernet)
		}

		var sIP, dIP net.IP
		ipBased := true
		if ip4 != nil {
			ip := ip4.(*layers.IPv4)
			sIP = ip.SrcIP
			dIP = ip.DstIP
		} else if ip6 != nil {
			ip := ip6.(*layers.IPv6)
			sIP = ip.SrcIP
			dIP = ip.DstIP
		} else {
			ipBased = false
		}

		// Profinet DCP (L2 only)
		if !ipBased && eth != nil && eth.EthernetType == layers.EthernetType(0x8892) {
			srcID := eth.SrcMAC.String()
			dstID := eth.DstMAC.String()
			srcHost := g.getHost(srcID)
			dstHost := g.getHost(dstID)

			proto, _, _ := protFromPacket(nil, nil, eth)
			key := FlowKey{SrcIP: srcID, DstIP: dstID, Proto: proto}
			edge := g.Edges[key]
			if edge == nil {
				edge = &Edge{
					Src:       srcID,
					Dst:       dstID,
					Protocol:  proto,
					FirstSeen: pkt.Metadata().Timestamp,
				}
				g.Edges[key] = edge
			}
			edge.Packets++
			edge.Bytes += int64(len(pkt.Data()))
			edge.LastSeen = pkt.Metadata().Timestamp

			lvl, notes := classifyEdge(proto, false)
			if edge.InferredLevel == Unknown {
				edge.InferredLevel = lvl
			}
			edge.Notes = append(edge.Notes, notes...)
			_ = srcHost
			_ = dstHost
			continue
		}
		if !ipBased {
			continue
		}

		var tcp *layers.TCP
		var udp *layers.UDP
		if tcpL != nil {
			tcp = tcpL.(*layers.TCP)
		}
		if udpL != nil {
			udp = udpL.(*layers.UDP)
		}

		srcID := sIP.String()
		dstID := dIP.String()
		srcHost := g.getHost(srcID)
		dstHost := g.getHost(dstID)

		// Extract and store MAC addresses (vendor lookup deferred for performance)
		if eth != nil {
			srcHost.MAC = eth.SrcMAC.String()
			dstHost.MAC = eth.DstMAC.String()
		}

		// Apply mapping overrides if present
		mapping.apply(srcHost)
		mapping.apply(dstHost)

		// Track seen ports (for scoring)
		if tcp != nil {
			srcHost.PortsSeen[uint16(tcp.SrcPort)] = true
			dstHost.PortsSeen[uint16(tcp.DstPort)] = true
		}
		if udp != nil {
			srcHost.PortsSeen[uint16(udp.SrcPort)] = true
			dstHost.PortsSeen[uint16(udp.DstPort)] = true
		}
		if isMulticastIP(dIP) {
			dstHost.MulticastPeer = true
		}

		// Protocol + edge record
		proto, _, _ := protFromPacket(tcp, udp, eth)
		key := FlowKey{SrcIP: srcID, DstIP: dstID, Proto: proto}
		edge := g.Edges[key]
		if edge == nil {
			edge = &Edge{
				Src:       srcID,
				Dst:       dstID,
				Protocol:  proto,
				FirstSeen: pkt.Metadata().Timestamp,
			}
			g.Edges[key] = edge
		}
		edge.Packets++
		edge.Bytes += int64(len(pkt.Data()))
		edge.LastSeen = pkt.Metadata().Timestamp

		// Edge-level Purdue hint
		lvl, notes := classifyEdge(proto, isMulticastIP(dIP))
		if edge.InferredLevel == Unknown {
			edge.InferredLevel = lvl
		}
		if len(notes) > 0 {
			edge.Notes = append(edge.Notes, notes...)
		}

		// CIP sniffer for TCP/44818
		if proto == ProtoENIP_Explicit && tcp != nil {
			app := tcp.LayerPayload()
			if name, hex, ok := parseENIP_CIP_FromTCP(app); ok {
				edge.CIPService = name
				edge.CIPServiceCode = hex
			}
		}

		// Per-host flow stats for best-effort classification
		srcHost.ensureMaps()
		dstHost.ensureMaps()

		if srcHost.PeersByProtoInitiated[proto] == nil {
			srcHost.PeersByProtoInitiated[proto] = map[string]bool{}
		}
		srcHost.PeersByProtoInitiated[proto][dstID] = true
		srcHost.InitiatedCounts[proto]++

		if dstHost.PeersByProtoReceived[proto] == nil {
			dstHost.PeersByProtoReceived[proto] = map[string]bool{}
		}
		dstHost.PeersByProtoReceived[proto][srcID] = true
		dstHost.ReceivedCounts[proto]++
	}

	log.Printf("Processed %d total packets", packetCount)
	log.Printf("Found %d hosts and %d communication flows", len(g.Hosts), len(g.Edges))

	// Deduplicate and enhance host information
	deduplicateHosts(g)
	log.Printf("After deduplication: %d unique hosts", len(g.Hosts))

	// PERFORMANCE OPTIMIZATION: Batch expensive network operations after packet processing
	if !*fastMode {
		log.Printf("Performing vendor identification and hostname resolution...")

		// First pass: Resolve vendor names from MAC addresses (with caching)
		vendorCache := make(map[string]string)
		for _, h := range g.Hosts {
			if h.MAC != "" && h.Vendor == "" {
				if vendor, cached := vendorCache[h.MAC]; cached {
					h.Vendor = vendor
				} else {
					h.Vendor = lookupOUI(h.MAC)
					vendorCache[h.MAC] = h.Vendor
				}
			}
		}

		// Second pass: Tag hosts and resolve hostnames
		for _, h := range g.Hosts {
			tagHostHeuristic(h)

			// Resolve hostname if requested (DNS lookup)
			if *showHostnames {
				h.Hostname = resolveHostname(h.IP)
			}

			// Detect device name from protocols/roles
			h.DeviceName = detectDeviceName(h)
		}
	} else {
		log.Printf("Fast mode: skipping vendor/hostname resolution for speed")
		// Still do heuristic tagging as it's fast
		for _, h := range g.Hosts {
			tagHostHeuristic(h)
			h.DeviceName = detectDeviceName(h)
		}
	}

	log.Printf("Found %d hosts and %d communication flows before filtering", len(g.Hosts), len(g.Edges))

	// Apply relationship-focused filtering (no packet count filtering)
	var finalGraph *Graph
	if *summaryMode {
		log.Printf("Creating summary diagram...")
		filteredGraph := filterGraph(g, *hideUnknown, *maxNodes)
		finalGraph = createSummaryGraph(filteredGraph)
	} else {
		log.Printf("Applying relationship-focused filters: hide-unknown=%v, max-nodes=%d", *hideUnknown, *maxNodes)
		finalGraph = filterGraph(g, *hideUnknown, *maxNodes)
	}

	log.Printf("Final diagram has %d hosts and %d communication flows",
		len(finalGraph.Hosts), len(finalGraph.Edges))

	// Training workshop feedback - show FINAL classification results
	log.Printf("")
	log.Printf("🎓 Training Analysis Summary:")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	l1Count := 0
	l2Count := 0
	l3Count := 0
	unknownCount := 0

	// Count devices AFTER classification (use final results)
	for _, host := range finalGraph.Hosts {
		switch host.InferredLevel {
		case L1:
			l1Count++
		case L2:
			l2Count++
		case L3:
			l3Count++
		default:
			unknownCount++
		}
	}

	log.Printf("📊 Purdue Model Classification:")
	log.Printf("   Level 1 (Field Devices): %d", l1Count)
	log.Printf("   Level 2 (Control Systems): %d", l2Count)
	log.Printf("   Level 3 (Operations): %d", l3Count)
	if unknownCount > 0 {
		log.Printf("   Unknown Classification: %d", unknownCount)
	}

	// Show detected protocols for training
	protocols := make(map[string]int)
	for _, edge := range finalGraph.Edges {
		protoStr := string(edge.Protocol)
		if strings.Contains(protoStr, "ENIP") {
			protocols["EtherNet/IP"]++
		} else if strings.Contains(protoStr, "Modbus") {
			protocols["Modbus TCP"]++
		} else if strings.Contains(protoStr, "S7") {
			protocols["S7Comm"]++
		} else if strings.Contains(protoStr, "OPC") {
			protocols["OPC-UA"]++
		}
	}

	if len(protocols) > 0 {
		log.Printf("🔌 Industrial Protocols Detected:")
		for proto, count := range protocols {
			log.Printf("   %s: %d connections", proto, count)
		}
	}

	// Generate diagrams based on type
	switch *diagramType {
	case "both":
		// Generate both Purdue and Network diagrams
		log.Printf("Generating both Purdue and Network diagrams...")

		// Purdue diagram using gg (Go Graphics)
		purduePngPath, err := generatePurdueWithGG(finalGraph, paths.NetworkDiagrams)
		if err != nil {
			log.Printf("❌ Error generating Purdue diagram: %v", err)
			log.Printf("💡 Tip: This might be due to missing graphics libraries or insufficient data")
			log.Printf("🔄 Continuing with other outputs...")
		} else {
			log.Printf("• Purdue PNG: %s", purduePngPath)
		}

		// Network diagram using DOT
		networkDotPath := filepath.Join(paths.NetworkDiagrams, "network_diagram.dot")
		if err := writeDOT(finalGraph, networkDotPath, NetworkDiagram); err != nil {
			log.Printf("❌ Error generating network DOT file: %v", err)
			log.Printf("💡 Tip: Check disk space and write permissions")
			log.Printf("🔄 Continuing with other outputs...")
		} else {
			log.Printf("• Network DOT: %s", networkDotPath)

			// Generate network diagram images
			if *generateImages {
				if err := generateImageEmbedded(networkDotPath); err != nil {
					log.Printf("Network image generation warning: %v", err)
					log.Printf("💡 Tip: The DOT file is still available for manual processing")
				}
			}
		}

	case "network":
		log.Printf("Generating network segmentation diagram...")
		if err := writeDOT(finalGraph, *outDOT, NetworkDiagram); err != nil {
			log.Printf("❌ Error generating network diagram: %v", err)
			log.Printf("💡 Tip: Check output directory permissions and disk space")
			log.Printf("📁 Attempted path: %s", *outDOT)
		} else {
			log.Printf("• DOT file: %s", *outDOT)

			// Generate images if requested
			if *generateImages {
				if err := generateImageEmbedded(*outDOT); err != nil {
					log.Printf("Image generation warning: %v", err)
					log.Printf("💡 Tip: The DOT file is still available for manual processing")
				}
			}
		}

	default: // "purdue"
		log.Printf("Generating Purdue functional model diagram...")

		// Use gg-based generation for Purdue diagrams
		purduePngPath, err := generatePurdueWithGG(finalGraph, paths.NetworkDiagrams)
		if err != nil {
			log.Printf("❌ Error generating Purdue diagram: %v", err)
			log.Printf("💡 Tip: This might be due to missing graphics libraries or insufficient data")
		} else {
			log.Printf("• Purdue PNG: %s", purduePngPath)
		}
	}

	// Write JSON output (always generated)
	if err := writeJSON(finalGraph, *outJSON); err != nil {
		log.Printf("❌ Error writing JSON output: %v", err)
		log.Printf("💡 Tip: Check output directory permissions and disk space")
		log.Printf("📁 Attempted path: %s", *outJSON)
	} else {
		log.Printf("• JSON file: %s", *outJSON)
	}

	// Save OUI cache for future runs
	SaveOUICache()

	// Generate project summary
	metadata := output.ProjectMetadata{
		AnalysisType: "PCAP Traffic Analysis",
		InputSources: []output.InputSourceInfo{
			{
				Type:        "PCAP File",
				Path:        *pcapPath,
				Size:        getFileSize(*pcapPath),
				Description: "Network traffic capture for industrial protocol analysis",
			},
		},
		Summary: output.AnalysisSummary{
			AssetsFound:     len(finalGraph.Hosts),
			NetworksFound:   countInferredNetworks(finalGraph),
			PoliciesFound:   0, // N/A for PCAP-only analysis
			ViolationsFound: 0, // N/A for PCAP-only analysis
			RiskLevel:       inferOverallRisk(finalGraph),
		},
	}

	if err := outputMgr.GenerateProjectSummary(paths, metadata); err != nil {
		log.Printf("Warning: Failed to generate project summary: %v", err)
	} else {
		log.Printf("📋 Project summary: %s/project_summary.md", paths.ProjectRoot)
	}

	fmt.Printf("\n🎯 Analysis complete! Check the %s directory for results.\n", paths.ProjectRoot)
}

// Helper functions for project summary
func getFileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func countInferredNetworks(g *Graph) int {
	networks := make(map[string]bool)
	for _, host := range g.Hosts {
		if host.IP != "" {
			// Simple network inference based on /24 networks
			ip := strings.Split(host.IP, ".")
			if len(ip) >= 3 {
				network := fmt.Sprintf("%s.%s.%s.0/24", ip[0], ip[1], ip[2])
				networks[network] = true
			}
		}
	}
	return len(networks)
}

func inferOverallRisk(g *Graph) string {
	highRiskCount := 0
	totalHosts := len(g.Hosts)

	for _, host := range g.Hosts {
		if host.ICSScore > host.ITScore && host.ICSScore > 0 {
			highRiskCount++
		}
	}

	if totalHosts == 0 {
		return "Unknown"
	}

	riskRatio := float64(highRiskCount) / float64(totalHosts)
	if riskRatio > 0.7 {
		return "High"
	} else if riskRatio > 0.3 {
		return "Medium"
	}
	return "Low"
}
