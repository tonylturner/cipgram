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

	"cipgram/internal/output"

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

func main() {
	pcapPath := flag.String("pcap", "", "Path to pcap/pcapng file")
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

	if *pcapPath == "" {
		log.Fatal("provide -pcap path to analyze")
	}

	// Create output manager with project name
	if *projectName == "" {
		// Auto-generate project name from pcap file
		base := filepath.Base(*pcapPath)
		*projectName = strings.TrimSuffix(base, filepath.Ext(base))
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
	log.Printf("📊 DOT file: %s", *outDOT)
	log.Printf("💾 JSON file: %s", *outJSON)

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
		log.Fatalf("pcap open error: %v", err)
	}
	defer handle.Close()

	log.Printf("Analyzing pcap file: %s", *pcapPath)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	for pkt := range src.Packets() {
		packetCount++
		if packetCount%1000 == 0 {
			log.Printf("Processed %d packets...", packetCount)
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

	// Generate diagrams based on type
	switch *diagramType {
	case "both":
		// Generate both Purdue and Network diagrams
		log.Printf("Generating both Purdue and Network diagrams...")

		// Purdue diagram using gg (Go Graphics)
		purduePngPath, err := generatePurdueWithGG(finalGraph, paths.NetworkDiagrams)
		if err != nil {
			log.Fatalf("Purdue PNG generation error: %v", err)
		}
		log.Printf("• Purdue PNG: %s", purduePngPath)

		// Network diagram using DOT
		networkDotPath := filepath.Join(paths.NetworkDiagrams, "network_diagram.dot")
		if err := writeDOT(finalGraph, networkDotPath, NetworkDiagram); err != nil {
			log.Fatalf("Network DOT write error: %v", err)
		}
		log.Printf("• Network DOT: %s", networkDotPath)

		// Generate network diagram images
		if *generateImages {
			if err := generateImage(networkDotPath); err != nil {
				log.Printf("Network image generation warning: %v", err)
			}
		}

	case "network":
		log.Printf("Generating network segmentation diagram...")
		if err := writeDOT(finalGraph, *outDOT, NetworkDiagram); err != nil {
			log.Fatalf("DOT write error: %v", err)
		}
		log.Printf("• DOT file: %s", *outDOT)

		// Generate images if requested
		if *generateImages {
			if err := generateImage(*outDOT); err != nil {
				log.Printf("Image generation warning: %v", err)
			}
		}

	default: // "purdue"
		log.Printf("Generating Purdue functional model diagram...")

		// Use gg-based generation for Purdue diagrams
		purduePngPath, err := generatePurdueWithGG(finalGraph, paths.NetworkDiagrams)
		if err != nil {
			log.Fatalf("Purdue PNG generation error: %v", err)
		}
		log.Printf("• Purdue PNG: %s", purduePngPath)
	}

	// Write JSON output (always generated)
	if err := writeJSON(finalGraph, *outJSON); err != nil {
		log.Fatalf("JSON write error: %v", err)
	}
	log.Printf("• JSON file: %s", *outJSON)

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
