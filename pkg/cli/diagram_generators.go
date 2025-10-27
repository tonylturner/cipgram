package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"cipgram/internal/output"
	"cipgram/pkg/types"
)

// generateTraditionalPurdueDOT creates a clean Purdue model like the reference image
func (a *App) generateTraditionalPurdueDOT(graph *types.Graph, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "digraph PurdueModel {")
	fmt.Fprintln(file, "  rankdir=TB;")
	fmt.Fprintln(file, "  ranksep=1.2;")
	fmt.Fprintln(file, "  nodesep=0.8;")
	fmt.Fprintln(file, "  node [fontname=\"Arial\", fontsize=10, width=2.0, height=0.8];")
	fmt.Fprintln(file, "  edge [fontname=\"Arial\", fontsize=9, penwidth=2];")
	fmt.Fprintln(file, "  bgcolor=\"white\";")
	fmt.Fprintln(file, "  pad=0.8;")
	fmt.Fprintln(file, "  dpi=150;")
	fmt.Fprintln(file, "")

	// Group hosts by Purdue level, filtering out unwanted addresses
	levelGroups := make(map[types.PurdueLevel][]*types.Host)
	for _, host := range graph.Hosts {
		// Filter out multicast, broadcast, and IPv6 for cleaner Purdue diagram
		if a.shouldSkipIPForNetworkDiagram(host.IP) {
			continue
		}

		level := host.InferredLevel
		if level == types.Unknown {
			level = types.L1 // Default unknown to L1
		}
		levelGroups[level] = append(levelGroups[level], host)
	}

	// Create clean Purdue levels with proper numbering like reference
	levels := []types.PurdueLevel{types.L4, types.L3, types.L2, types.L1, types.L0}
	levelNames := map[types.PurdueLevel]string{
		types.L4: "4    Enterprise",
		types.L3: "3    Operations Systems",
		types.L2: "2    Supervisory Control",
		types.L1: "1    Process Control",
		types.L0: "0    Physical Process",
	}
	levelColors := map[types.PurdueLevel]string{
		types.L4: "#4A90E2", // Professional blue
		types.L3: "#4A90E2", // Professional blue
		types.L2: "#4A90E2", // Professional blue
		types.L1: "#4A90E2", // Professional blue
		types.L0: "#4A90E2", // Professional blue
	}

	// Add invisible spine for proper ordering
	fmt.Fprintln(file, "  // Invisible spine for level ordering")
	fmt.Fprintln(file, "  spine_top [style=invis];")
	fmt.Fprintln(file, "  spine_l4 [style=invis];")
	fmt.Fprintln(file, "  spine_dmz [style=invis];") // Add DMZ spine
	fmt.Fprintln(file, "  spine_l3 [style=invis];")
	fmt.Fprintln(file, "  spine_l2 [style=invis];")
	fmt.Fprintln(file, "  spine_l1 [style=invis];")
	fmt.Fprintln(file, "  spine_l0 [style=invis];")
	fmt.Fprintln(file, "  spine_bottom [style=invis];")
	fmt.Fprintln(file, "  spine_top -> spine_l4 -> spine_dmz -> spine_l3 -> spine_l2 -> spine_l1 -> spine_l0 -> spine_bottom [style=invis];")
	fmt.Fprintln(file, "")

	// Level 4 - Enterprise (if devices exist)
	if hosts, exists := levelGroups[types.L4]; exists && len(hosts) > 0 {
		fmt.Fprintln(file, "  subgraph cluster_L4 {")
		fmt.Fprintln(file, "    label=\"4    Enterprise\";")
		fmt.Fprintln(file, "    style=\"filled,rounded\";")
		fmt.Fprintln(file, "    fillcolor=\"#4A90E2\";")
		fmt.Fprintln(file, "    fontcolor=\"white\";")
		fmt.Fprintln(file, "    fontsize=14;")
		fmt.Fprintln(file, "    fontname=\"Arial Bold\";")
		fmt.Fprintln(file, "    margin=12;")

		for j, host := range hosts {
			deviceLabel := fmt.Sprintf("%s\\n%s", host.IP, host.DeviceName)
			if host.Vendor != "" && !strings.Contains(host.Vendor, "Unknown") {
				deviceLabel += fmt.Sprintf("\\n%s", host.Vendor)
			}
			fmt.Fprintf(file, "    \"L4_%d\" [label=\"%s\", shape=box, style=\"filled,rounded\", fillcolor=\"white\", penwidth=1.5];\n",
				j, deviceLabel)
		}
		fmt.Fprintln(file, "  }")
		fmt.Fprintf(file, "  { rank=same; spine_l4;")
		for j := range hosts {
			fmt.Fprintf(file, " \"L4_%d\";", j)
		}
		fmt.Fprintln(file, " }")
	}

	// Level 3.5 - DMZ (always show as reference point)
	fmt.Fprintln(file, "  subgraph cluster_DMZ {")
	fmt.Fprintln(file, "    label=\"3.5  DMZ\";")
	fmt.Fprintln(file, "    style=\"filled,rounded\";")
	fmt.Fprintln(file, "    fillcolor=\"#E0E0E0\";")
	fmt.Fprintln(file, "    fontcolor=\"black\";")
	fmt.Fprintln(file, "    fontsize=14;")
	fmt.Fprintln(file, "    fontname=\"Arial Bold\";")
	fmt.Fprintln(file, "    margin=12;")
	fmt.Fprintln(file, "    dmz_placeholder [label=\"Firewall / Proxy\", shape=box, style=\"filled,rounded\", fillcolor=\"white\", penwidth=1.5];")
	fmt.Fprintln(file, "  }")
	fmt.Fprintln(file, "  { rank=same; spine_dmz; dmz_placeholder; }")
	fmt.Fprintln(file, "")

	// Remaining levels with actual PCAP devices
	for i, level := range levels {
		if hosts, exists := levelGroups[level]; exists && len(hosts) > 0 {
			fmt.Fprintf(file, "  subgraph cluster_L%d {\n", i)
			fmt.Fprintf(file, "    label=\"%s\";\n", levelNames[level])
			fmt.Fprintf(file, "    style=\"filled,rounded\";\n")
			fmt.Fprintf(file, "    fillcolor=\"%s\";\n", levelColors[level])
			fmt.Fprintf(file, "    fontcolor=\"white\";\n")
			fmt.Fprintf(file, "    fontsize=14;\n")
			fmt.Fprintf(file, "    fontname=\"Arial Bold\";\n")
			fmt.Fprintf(file, "    margin=12;\n")

			// Add actual devices from PCAP
			for j, host := range hosts {
				deviceLabel := fmt.Sprintf("%s\\n%s", host.IP, host.DeviceName)
				if host.Vendor != "" && !strings.Contains(host.Vendor, "Unknown") {
					deviceLabel += fmt.Sprintf("\\n%s", host.Vendor)
				}
				fmt.Fprintf(file, "    \"L%d_%d\" [label=\"%s\", shape=box, style=\"filled,rounded\", fillcolor=\"white\", penwidth=1.5];\n",
					i, j, deviceLabel)
			}

			fmt.Fprintln(file, "  }")

			// Force same rank
			spineNode := fmt.Sprintf("spine_l%d", 4-i)
			fmt.Fprintf(file, "  { rank=same; %s;", spineNode)
			for j := range hosts {
				fmt.Fprintf(file, " \"L%d_%d\";", i, j)
			}
			fmt.Fprintln(file, " }")
		}
	}

	fmt.Fprintln(file, "}")
	return nil
}

// generateTraditionalNetworkDOT creates traditional network topology with router/firewall center
func (a *App) generateTraditionalNetworkDOT(graph *types.Graph, outputPath string, model *types.NetworkModel) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "digraph NetworkTopology {")
	fmt.Fprintln(file, "  layout=fdp;") // Force-directed layout for traditional network
	fmt.Fprintln(file, "  node [fontname=\"Arial\", fontsize=10];")
	fmt.Fprintln(file, "  edge [fontname=\"Arial\", fontsize=9];")
	fmt.Fprintln(file, "  bgcolor=white;")
	fmt.Fprintln(file, "  overlap=false;")
	fmt.Fprintln(file, "  splines=true;")
	fmt.Fprintln(file, "  labelloc=\"b\";")  // Place legend at bottom
	fmt.Fprintln(file, "  labeljust=\"l\";") // Left justify legend
	fmt.Fprintln(file, "")

	// Central router/firewall node
	fmt.Fprintln(file, "  // Central Network Infrastructure")
	fmt.Fprintln(file, "  router [label=\"Network\\nRouter/Firewall\", shape=diamond, style=\"filled\", fillcolor=\"#ffcccc\"];")
	fmt.Fprintln(file, "")

	// Group hosts by network (inferred from IP ranges)
	networks := a.groupHostsByNetwork(graph)

	networkIndex := 0
	for networkCIDR, hosts := range networks {
		fmt.Fprintf(file, "  // Network: %s\n", networkCIDR)
		fmt.Fprintf(file, "  subgraph cluster_net%d {\n", networkIndex)
		fmt.Fprintf(file, "    label=\"Network %s\";\n", networkCIDR)
		fmt.Fprintln(file, "    style=\"filled,rounded\";")
		fmt.Fprintln(file, "    fillcolor=\"#f0f0f0\";")

		// Add hosts in this network
		for _, host := range hosts {
			deviceInfo := fmt.Sprintf("%s\\n%s", host.IP, host.DeviceName)
			if host.MAC != "" {
				deviceInfo += fmt.Sprintf("\\nMAC: %s", host.MAC)
			}
			if host.Vendor != "" {
				deviceInfo += fmt.Sprintf("\\n%s", host.Vendor)
			}

			fmt.Fprintf(file, "    \"%s\" [label=\"%s\", shape=box, style=\"filled,rounded\", fillcolor=\"white\"];\n",
				host.IP, deviceInfo)
		}

		fmt.Fprintln(file, "  }")

		// Connect network to router
		if len(hosts) > 0 {
			fmt.Fprintf(file, "  router -> \"%s\" [style=bold, color=\"#333333\"];\n", hosts[0].IP)
		}

		networkIndex++
	}

	// Add protocol conversations between hosts (intra-network connections)
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "  // Intra-network protocol conversations")
	for _, edge := range graph.Edges {
		// Skip unwanted IPs
		if a.shouldSkipIPForNetworkDiagram(edge.Src) || a.shouldSkipIPForNetworkDiagram(edge.Dst) {
			continue
		}

		// Check if this is an intra-network connection (same network)
		srcNetwork := a.getNetworkFromIP(edge.Src)
		dstNetwork := a.getNetworkFromIP(edge.Dst)

		if srcNetwork == dstNetwork {
			protocolLabel := string(edge.Protocol)
			edgeColor := "#666666"

			// Color code industrial protocols
			switch {
			case strings.Contains(protocolLabel, "ENIP"):
				edgeColor = "#00aa44"
				protocolLabel = "EtherNet/IP"
			case strings.Contains(protocolLabel, "Modbus"):
				edgeColor = "#ff8800"
			case strings.Contains(protocolLabel, "S7"):
				edgeColor = "#0066cc"
			case strings.Contains(protocolLabel, "OPC"):
				edgeColor = "#cc00cc"
			case strings.Contains(protocolLabel, "PROFINET"):
				edgeColor = "#9900cc"
			case strings.Contains(protocolLabel, "DNP3"):
				edgeColor = "#ff6600"
			}

			fmt.Fprintf(file, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\"];\n",
				edge.Src, edge.Dst, protocolLabel, edgeColor)
		}
	}

	// Add inter-network routing connections
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "  // Inter-network routing connections")
	routedConnections := make(map[string]bool) // Track unique network-to-network connections

	for _, edge := range graph.Edges {
		// Skip unwanted IPs
		if a.shouldSkipIPForNetworkDiagram(edge.Src) || a.shouldSkipIPForNetworkDiagram(edge.Dst) {
			continue
		}

		// Check if this is an inter-network connection (routed)
		srcNetwork := a.findNetworkForIP(edge.Src, model)
		dstNetwork := a.findNetworkForIP(edge.Dst, model)

		if srcNetwork != dstNetwork && srcNetwork != "Unknown" && dstNetwork != "Unknown" {
			// Create unique connection identifier
			connectionKey := fmt.Sprintf("%s->%s", srcNetwork, dstNetwork)
			reverseKey := fmt.Sprintf("%s->%s", dstNetwork, srcNetwork)

			// Avoid duplicate connections
			if !routedConnections[connectionKey] && !routedConnections[reverseKey] {
				routedConnections[connectionKey] = true

				protocolLabel := string(edge.Protocol)

				// Show routing through central router with thick red lines
				fmt.Fprintf(file, "  \"%s\" -> router [style=\"bold,dashed\", color=\"#ff0000\", penwidth=3, label=\"%s\"];\n",
					edge.Src, protocolLabel)
				fmt.Fprintf(file, "  router -> \"%s\" [style=\"bold,dashed\", color=\"#ff0000\", penwidth=3];\n",
					edge.Dst)
			}
		}
	}

	// Add legend explaining the diagram elements
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "  // Legend")
	fmt.Fprintln(file, "  subgraph cluster_legend {")
	fmt.Fprintln(file, "    label=\"\";") // Remove cluster title
	fmt.Fprintln(file, "    style=\"filled,rounded\";")
	fmt.Fprintln(file, "    fillcolor=\"#f9f9f9\";")
	fmt.Fprintln(file, "    fontsize=10;")
	fmt.Fprintln(file, "    fontname=\"Arial\";")
	fmt.Fprintln(file, "    margin=10;")
	fmt.Fprintln(file, "")

	// Line 1: "Node Types"
	fmt.Fprintln(file, "    legend_line1 [label=\"Node Types\", shape=plaintext, fontsize=11, fontname=\"Arial Bold\"];")
	fmt.Fprintln(file, "")

	// Line 2: Node types from left to right
	fmt.Fprintln(file, "    legend_router [label=\"Router/Firewall\", shape=diamond, style=\"filled\", fillcolor=\"#ffcccc\", fontsize=9];")
	fmt.Fprintln(file, "    legend_device [label=\"Network Device\", shape=box, style=\"filled,rounded\", fillcolor=\"white\", fontsize=9];")
	fmt.Fprintln(file, "    legend_network [label=\"Network Segment\", shape=box, style=\"filled,rounded\", fillcolor=\"#f0f0f0\", fontsize=9];")
	fmt.Fprintln(file, "")

	// Line 3: "Connection Types"
	fmt.Fprintln(file, "    legend_line3 [label=\"Connection Types\", shape=plaintext, fontsize=11, fontname=\"Arial Bold\"];")
	fmt.Fprintln(file, "")

	// Line 4: Intra-network traffic
	fmt.Fprintln(file, "    legend_intra_start [label=\"Intra-Network Traffic\", shape=plaintext, fontsize=9];")
	fmt.Fprintln(file, "    legend_intra_end [label=\"\", shape=plaintext, fontsize=9];")
	fmt.Fprintln(file, "    legend_intra_start -> legend_intra_end [color=\"#00aa44\", penwidth=2, label=\"\", dir=none];")
	fmt.Fprintln(file, "")

	// Line 5: Inter-network routing
	fmt.Fprintln(file, "    legend_routed_start [label=\"Inter-Network Routing\", shape=plaintext, fontsize=9];")
	fmt.Fprintln(file, "    legend_routed_end [label=\"\", shape=plaintext, fontsize=9];")
	fmt.Fprintln(file, "    legend_routed_start -> legend_routed_end [style=\"bold,dashed\", color=\"#ff0000\", penwidth=3, label=\"\", dir=none];")
	fmt.Fprintln(file, "")

	// Bottom left: "Legend"
	fmt.Fprintln(file, "    legend_title [label=\"Legend\", shape=plaintext, fontsize=10, fontname=\"Arial Bold\"];")
	fmt.Fprintln(file, "")

	// No protocol colors section - protocols are already labeled on the diagram

	// Arrange legend elements in exact vertical order
	fmt.Fprintln(file, "    // Legend layout - clean vertical structure")
	fmt.Fprintln(file, "    { rank=same; legend_line1; }")                                 // Line 1: "Node Types"
	fmt.Fprintln(file, "    { rank=same; legend_router; legend_device; legend_network; }") // Line 2: Node types left to right
	fmt.Fprintln(file, "    { rank=same; legend_line3; }")                                 // Line 3: "Connection Types"
	fmt.Fprintln(file, "    { rank=same; legend_intra_start; legend_intra_end; }")         // Line 4: Intra-network traffic
	fmt.Fprintln(file, "    { rank=same; legend_routed_start; legend_routed_end; }")       // Line 5: Inter-network routing
	fmt.Fprintln(file, "    { rank=same; legend_title; }")                                 // Bottom: "Legend"
	fmt.Fprintln(file, "  }")

	fmt.Fprintln(file, "}")
	return nil
}

// groupHostsByNetwork groups hosts into network segments based on IP ranges
func (a *App) groupHostsByNetwork(graph *types.Graph) map[string][]*types.Host {
	networks := make(map[string][]*types.Host)

	for _, host := range graph.Hosts {
		// Filter out multicast, broadcast, and IPv6 addresses
		if a.shouldSkipIPForNetworkDiagram(host.IP) {
			continue
		}

		// Simple network grouping by /24 subnet
		ipParts := strings.Split(host.IP, ".")
		if len(ipParts) >= 3 {
			networkCIDR := fmt.Sprintf("%s.%s.%s.0/24", ipParts[0], ipParts[1], ipParts[2])
			networks[networkCIDR] = append(networks[networkCIDR], host)
		}
	}

	return networks
}

// shouldSkipIPForNetworkDiagram filters out multicast, broadcast, and IPv6 addresses
func (a *App) shouldSkipIPForNetworkDiagram(ip string) bool {
	// Skip IPv6 addresses
	if strings.Contains(ip, ":") {
		return true
	}

	// Skip broadcast addresses
	if ip == "255.255.255.255" || strings.HasSuffix(ip, ".255") {
		return true
	}

	// Skip multicast addresses (224.0.0.0 to 239.255.255.255)
	ipParts := strings.Split(ip, ".")
	if len(ipParts) >= 1 {
		if firstOctet := ipParts[0]; firstOctet >= "224" && firstOctet <= "239" {
			return true
		}
	}

	// Skip other special addresses
	if ip == "0.0.0.0" || ip == "127.0.0.1" {
		return true
	}

	return false
}

// generateGraphJSON exports graph data as JSON
func (a *App) generateGraphJSON(graph *types.Graph, model *types.NetworkModel, outputPath string) error {
	// Create a serializable version of the data
	data := map[string]interface{}{
		"metadata": model.Metadata,
		"assets":   model.Assets,
		// Convert complex map types to arrays for JSON serialization
		"hosts":    convertHostsMapToArray(graph.Hosts),
		"edges":    convertEdgesMapToArray(graph.Edges),
		"flows":    convertFlowsMapToArray(model.Flows),
		"networks": model.Networks,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}

// Helper functions to convert maps to arrays for JSON serialization
func convertHostsMapToArray(hosts map[string]*types.Host) []map[string]interface{} {
	var result []map[string]interface{}
	for _, host := range hosts {
		result = append(result, map[string]interface{}{
			"ip":             host.IP,
			"mac":            host.MAC,
			"hostname":       host.Hostname,
			"device_name":    host.DeviceName,
			"vendor":         host.Vendor,
			"inferred_level": host.InferredLevel,
			"roles":          host.Roles,
		})
	}
	return result
}

func convertEdgesMapToArray(edges map[types.FlowKey]*types.Edge) []map[string]interface{} {
	var result []map[string]interface{}
	for _, edge := range edges {
		result = append(result, map[string]interface{}{
			"src":        edge.Src,
			"dst":        edge.Dst,
			"protocol":   edge.Protocol,
			"packets":    edge.Packets,
			"bytes":      edge.Bytes,
			"first_seen": edge.FirstSeen,
			"last_seen":  edge.LastSeen,
		})
	}
	return result
}

func convertFlowsMapToArray(flows map[types.FlowKey]*types.Flow) []map[string]interface{} {
	var result []map[string]interface{}
	for _, flow := range flows {
		result = append(result, map[string]interface{}{
			"source":      flow.Source,
			"destination": flow.Destination,
			"protocol":    flow.Protocol,
			"packets":     flow.Packets,
			"bytes":       flow.Bytes,
			"first_seen":  flow.FirstSeen,
			"last_seen":   flow.LastSeen,
			"allowed":     flow.Allowed,
		})
	}
	return result
}

// generateSVGFromDOT converts DOT file to SVG using Graphviz
func (a *App) generateSVGFromDOT(dotPath, svgPath string) error {
	cmd := exec.Command("dot", "-Tsvg", dotPath, "-o", svgPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("SVG generation failed (ensure Graphviz is installed): %v", err)
	}
	return nil
}

// generatePNGFromSVG converts DOT to PNG using Graphviz
func (a *App) generatePNGFromSVG(svgPath, pngPath string) error {
	// Generate PNG directly from DOT instead of SVG conversion for better quality
	dotPath := strings.Replace(svgPath, ".svg", ".dot", 1)
	cmd := exec.Command("dot", "-Tpng", dotPath, "-o", pngPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("PNG generation failed (ensure Graphviz is installed): %v", err)
	}
	return nil
}

// generateConversationCSV creates a CSV file listing all unique conversations
func (a *App) generateConversationCSV(model *types.NetworkModel, paths *output.OutputPaths) error {
	// Create data directory
	dataDir := filepath.Join(paths.ProjectRoot, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Create CSV file
	csvPath := filepath.Join(dataDir, "conversations.csv")
	file, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	header := []string{
		"Source IP",
		"Destination IP",
		"Protocol",
		"Port",
		"Packet Count",
		"Bytes",
		"Is Routed",
		"Source Network",
		"Destination Network",
		"First Seen",
		"Last Seen",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	// Process each flow as a conversation
	for _, flow := range model.Flows {
		// Skip filtered addresses
		if a.shouldSkipIPForNetworkDiagram(flow.Source) || a.shouldSkipIPForNetworkDiagram(flow.Destination) {
			continue
		}

		// Determine if conversation is routed (crosses network boundaries)
		isRouted := a.isRoutedConversation(flow.Source, flow.Destination, model)

		// Find source and destination networks
		srcNetwork := a.findNetworkForIP(flow.Source, model)
		dstNetwork := a.findNetworkForIP(flow.Destination, model)

		// Extract port from protocol or flow data
		port := a.extractPortFromFlow(flow)

		// Create CSV record
		record := []string{
			flow.Source,
			flow.Destination,
			string(flow.Protocol),
			port,
			strconv.FormatInt(int64(flow.Packets), 10),
			strconv.FormatInt(flow.Bytes, 10),
			strconv.FormatBool(isRouted),
			srcNetwork,
			dstNetwork,
			flow.FirstSeen.Format("2006-01-02 15:04:05"),
			flow.LastSeen.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %v", err)
		}
	}

	return nil
}

// isRoutedConversation determines if a conversation crosses network boundaries
func (a *App) isRoutedConversation(srcIP, dstIP string, model *types.NetworkModel) bool {
	srcNet := a.findNetworkForIP(srcIP, model)
	dstNet := a.findNetworkForIP(dstIP, model)

	// If IPs are in different networks, it's routed
	return srcNet != dstNet && srcNet != "Unknown" && dstNet != "Unknown"
}

// findNetworkForIP finds which network segment an IP belongs to
func (a *App) findNetworkForIP(ip string, model *types.NetworkModel) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "Unknown"
	}

	for networkID, network := range model.Networks {
		_, cidr, err := net.ParseCIDR(network.CIDR)
		if err != nil {
			continue
		}

		if cidr.Contains(parsedIP) {
			return networkID
		}
	}

	// Try to infer network from IP pattern if not found in defined networks
	if parsedIP.To4() != nil {
		// IPv4 - use /24 as default
		ip4 := parsedIP.To4()
		return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	}

	return "Unknown"
}

// extractPortFromFlow extracts port information from flow data
func (a *App) extractPortFromFlow(flow *types.Flow) string {
	// Check if we have port information in the flow
	if len(flow.Ports) > 0 {
		return strconv.Itoa(int(flow.Ports[0].Number))
	}

	// Try to infer from protocol
	protocol := strings.ToLower(string(flow.Protocol))
	switch {
	case strings.Contains(protocol, "http"):
		return "80"
	case strings.Contains(protocol, "https"):
		return "443"
	case strings.Contains(protocol, "ssh"):
		return "22"
	case strings.Contains(protocol, "ftp"):
		return "21"
	case strings.Contains(protocol, "telnet"):
		return "23"
	case strings.Contains(protocol, "smtp"):
		return "25"
	case strings.Contains(protocol, "dns"):
		return "53"
	case strings.Contains(protocol, "dhcp"):
		return "67"
	case strings.Contains(protocol, "snmp"):
		return "161"
	case strings.Contains(protocol, "modbus"):
		return "502"
	case strings.Contains(protocol, "enip") || strings.Contains(protocol, "ethernet/ip"):
		return "44818"
	case strings.Contains(protocol, "s7"):
		return "102"
	case strings.Contains(protocol, "opc"):
		return "4840"
	case strings.Contains(protocol, "dnp3"):
		return "20000"
	default:
		return "Unknown"
	}
}

// getNetworkFromIP returns the network segment for an IP address (simple /24 grouping)
func (a *App) getNetworkFromIP(ip string) string {
	ipParts := strings.Split(ip, ".")
	if len(ipParts) >= 3 {
		return fmt.Sprintf("%s.%s.%s.0/24", ipParts[0], ipParts[1], ipParts[2])
	}
	return "Unknown"
}

// getProtocolsInGraph extracts all unique protocols present in the graph edges
func (a *App) getProtocolsInGraph(graph *types.Graph) []string {
	protocolSet := make(map[string]bool)

	for _, edge := range graph.Edges {
		protocol := string(edge.Protocol)
		if protocol != "" {
			protocolSet[protocol] = true
		}
	}

	protocols := make([]string, 0, len(protocolSet))
	for protocol := range protocolSet {
		protocols = append(protocols, protocol)
	}

	sort.Strings(protocols)
	return protocols
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
