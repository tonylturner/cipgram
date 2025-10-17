package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
func (a *App) generateTraditionalNetworkDOT(graph *types.Graph, outputPath string) error {
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

	// Add protocol conversations between hosts
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "  // Protocol conversations from PCAP")
	for _, edge := range graph.Edges {
		// Skip unwanted IPs
		if a.shouldSkipIPForNetworkDiagram(edge.Src) || a.shouldSkipIPForNetworkDiagram(edge.Dst) {
			continue
		}

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
