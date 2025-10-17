package diagram

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"cipgram/pkg/types"
)

// DiagramType represents different diagram layouts
type DiagramType string

const (
	PurdueDiagram  DiagramType = "purdue"
	NetworkDiagram DiagramType = "network"
)

func WriteDOT(g *types.Graph, path string, diagramType DiagramType) error {
	switch diagramType {
	case NetworkDiagram:
		return writeNetworkDOT(g, path)
	default:
		return writePurdueDOT(g, path)
	}
}

// writePurdueDOT creates a professional system-level Purdue model diagram for functional modeling
func writePurdueDOT(g *types.Graph, path string) error {
	// Group devices into functional systems instead of individual nodes
	systems := groupDevicesIntoSystems(g)

	var b strings.Builder
	w := bufio.NewWriter(&b)

	// Professional Purdue model with system-level view
	fmt.Fprintln(w, "digraph PurdueModel {")
	fmt.Fprintln(w, `  graph [rankdir=TB, splines=ortho, ranksep=3.0, nodesep=2.0, bgcolor=white, pad=0.5];`)
	fmt.Fprintln(w, `  node [shape=record, style="rounded,filled", fontname="Arial", fontsize=11];`)
	fmt.Fprintln(w, `  edge [fontname="Arial", fontsize=10, penwidth=2];`)
	fmt.Fprintln(w, "")

	// Level 4: Enterprise (if detected)
	if systems.Enterprise.HasSystems() {
		writeEnterpriseLevel(w, &systems.Enterprise)
	}

	// Level 3.5: DMZ (if detected)
	if systems.DMZ.HasSystems() {
		writeDMZLevel(w, &systems.DMZ)
	}

	// Level 3: Operations Systems
	if systems.Operations.HasSystems() {
		writeOperationsLevel(w, &systems.Operations)
	}

	// Level 2: Supervisory Control
	if systems.Supervisory.HasSystems() {
		writeSupervisoryLevel(w, &systems.Supervisory)
	}

	// Level 1: Process Control
	if systems.ProcessControl.HasSystems() {
		writeProcessControlLevel(w, &systems.ProcessControl)
	}

	// Level 0: Physical Process (if detected)
	if systems.Physical.HasSystems() {
		writePhysicalLevel(w, &systems.Physical)
	}

	// Add network separation lines
	writeNetworkSeparations(w, &systems)

	// Force vertical ordering with invisible edges between levels
	writeVerticalOrdering(w, &systems)

	// Write logical system connections with protocols
	writeSystemConnections(w, g, &systems)

	fmt.Fprintln(w, "}")
	w.Flush()
	return os.WriteFile(path, []byte(b.String()), 0644)
}

// writeNetworkDOT creates a network segmentation diagram for OT planning
func writeNetworkDOT(g *types.Graph, path string) error {
	// Create hierarchical network diagram similar to traditional topology
	return writeHierarchicalNetworkDOT(g, path)
}

// writeHierarchicalNetworkDOT creates a traditional hierarchical network diagram
func writeHierarchicalNetworkDOT(g *types.Graph, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	// Hierarchical network diagram header
	fmt.Fprintln(w, "digraph HierarchicalNetwork {")
	fmt.Fprintln(w, "  rankdir=TB;") // Top to bottom for hierarchy
	fmt.Fprintln(w, "  ranksep=1.5;")
	fmt.Fprintln(w, "  nodesep=1.0;")
	fmt.Fprintln(w, "  splines=ortho;")
	fmt.Fprintln(w, "  concentrate=false;")
	fmt.Fprintln(w, "  bgcolor=white;")
	fmt.Fprintln(w, "  node [fontname=\"Arial\", fontsize=10];")
	fmt.Fprintln(w, "  edge [fontname=\"Arial\", fontsize=9];")
	fmt.Fprintln(w, "")

	// Create hierarchical layers
	writeHierarchicalLayers(w, g)

	fmt.Fprintln(w, "}")
	return nil
}

// writeHierarchicalLayers creates a traditional network hierarchy
func writeHierarchicalLayers(w *bufio.Writer, g *types.Graph) {
	// Layer 1: Internet
	fmt.Fprintln(w, "  // Layer 1: Internet")
	fmt.Fprintln(w, "  subgraph cluster_internet {")
	fmt.Fprintln(w, "    rank=source;")
	fmt.Fprintln(w, "    label=\"Internet\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    fillcolor=\"#e6f3ff\";")
	fmt.Fprintln(w, "    internet [label=\"Internet\", shape=cloud, style=filled, fillcolor=\"white\"];")
	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")

	// Layer 2: Gateway Router (Layer 3 device)
	fmt.Fprintln(w, "  // Layer 2: Gateway Router")
	fmt.Fprintln(w, "  subgraph cluster_gateway {")
	fmt.Fprintln(w, "    rank=same;")
	fmt.Fprintln(w, "    label=\"Gateway Router\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    fillcolor=\"#fff2e6\";")

	// Find Cisco router if available (and exclude it from end devices later)
	var gatewayLabel = "Gateway Router\\n(Layer 3)"
	var ciscoRouterIP string
	for _, host := range g.Hosts {
		vendor := strings.ToLower(host.Vendor)
		if strings.Contains(vendor, "cisco") {
			gatewayLabel = fmt.Sprintf("Cisco Router\\n%s\\n(Layer 3)", host.IP)
			ciscoRouterIP = host.IP // Remember this IP to exclude from devices
			break
		}
	}

	fmt.Fprintf(w, "    gateway_router [label=\"%s\", shape=diamond, style=filled, fillcolor=\"#ffcc99\"];\n", gatewayLabel)
	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")

	// Identify network segments and classify them into layers
	segments := identifyNetworks(g)
	coreSegments, aggregationSegments, accessSegments := classifyNetworkLayers(segments)

	// Layer 3: Core Networks (represented as network clouds, not switches)
	if len(coreSegments) > 0 {
		fmt.Fprintln(w, "  // Layer 3: Core Networks")
		fmt.Fprintln(w, "  subgraph cluster_core {")
		fmt.Fprintln(w, "    rank=same;")
		fmt.Fprintln(w, "    label=\"Core Networks\";")
		fmt.Fprintln(w, "    style=filled;")
		fmt.Fprintln(w, "    fillcolor=\"#e6ffe6\";")

		for i, segment := range coreSegments {
			writeNetworkCloud(w, fmt.Sprintf("core_net%d", i), segment.CIDR, "#99ff99", segment)
		}
		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w, "")
	}

	// Layer 4: Aggregation Networks
	if len(aggregationSegments) > 0 {
		fmt.Fprintln(w, "  // Layer 4: Aggregation Networks")
		fmt.Fprintln(w, "  subgraph cluster_aggregation {")
		fmt.Fprintln(w, "    rank=same;")
		fmt.Fprintln(w, "    label=\"Aggregation Networks\";")
		fmt.Fprintln(w, "    style=filled;")
		fmt.Fprintln(w, "    fillcolor=\"#ffe6e6\";")

		for i, segment := range aggregationSegments {
			writeNetworkCloud(w, fmt.Sprintf("agg_net%d", i), segment.CIDR, "#ff9999", segment)
		}
		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w, "")
	}

	// Layer 5: Access Networks
	if len(accessSegments) > 0 {
		fmt.Fprintln(w, "  // Layer 5: Access Networks")
		fmt.Fprintln(w, "  subgraph cluster_access {")
		fmt.Fprintln(w, "    rank=same;")
		fmt.Fprintln(w, "    label=\"Access Networks\";")
		fmt.Fprintln(w, "    style=filled;")
		fmt.Fprintln(w, "    fillcolor=\"#f0f0ff\";")

		for i, segment := range accessSegments {
			writeNetworkCloud(w, fmt.Sprintf("access_net%d", i), segment.CIDR, "#ccccff", segment)
		}
		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w, "")
	}

	// Layer 6: Computing Servers/Devices (connected to their respective networks)
	fmt.Fprintln(w, "  // Layer 6: Computing Servers/Devices")
	fmt.Fprintln(w, "  subgraph cluster_devices {")
	fmt.Fprintln(w, "    rank=sink;")
	fmt.Fprintln(w, "    label=\"Computing Servers\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    fillcolor=\"#f5f5f5\";")

	// Group devices by segment and show key devices with full IPs (excluding the gateway router)
	writeHierarchicalDevicesWithFullIPs(w, segments, ciscoRouterIP)

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")

	// Write connections between layers (Router to Networks to Devices)
	writeHierarchicalNetworkConnections(w, coreSegments, aggregationSegments, accessSegments, ciscoRouterIP)

	// Add legend for device shapes
	writeShapeLegend(w)
}

// classifyNetworkLayers classifies network segments into core, aggregation, and access layers
func classifyNetworkLayers(segments []NetworkSegment) (core, aggregation, access []NetworkSegment) {
	for _, segment := range segments {
		// Classify based on network characteristics
		if len(segment.Hosts) >= 10 || hasServerDevices(segment.Hosts) {
			core = append(core, segment)
		} else if len(segment.Hosts) >= 5 || hasOTDevices(segment.Hosts) {
			aggregation = append(aggregation, segment)
		} else {
			access = append(access, segment)
		}
	}
	return
}

// hasServerDevices checks if segment contains server-like devices
func hasServerDevices(hosts []*types.Host) bool {
	for _, host := range hosts {
		for _, role := range host.Roles {
			if strings.Contains(strings.ToLower(role), "server") ||
				strings.Contains(strings.ToLower(role), "workstation") {
				return true
			}
		}
	}
	return false
}

// hasOTDevices checks if segment contains OT/industrial devices
func hasOTDevices(hosts []*types.Host) bool {
	for _, host := range hosts {
		if host.ICSScore > 0 || host.InferredLevel != types.Unknown {
			return true
		}
	}
	return false
}

// writeNetworkCloud writes a network cloud node with OT/IT classification
func writeNetworkCloud(w *bufio.Writer, networkID, cidr, color string, segment NetworkSegment) {
	// Determine network function based on protocols and devices
	var networkLabel string
	var protocols []string

	// Analyze protocols in this network more carefully
	protocolCounts := make(map[string]int)

	for _, host := range segment.Hosts {
		// Check initiated protocols
		for protocol, count := range host.InitiatedCounts {
			if count > 0 {
				protocolCounts[string(protocol)]++
			}
		}
		// Check received protocols
		for protocol, count := range host.ReceivedCounts {
			if count > 0 {
				protocolCounts[string(protocol)]++
			}
		}
	}

	// Only include protocols that are actually present with meaningful activity
	if protocolCounts["ENIP-TCP-44818"] > 0 || protocolCounts["ENIP-UDP-2222"] > 0 {
		protocols = append(protocols, "EtherNet/IP")
	}
	if protocolCounts["Modbus-TCP-502"] > 0 {
		protocols = append(protocols, "Modbus")
	}
	if protocolCounts["OPC-UA-TCP-4840"] > 0 {
		protocols = append(protocols, "OPC-UA")
	}
	if protocolCounts["S7Comm-TCP-102"] > 0 {
		protocols = append(protocols, "S7")
	}

	// Create network label with function
	if len(protocols) > 0 {
		networkLabel = fmt.Sprintf("%s Network\\n%s\\n%s", segment.Type, cidr, strings.Join(protocols, ", "))
	} else {
		networkLabel = fmt.Sprintf("%s Network\\n%s", segment.Type, cidr)
	}

	fmt.Fprintf(w, "    %s [label=\"%s\", shape=ellipse, style=filled, fillcolor=\"%s\"];\n",
		networkID, networkLabel, color)
}

// writeHierarchicalDevicesWithFullIPs writes device nodes with full IP addresses (excluding gateway router)
func writeHierarchicalDevicesWithFullIPs(w *bufio.Writer, segments []NetworkSegment, excludeIP string) {
	deviceCount := 0
	for _, segment := range segments {
		// Show key devices from each segment
		keyDevices := getKeyDevicesFromSegment(segment.Hosts, 3) // Max 3 devices per segment

		for _, host := range keyDevices {
			// Skip the gateway router device to avoid duplication
			if host.IP == excludeIP {
				continue
			}

			deviceID := fmt.Sprintf("device_%d", deviceCount)
			deviceCount++

			// Determine device shape and color based on type
			shape, color := getDeviceAppearance(host)
			label := buildFullIPDeviceLabel(host)

			fmt.Fprintf(w, "    %s [label=\"%s\", shape=%s, style=filled, fillcolor=\"%s\"];\n",
				deviceID, label, shape, color)
		}
	}
}

// writeHierarchicalNetworkConnections writes proper Layer 3 connections with correct IP matching
func writeHierarchicalNetworkConnections(w *bufio.Writer, core, aggregation, access []NetworkSegment, excludeIP string) {
	fmt.Fprintln(w, "  // Hierarchical network connections")

	// Internet -> Gateway Router
	fmt.Fprintln(w, "  internet -> gateway_router [label=\"WAN\"];")

	// Gateway Router -> Networks (Layer 3 routing)
	if len(core) > 0 {
		for i := range core {
			fmt.Fprintf(w, "  gateway_router -> core_net%d [label=\"Route\"];\n", i)
		}
	}

	for i := range aggregation {
		fmt.Fprintf(w, "  gateway_router -> agg_net%d [label=\"Route\"];\n", i)
	}

	for i := range access {
		fmt.Fprintf(w, "  gateway_router -> access_net%d [label=\"Route\"];\n", i)
	}

	// Networks -> Devices (devices connected to their CORRECT networks by IP)
	allSegments := append(append(core, aggregation...), access...)

	for segIdx, segment := range allSegments {
		// Determine network type and ID
		var networkID string
		if segIdx < len(core) {
			networkID = fmt.Sprintf("core_net%d", segIdx)
		} else if segIdx < len(core)+len(aggregation) {
			networkID = fmt.Sprintf("agg_net%d", segIdx-len(core))
		} else {
			networkID = fmt.Sprintf("access_net%d", segIdx-len(core)-len(aggregation))
		}

		// Connect devices to their network (find device by IP in all segments)
		deviceCount := 0
		for _, targetSegment := range allSegments {
			targetDevices := getKeyDevicesFromSegment(targetSegment.Hosts, 3)
			for _, device := range targetDevices {
				// Skip the gateway router device to avoid duplication
				if device.IP == excludeIP {
					deviceCount++
					continue
				}

				// Check if this device belongs to current network segment
				if deviceBelongsToNetwork(device.IP, segment.CIDR) {
					fmt.Fprintf(w, "  %s -> device_%d [label=\"types.L2\"];\n", networkID, deviceCount)
				}
				deviceCount++
			}
		}
	}
}

// deviceBelongsToNetwork checks if an IP address belongs to a CIDR network
func deviceBelongsToNetwork(ip, cidr string) bool {
	// Parse the network CIDR
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Parse the IP address
	deviceIP := net.ParseIP(ip)
	if deviceIP == nil {
		return false
	}

	// Check if IP is in the network
	return network.Contains(deviceIP)
}

// buildFullIPDeviceLabel creates a label with full IP address for devices
func buildFullIPDeviceLabel(host *types.Host) string {
	var parts []string

	// Full IP address (not truncated)
	parts = append(parts, host.IP)

	// Vendor or role
	if host.Vendor != "" {
		vendor := host.Vendor
		if len(vendor) > 12 {
			vendor = vendor[:12] + "..."
		}
		parts = append(parts, vendor)
	} else if len(host.Roles) > 0 {
		role := host.Roles[0]
		if len(role) > 12 {
			role = role[:12] + "..."
		}
		parts = append(parts, role)
	}

	return strings.Join(parts, "\\n")
}

// getKeyDevicesFromSegment returns the most important devices from a segment
func getKeyDevicesFromSegment(hosts []*types.Host, maxDevices int) []*types.Host {
	// Return ALL devices if we have few enough, don't artificially limit for small networks
	if len(hosts) <= 10 { // Increased from maxDevices to show more assets
		return hosts
	}

	// Sort by importance (ICS score, roles, etc.)
	sortedHosts := make([]*types.Host, len(hosts))
	copy(sortedHosts, hosts)

	sort.Slice(sortedHosts, func(i, j int) bool {
		scoreI := sortedHosts[i].ICSScore*10 + len(sortedHosts[i].Roles)*5
		scoreJ := sortedHosts[j].ICSScore*10 + len(sortedHosts[j].Roles)*5
		return scoreI > scoreJ
	})

	// Return more devices to show better network coverage
	maxToShow := maxDevices * 2 // Double the limit to show more assets
	if maxToShow > len(sortedHosts) {
		maxToShow = len(sortedHosts)
	}

	return sortedHosts[:maxToShow]
}

// getDeviceAppearance returns shape and color for a device based on its characteristics
func getDeviceAppearance(host *types.Host) (shape, color string) {
	// Check for specific vendors/devices
	vendor := strings.ToLower(host.Vendor)
	if strings.Contains(vendor, "cisco") {
		return "diamond", "#ffdddd"
	}
	if strings.Contains(vendor, "moxa") {
		return "hexagon", "#ddffdd"
	}

	// Check roles
	for _, role := range host.Roles {
		roleLower := strings.ToLower(role)
		if strings.Contains(roleLower, "server") {
			return "box", "#ddddff"
		}
		if strings.Contains(roleLower, "plc") || strings.Contains(roleLower, "controller") {
			return "octagon", "#ffddff"
		}
		if strings.Contains(roleLower, "hmi") || strings.Contains(roleLower, "workstation") {
			return "ellipse", "#ffffdd"
		}
	}

	// Default based on Purdue level
	switch host.InferredLevel {
	case types.L1:
		return "box", "#ccffcc"
	case types.L2:
		return "ellipse", "#ffcccc"
	case types.L3:
		return "diamond", "#ccccff"
	default:
		return "circle", "#f0f0f0"
	}
}

// buildHierarchicalDeviceLabel creates a label for devices in the hierarchical view
func buildHierarchicalDeviceLabel(host *types.Host) string {
	var parts []string

	// IP address (last octet for space)
	ipParts := strings.Split(host.IP, ".")
	if len(ipParts) == 4 {
		parts = append(parts, "..."+ipParts[3])
	} else {
		parts = append(parts, host.IP)
	}

	// Vendor or role
	if host.Vendor != "" {
		vendor := host.Vendor
		if len(vendor) > 8 {
			vendor = vendor[:8] + "..."
		}
		parts = append(parts, vendor)
	} else if len(host.Roles) > 0 {
		role := host.Roles[0]
		if len(role) > 8 {
			role = role[:8] + "..."
		}
		parts = append(parts, role)
	}

	return strings.Join(parts, "\\n")
}

// buildAssetLabel creates comprehensive asset labels with full IP and MAC
func buildAssetLabel(host *types.Host, fullDetails bool) string {
	var parts []string

	// Primary identifier
	if host.Hostname != "" {
		parts = append(parts, host.Hostname)
	} else if host.DeviceName != "" {
		parts = append(parts, host.DeviceName)
	} else {
		parts = append(parts, "Device")
	}

	// Always show full IP address
	parts = append(parts, host.IP)

	// Add MAC address if known
	if host.MAC != "" && fullDetails {
		// Show first 6 chars of MAC for space efficiency
		shortMAC := strings.ReplaceAll(host.MAC[:8], ":", "")
		parts = append(parts, "MAC: "+shortMAC+"...")
	}

	// Add vendor info
	if host.Vendor != "" {
		vendor := host.Vendor
		if len(vendor) > 12 {
			vendor = vendor[:12] + "..."
		}
		parts = append(parts, "["+vendor+"]")
	}

	// Add primary role
	if len(host.Roles) > 0 {
		role := host.Roles[0]
		// Simplify role names for display
		role = strings.ReplaceAll(role, "Engineering Station", "ENG")
		role = strings.ReplaceAll(role, "I/O Adapter/Drive", "I/O")
		role = strings.ReplaceAll(role, "Server/Workstation", "Server")
		parts = append(parts, "("+role+")")
	}

	return strings.Join(parts, "\\n")
}

// writeFunctionalFlows writes protocol flows for functional modeling
func writeFunctionalFlows(w *bufio.Writer, g *types.Graph) {
	fmt.Fprintln(w, "  // Functional Protocol Flows")

	processedPairs := make(map[string]bool)

	for _, e := range g.Edges {
		srcHost := g.Hosts[e.Src]
		dstHost := g.Hosts[e.Dst]

		// Skip unknown devices in Purdue diagram
		if srcHost.InferredLevel == types.Unknown || dstHost.InferredLevel == types.Unknown {
			continue
		}

		// Avoid duplicate bidirectional edges
		pairKey := e.Src + "<->" + e.Dst
		reversePairKey := e.Dst + "<->" + e.Src
		if processedPairs[pairKey] || processedPairs[reversePairKey] {
			continue
		}
		processedPairs[pairKey] = true

		// Show key industrial protocols only
		protocolName := string(e.Protocol)
		var edgeColor, label string

		switch {
		case strings.Contains(protocolName, "ENIP"):
			edgeColor = "#00aa44"
			label = "EtherNet/IP"
		case strings.Contains(protocolName, "Modbus"):
			edgeColor = "#ff8800"
			label = "Modbus"
		case strings.Contains(protocolName, "S7"):
			edgeColor = "#0066cc"
			label = "S7"
		case strings.Contains(protocolName, "OPC"):
			edgeColor = "#cc00cc"
			label = "OPC"
		default:
			continue // Skip non-industrial protocols
		}

		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\"];\n",
			e.Src, e.Dst, label, edgeColor)
	}
}

// SystemGroups represents the logical grouping of devices into functional systems
type SystemGroups struct {
	Enterprise     PurdueSystemLevel
	DMZ            PurdueSystemLevel
	Operations     PurdueSystemLevel
	Supervisory    PurdueSystemLevel
	ProcessControl PurdueSystemLevel
	Physical       PurdueSystemLevel
}

// PurdueSystemLevel represents a level in the Purdue model with functional systems
type PurdueSystemLevel struct {
	Databases    []SystemGroup
	Gateways     []SystemGroup
	Servers      []SystemGroup
	Clients      []SystemGroup
	Controllers  []SystemGroup
	Modules      []SystemGroup
	FieldDevices []SystemGroup
}

// SystemGroup represents a functional system (like "Local Ignition Server" or "SQL DB")
type SystemGroup struct {
	Name    string
	Type    string
	Devices []*types.Host
	Color   string
	Icon    string
}

// HasSystems returns true if this level has any systems
func (level *PurdueSystemLevel) HasSystems() bool {
	return len(level.Databases) > 0 || len(level.Gateways) > 0 ||
		len(level.Servers) > 0 || len(level.Clients) > 0 ||
		len(level.Controllers) > 0 || len(level.Modules) > 0 ||
		len(level.FieldDevices) > 0
}

// groupDevicesIntoSystems analyzes the network and groups devices into functional systems
func groupDevicesIntoSystems(g *types.Graph) SystemGroups {
	systems := SystemGroups{}

	for _, host := range g.Hosts {
		system := classifySystemType(host)
		level := determinePurdueLevel(host)

		switch level {
		case "Enterprise":
			addSystemToLevel(&systems.Enterprise, system)
		case "DMZ":
			addSystemToLevel(&systems.DMZ, system)
		case "Operations":
			addSystemToLevel(&systems.Operations, system)
		case "Supervisory":
			addSystemToLevel(&systems.Supervisory, system)
		case "ProcessControl":
			addSystemToLevel(&systems.ProcessControl, system)
		case "Physical":
			addSystemToLevel(&systems.Physical, system)
		}
	}

	return systems
}

// classifySystemType determines what type of system a device represents
func classifySystemType(host *types.Host) SystemGroup {
	vendor := strings.ToLower(host.Vendor)
	deviceName := strings.ToLower(host.DeviceName)
	hostname := strings.ToLower(host.Hostname)

	// Database systems
	if strings.Contains(vendor, "sql") || strings.Contains(deviceName, "database") ||
		strings.Contains(hostname, "db") || strings.Contains(hostname, "sql") {
		return SystemGroup{
			Name:    "SQL Database",
			Type:    "database",
			Devices: []*types.Host{host},
			Color:   "#f0f8ff",
			Icon:    "database",
		}
	}

	// HMI/Client systems
	if strings.Contains(vendor, "vmware") || strings.Contains(deviceName, "client") ||
		strings.Contains(hostname, "hmi") || strings.Contains(hostname, "client") {
		return SystemGroup{
			Name:    "HMI Client",
			Type:    "client",
			Devices: []*types.Host{host},
			Color:   "#fff8e1",
			Icon:    "desktop",
		}
	}

	// Server systems
	if strings.Contains(vendor, "server") || strings.Contains(deviceName, "server") ||
		strings.Contains(hostname, "server") || strings.Contains(vendor, "lantronix") {
		return SystemGroup{
			Name:    "Ignition Server",
			Type:    "server",
			Devices: []*types.Host{host},
			Color:   "#e8f5e8",
			Icon:    "server",
		}
	}

	// PLC/Controller systems
	if strings.Contains(vendor, "rockwell") || strings.Contains(deviceName, "plc") ||
		strings.Contains(hostname, "plc") || host.ICSScore > 50 {
		return SystemGroup{
			Name:    "Allen-Bradley PLC",
			Type:    "controller",
			Devices: []*types.Host{host},
			Color:   "#fff3e0",
			Icon:    "controller",
		}
	}

	// Gateway/Router systems
	if strings.Contains(vendor, "cisco") || strings.Contains(deviceName, "router") ||
		strings.Contains(hostname, "gateway") || strings.Contains(hostname, "router") {
		return SystemGroup{
			Name:    "Industrial Gateway",
			Type:    "gateway",
			Devices: []*types.Host{host},
			Color:   "#e3f2fd",
			Icon:    "router",
		}
	}

	// Default field device
	return SystemGroup{
		Name:    "Field Device",
		Type:    "field",
		Devices: []*types.Host{host},
		Color:   "#f9f9f9",
		Icon:    "device",
	}
}

// determinePurdueLevel maps a host to the appropriate Purdue level
func determinePurdueLevel(host *types.Host) string {
	// Use existing classification if available
	switch host.InferredLevel {
	case types.L3:
		return "Operations"
	case types.L2:
		return "Supervisory"
	case types.L1:
		return "ProcessControl"
	default:
		// Enhanced classification based on vendor and role
		vendor := strings.ToLower(host.Vendor)

		if strings.Contains(vendor, "vmware") || strings.Contains(vendor, "sql") {
			return "Operations"
		}
		if strings.Contains(vendor, "rockwell") && host.ICSScore > 30 {
			return "Supervisory"
		}
		if strings.Contains(vendor, "rockwell") || host.ICSScore > 0 {
			return "ProcessControl"
		}

		return "ProcessControl"
	}
}

// addSystemToLevel adds a system to the appropriate level category
func addSystemToLevel(level *PurdueSystemLevel, system SystemGroup) {
	switch system.Type {
	case "database":
		level.Databases = append(level.Databases, system)
	case "gateway":
		level.Gateways = append(level.Gateways, system)
	case "server":
		level.Servers = append(level.Servers, system)
	case "client":
		level.Clients = append(level.Clients, system)
	case "controller":
		level.Controllers = append(level.Controllers, system)
	default:
		level.FieldDevices = append(level.FieldDevices, system)
	}
}

// writeEnterpriseLevel writes the Enterprise level (Level 4) systems
func writeEnterpriseLevel(w *bufio.Writer, level *PurdueSystemLevel) {
	fmt.Fprintln(w, "  // Level 4: Enterprise")
	fmt.Fprintln(w, "  subgraph cluster_enterprise {")
	fmt.Fprintln(w, "    rank=source;")
	fmt.Fprintln(w, "    label=\"Enterprise\\nWorkforce Management | Order Management | Inventory Management\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#e6f3ff\";")
	fmt.Fprintln(w, "    color=\"#0066cc\";")
	fmt.Fprintln(w, "    penwidth=3;")
	fmt.Fprintln(w, "    fontsize=12;")

	writeSystemsInLevel(w, level, "enterprise")

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// writeDMZLevel writes the DMZ level (Level 3.5) systems
func writeDMZLevel(w *bufio.Writer, level *PurdueSystemLevel) {
	fmt.Fprintln(w, "  // Level 3.5: DMZ")
	fmt.Fprintln(w, "  subgraph cluster_dmz {")
	fmt.Fprintln(w, "    rank=1;")
	fmt.Fprintln(w, "    label=\"DMZ\\nProxy | Firewall | Separation of Networks\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#f5f5f5\";")
	fmt.Fprintln(w, "    color=\"#666666\";")
	fmt.Fprintln(w, "    penwidth=2;")
	fmt.Fprintln(w, "    fontsize=11;")

	writeSystemsInLevel(w, level, "dmz")

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// writeOperationsLevel writes the Operations level (Level 3) systems
func writeOperationsLevel(w *bufio.Writer, level *PurdueSystemLevel) {
	fmt.Fprintln(w, "  // Level 3: Operations Systems")
	fmt.Fprintln(w, "  subgraph cluster_operations {")
	fmt.Fprintln(w, "    label=\"Operations Systems\\nMES | Scheduling | OEE | Quality Management\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#e6f3ff\";")
	fmt.Fprintln(w, "    color=\"#0066cc\";")
	fmt.Fprintln(w, "    penwidth=3;")
	fmt.Fprintln(w, "    fontsize=12;")

	writeSystemsInLevel(w, level, "operations")

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// writeSupervisoryLevel writes the Supervisory Control level (Level 2) systems
func writeSupervisoryLevel(w *bufio.Writer, level *PurdueSystemLevel) {
	fmt.Fprintln(w, "  // Level 2: Supervisory Control")
	fmt.Fprintln(w, "  subgraph cluster_supervisory {")
	fmt.Fprintln(w, "    label=\"Supervisory Control\\nSCADA | HMI | Alarming | Reporting | Trending\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#fff2e6\";")
	fmt.Fprintln(w, "    color=\"#ff8800\";")
	fmt.Fprintln(w, "    penwidth=3;")
	fmt.Fprintln(w, "    fontsize=12;")

	writeSystemsInLevel(w, level, "supervisory")

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// writeProcessControlLevel writes the Process Control level (Level 1) systems
func writeProcessControlLevel(w *bufio.Writer, level *PurdueSystemLevel) {
	fmt.Fprintln(w, "  // Level 1: Process Control")
	fmt.Fprintln(w, "  subgraph cluster_process {")
	fmt.Fprintln(w, "    label=\"Process Control\\nPLCs | RTUs\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#e8f6e8\";")
	fmt.Fprintln(w, "    color=\"#00aa44\";")
	fmt.Fprintln(w, "    penwidth=3;")
	fmt.Fprintln(w, "    fontsize=12;")

	writeSystemsInLevel(w, level, "process")

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// writePhysicalLevel writes the Physical Process level (Level 0) systems
func writePhysicalLevel(w *bufio.Writer, level *PurdueSystemLevel) {
	fmt.Fprintln(w, "  // Level 0: Physical Process")
	fmt.Fprintln(w, "  subgraph cluster_physical {")
	fmt.Fprintln(w, "    rank=sink;")
	fmt.Fprintln(w, "    label=\"Physical Process\\nSensors | Actuators\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#f0f0f0\";")
	fmt.Fprintln(w, "    color=\"#888888\";")
	fmt.Fprintln(w, "    penwidth=2;")
	fmt.Fprintln(w, "    fontsize=11;")

	writeSystemsInLevel(w, level, "physical")

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// writeSystemsInLevel writes all systems within a Purdue level
func writeSystemsInLevel(w *bufio.Writer, level *PurdueSystemLevel, levelName string) {
	// Write databases
	for i, system := range level.Databases {
		nodeID := fmt.Sprintf("%s_db_%d", levelName, i)
		fmt.Fprintf(w, "    %s [label=\"%s\", shape=cylinder, style=filled, fillcolor=\"%s\"];\n",
			nodeID, system.Name, system.Color)
	}

	// Write gateways
	for i, system := range level.Gateways {
		nodeID := fmt.Sprintf("%s_gw_%d", levelName, i)
		fmt.Fprintf(w, "    %s [label=\"%s\", shape=house, style=filled, fillcolor=\"%s\"];\n",
			nodeID, system.Name, system.Color)
	}

	// Write servers
	for i, system := range level.Servers {
		nodeID := fmt.Sprintf("%s_srv_%d", levelName, i)
		fmt.Fprintf(w, "    %s [label=\"%s\", shape=rect, style=\"rounded,filled\", fillcolor=\"%s\"];\n",
			nodeID, system.Name, system.Color)
	}

	// Write clients
	for i, system := range level.Clients {
		nodeID := fmt.Sprintf("%s_cli_%d", levelName, i)
		fmt.Fprintf(w, "    %s [label=\"%s\", shape=rect, style=\"rounded,filled\", fillcolor=\"%s\"];\n",
			nodeID, system.Name, system.Color)
	}

	// Write controllers
	for i, system := range level.Controllers {
		nodeID := fmt.Sprintf("%s_ctrl_%d", levelName, i)
		fmt.Fprintf(w, "    %s [label=\"%s\", shape=rect, style=\"rounded,filled\", fillcolor=\"%s\"];\n",
			nodeID, system.Name, system.Color)
	}

	// Write field devices
	for i, system := range level.FieldDevices {
		nodeID := fmt.Sprintf("%s_field_%d", levelName, i)
		fmt.Fprintf(w, "    %s [label=\"%s\", shape=oval, style=filled, fillcolor=\"%s\"];\n",
			nodeID, system.Name, system.Color)
	}
}

// writeNetworkSeparations draws network separation lines between levels
func writeNetworkSeparations(w *bufio.Writer, systems *SystemGroups) {
	// Add visible separation lines if needed
	fmt.Fprintln(w, "  // Network Separations")

	if systems.Enterprise.HasSystems() && systems.DMZ.HasSystems() {
		fmt.Fprintln(w, "  firewall1 [label=\"Firewall\", shape=diamond, style=filled, fillcolor=\"#ffcccc\"];")
	}

	if systems.Operations.HasSystems() && systems.Supervisory.HasSystems() {
		fmt.Fprintln(w, "  firewall2 [label=\"Industrial Firewall\", shape=diamond, style=filled, fillcolor=\"#ffcccc\"];")
	}

	fmt.Fprintln(w, "")
}

// writeSystemConnections draws logical connections between systems
func writeSystemConnections(w *bufio.Writer, g *types.Graph, systems *SystemGroups) {
	fmt.Fprintln(w, "  // System Connections")

	// For now, keep simplified protocol connections
	// This would be enhanced to show system-to-system flows
	processedPairs := make(map[string]bool)

	for _, e := range g.Edges {
		srcHost := g.Hosts[e.Src]
		dstHost := g.Hosts[e.Dst]

		// Skip unknown devices
		if srcHost.InferredLevel == types.Unknown || dstHost.InferredLevel == types.Unknown {
			continue
		}

		// Avoid duplicate bidirectional edges
		pairKey := e.Src + "<->" + e.Dst
		reversePairKey := e.Dst + "<->" + e.Src
		if processedPairs[pairKey] || processedPairs[reversePairKey] {
			continue
		}
		processedPairs[pairKey] = true

		// Show key industrial protocols only
		protocolName := string(e.Protocol)
		var edgeColor, label string

		switch {
		case strings.Contains(protocolName, "ENIP"):
			edgeColor = "#00aa44"
			label = "EtherNet/IP"
		case strings.Contains(protocolName, "Modbus"):
			edgeColor = "#ff8800"
			label = "Modbus"
		case strings.Contains(protocolName, "S7"):
			edgeColor = "#0066cc"
			label = "S7"
		case strings.Contains(protocolName, "OPC"):
			edgeColor = "#cc00cc"
			label = "OPC"
		default:
			continue // Skip non-industrial protocols
		}

		// Map IPs to system IDs (simplified approach)
		srcLevel := mapHostToLevelName(srcHost)
		dstLevel := mapHostToLevelName(dstHost)

		if srcLevel != "" && dstLevel != "" {
			fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\", fontsize=9];\n",
				e.Src, e.Dst, label, edgeColor)
		}
	}
}

// mapHostToLevelName maps a host to its level name for connections
func mapHostToLevelName(host *types.Host) string {
	switch host.InferredLevel {
	case types.L3:
		return "operations"
	case types.L2:
		return "supervisory"
	case types.L1:
		return "process"
	default:
		return ""
	}
}

// writeVerticalOrdering forces vertical ordering with rank constraints
func writeVerticalOrdering(w *bufio.Writer, systems *SystemGroups) {
	fmt.Fprintln(w, "  // Force vertical ordering with rank constraints")

	// Use rank constraints to force vertical layout
	if systems.Operations.HasSystems() {
		fmt.Fprintln(w, "  { rank=min; operations_srv_0; }")
	}
	if systems.Supervisory.HasSystems() && systems.ProcessControl.HasSystems() {
		fmt.Fprintln(w, "  { rank=max; process_ctrl_0; }")
	}

	fmt.Fprintln(w, "")
}

// Network identification and segmentation structures
type NetworkSegment struct {
	CIDR  string
	Hosts []*types.Host
	Type  string // "OT", "IT", "DMZ"
	Level types.PurdueLevel
}

// identifyNetworks groups hosts into network segments (IPv4 only, valid networks)
func identifyNetworks(g *types.Graph) []NetworkSegment {
	networks := make(map[string]*NetworkSegment)

	for _, host := range g.Hosts {
		// Skip external/public IPs that shouldn't be in network diagrams
		if isExternalIP(host.IP) {
			continue
		}

		cidr := inferNetworkCIDR(host.IP)
		if cidr == "" {
			continue // Skip IPv6, broadcast, and invalid networks
		}

		if networks[cidr] == nil {
			networks[cidr] = &NetworkSegment{
				CIDR:  cidr,
				Hosts: []*types.Host{},
				Type:  "",
			}
		}

		networks[cidr].Hosts = append(networks[cidr].Hosts, host)
	}

	// Only return networks with actual hosts and classify properly
	var result []NetworkSegment
	for _, net := range networks {
		if len(net.Hosts) > 0 {
			// Classify network based on ALL hosts, not just the last one
			net.Type = classifyNetworkType(net.Hosts)

			// Set Purdue level based on dominant device types
			net.Level = inferNetworkPurdueLevel(net.Hosts)

			result = append(result, *net)
		}
	}

	return result
}

// isExternalIP checks if an IP is external/public and should be filtered from network diagrams
func isExternalIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true // Skip malformed IPs
	}

	// Filter out external/public IPs
	if (parts[0] == "1" && parts[1] == "1" && parts[2] == "1") || // 1.1.1.1 DNS
		(parts[0] == "8" && parts[1] == "8" && parts[2] == "8") || // 8.8.8.8 DNS
		(parts[0] == "208" && parts[1] == "73") { // External services
		return true
	}

	return false
}

// classifyNetworkType determines if a network is OT, IT, or Mixed based on all hosts
func classifyNetworkType(hosts []*types.Host) string {
	otCount := 0
	itCount := 0

	for _, host := range hosts {
		if host.ICSScore > 0 || host.InferredLevel == types.L1 || host.InferredLevel == types.L2 {
			otCount++
		} else if host.ITScore > 0 || host.InferredLevel == types.L3 {
			itCount++
		}
	}

	// Classification based on majority
	if otCount > 0 && itCount == 0 {
		return "OT"
	} else if itCount > 0 && otCount == 0 {
		return "IT"
	} else if otCount > 0 && itCount > 0 {
		return "IT-OT" // Mixed network with both types
	} else {
		return "Mixed" // Unclear classification
	}
}

// inferNetworkPurdueLevel determines the dominant Purdue level for a network
func inferNetworkPurdueLevel(hosts []*types.Host) types.PurdueLevel {
	levelCounts := make(map[types.PurdueLevel]int)

	for _, host := range hosts {
		levelCounts[host.InferredLevel]++
	}

	// Find the most common level
	maxCount := 0
	dominantLevel := types.Unknown
	for level, count := range levelCounts {
		if count > maxCount && level != types.Unknown {
			maxCount = count
			dominantLevel = level
		}
	}

	return dominantLevel
}

// writeShapeLegend adds a legend explaining device shapes
func writeShapeLegend(w *bufio.Writer) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  // Legend: Device Shapes")
	fmt.Fprintln(w, "  subgraph cluster_legend {")
	fmt.Fprintln(w, "    rank=sink;")
	fmt.Fprintln(w, "    label=\"Device Legend\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    fillcolor=\"#f9f9f9\";")
	fmt.Fprintln(w, "    fontsize=12;")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    legend_plc [label=\"PLC\", shape=octagon, style=filled, fillcolor=\"#ffddff\"];")
	fmt.Fprintln(w, "    legend_field [label=\"Field Device\", shape=box, style=filled, fillcolor=\"#ccffcc\"];")
	fmt.Fprintln(w, "    legend_control [label=\"Control Device\", shape=ellipse, style=filled, fillcolor=\"#ffcccc\"];")
	fmt.Fprintln(w, "    legend_network [label=\"Network Device\", shape=diamond, style=filled, fillcolor=\"#ccccff\"];")
	fmt.Fprintln(w, "    legend_unknown [label=\"types.Unknown Device\", shape=circle, style=filled, fillcolor=\"#f0f0f0\"];")
	fmt.Fprintln(w, "  }")
}

// inferNetworkCIDR determines network CIDR from IP (IPv4 only, filter out broadcast/multicast)
func inferNetworkCIDR(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "" // Skip IPv6 and invalid IPs
	}

	// Convert first octet to check for valid unicast ranges
	first := parts[0]

	// Skip broadcast/multicast/invalid ranges
	switch first {
	case "0", "127", "169", "224", "225", "226", "227", "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253", "254", "255":
		return "" // Skip these ranges
	}

	// Filter out external/public IPs that are likely DNS servers or external services
	if (parts[0] == "1" && parts[1] == "1" && parts[2] == "1") || // 1.1.1.1 DNS
		(parts[0] == "8" && parts[1] == "8" && parts[2] == "8") || // 8.8.8.8 DNS
		(parts[0] == "208" && parts[1] == "73") { // External services
		return "" // Skip external IPs
	}

	// Common industrial network patterns (IPv4 only)
	if parts[0] == "192" && parts[1] == "168" {
		return fmt.Sprintf("192.168.%s.0/24", parts[2])
	}
	if parts[0] == "10" {
		return fmt.Sprintf("10.%s.%s.0/24", parts[1], parts[2]) // Use /24 based on actual data
	}
	if parts[0] == "172" {
		second, _ := strconv.Atoi(parts[1])
		if second >= 16 && second <= 31 {
			return fmt.Sprintf("172.%s.0.0/16", parts[1])
		}
	}

	// Special organizational networks - use /24 based on actual PCAP data
	if parts[0] == "141" && parts[1] == "81" {
		return fmt.Sprintf("141.81.%s.0/24", parts[2]) // Fix format error and use /24
	}

	// For other valid private ranges, use /24 subnet
	// Only include if it's likely a private network
	firstOctet, _ := strconv.Atoi(parts[0])
	if firstOctet >= 1 && firstOctet <= 223 && firstOctet != 127 {
		// Only create networks for what appear to be internal ranges
		if firstOctet == 192 || (firstOctet >= 172 && firstOctet <= 172) || firstOctet == 10 ||
			(firstOctet >= 141 && firstOctet <= 141) {
			return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}

	return "" // Skip everything else (external IPs)
}

// writeNetworkSegment writes a network segment for segmentation planning
func writeNetworkSegment(w *bufio.Writer, network NetworkSegment, g *types.Graph) {
	segmentID := strings.ReplaceAll(network.CIDR, ".", "_")
	segmentID = strings.ReplaceAll(segmentID, "/", "_")
	segmentID = strings.ReplaceAll(segmentID, ":", "_") // Fix IPv6 addresses

	// Determine segment color based on type
	var bgColor, borderColor string
	switch network.Type {
	case "OT":
		bgColor = "#e8f6e8" // Light green for OT
		borderColor = "#00aa44"
	case "IT":
		bgColor = "#e6f3ff" // Light blue for IT
		borderColor = "#0066cc"
	default:
		bgColor = "#f5f5f5" // Light gray for mixed
		borderColor = "#666666"
	}

	fmt.Fprintf(w, "  subgraph cluster_%s {\n", segmentID)
	fmt.Fprintf(w, "    label=\"%s Network\\n%s\";\n", network.Type, network.CIDR)
	fmt.Fprintf(w, "    style=filled; bgcolor=\"%s\"; color=\"%s\";\n", bgColor, borderColor)
	fmt.Fprintf(w, "    fontsize=12; fontname=\"Arial Bold\";\n")

	// Add a network node
	nodeID := strings.ReplaceAll(network.CIDR, ".", "_")
	nodeID = strings.ReplaceAll(nodeID, "/", "_")
	nodeID = strings.ReplaceAll(nodeID, ":", "_") // Fix IPv6 addresses
	fmt.Fprintf(w, "    net_%s [label=\"%s\\n%d hosts\", shape=ellipse, fillcolor=\"%s\", style=filled];\n",
		nodeID, network.CIDR, len(network.Hosts), bgColor)

	// Add key assets (limit to avoid clutter)
	keyHosts := getKeyNetworkHosts(network.Hosts)
	for _, host := range keyHosts {
		label := buildAssetLabel(host, false) // false = simplified for network view
		fmt.Fprintf(w, "    \"%s\" [label=\"%s\", shape=box, fillcolor=\"white\", style=filled];\n",
			host.IP, label)
		fmt.Fprintf(w, "    net_%s -> \"%s\" [style=dotted];\n",
			nodeID, host.IP)
	}

	fmt.Fprintln(w, "  }")
}

// writeHorizontalNetworkSegment writes network segments in horizontal layout with types.L2 detection
func writeHorizontalNetworkSegment(w *bufio.Writer, network NetworkSegment, g *types.Graph, index int, moxaDevice *types.Host) {
	segmentID := strings.ReplaceAll(network.CIDR, ".", "_")
	segmentID = strings.ReplaceAll(segmentID, "/", "_")
	segmentID = strings.ReplaceAll(segmentID, ":", "_")

	// Determine segment color and position
	var bgColor, borderColor string
	switch network.Type {
	case "OT":
		bgColor = "#e8f6e8" // Light green for OT
		borderColor = "#2E7D32"
	case "IT":
		bgColor = "#e3f2fd" // Light blue for IT
		borderColor = "#1976D2"
	default:
		bgColor = "#f5f5f5" // Light gray for mixed
		borderColor = "#666666"
	}

	fmt.Fprintf(w, "  subgraph cluster_%s {\n", segmentID)
	fmt.Fprintf(w, "    label=\"%s Network\\n%s\\n%d devices\";\n", network.Type, network.CIDR, len(network.Hosts))
	fmt.Fprintf(w, "    style=filled; bgcolor=\"%s\"; color=\"%s\"; penwidth=2;\n", bgColor, borderColor)
	fmt.Fprintf(w, "    fontsize=14; fontname=\"Arial Bold\";\n")

	// Network node
	nodeID := strings.ReplaceAll(network.CIDR, ".", "_")
	nodeID = strings.ReplaceAll(nodeID, "/", "_")
	nodeID = strings.ReplaceAll(nodeID, ":", "_")
	fmt.Fprintf(w, "    net_%s [label=\"%s\\nSwitch/Gateway\", shape=box, fillcolor=\"%s\", style=filled];\n",
		nodeID, network.CIDR, bgColor)

	// Identify Layer 2 devices and regular devices
	var l2Devices, regularDevices []*types.Host
	for _, host := range network.Hosts {
		vendor := strings.ToLower(host.Vendor)
		deviceName := strings.ToLower(host.DeviceName)

		// Check if it's a Layer 2 device (switch, bridge, etc.)
		if strings.Contains(vendor, "switch") ||
			strings.Contains(deviceName, "switch") ||
			strings.Contains(vendor, "bridge") ||
			strings.Contains(deviceName, "bridge") ||
			host.ITScore > host.ICSScore && len(host.Roles) == 0 {
			l2Devices = append(l2Devices, host)
		} else {
			regularDevices = append(regularDevices, host)
		}
	}

	// Add Layer 2 segment if types.L2 devices exist
	if len(l2Devices) > 0 {
		fmt.Fprintf(w, "    subgraph cluster_%s_l2 {\n", segmentID)
		fmt.Fprintln(w, "      label=\"Layer 2 Infrastructure\";")
		fmt.Fprintln(w, "      style=dashed; color=\"#FF9800\"; bgcolor=\"#FFF3E0\";")
		fmt.Fprintln(w, "      fontsize=10;")

		for _, host := range l2Devices {
			label := buildNetworkAssetLabel(host, moxaDevice)
			fmt.Fprintf(w, "      \"%s\" [label=\"%s\", shape=hexagon, fillcolor=\"#FFE0B2\", style=filled];\n",
				host.IP, label)
		}
		fmt.Fprintln(w, "    }")
	}

	// Add regular devices
	keyDevices := getKeyNetworkHosts(regularDevices)
	for _, host := range keyDevices {
		label := buildNetworkAssetLabel(host, moxaDevice)
		var shape, fillColor string

		// Special highlighting for known devices
		if host == moxaDevice {
			shape = "diamond"
			fillColor = "#FF5722" // Orange for Moxa
		} else if strings.Contains(strings.ToLower(host.Vendor), "cisco") {
			shape = "diamond"
			fillColor = "#4CAF50" // Green for Cisco
		} else {
			shape = "box"
			fillColor = "white"
		}

		fmt.Fprintf(w, "    \"%s\" [label=\"%s\", shape=%s, fillcolor=\"%s\", style=filled];\n",
			host.IP, label, shape, fillColor)

		// Connect to network switch
		fmt.Fprintf(w, "    net_%s -> \"%s\" [style=dotted];\n", nodeID, host.IP)
	}

	fmt.Fprintln(w, "  }")
}

// buildNetworkAssetLabel creates labels for network view with device highlighting
func buildNetworkAssetLabel(host *types.Host, moxaDevice *types.Host) string {
	var parts []string

	// Device identification
	if host == moxaDevice {
		parts = append(parts, "🔶 MOXA Device")
	} else if strings.Contains(strings.ToLower(host.Vendor), "cisco") {
		parts = append(parts, "🔷 Cisco Device")
	} else if host.DeviceName != "" {
		parts = append(parts, host.DeviceName)
	} else {
		parts = append(parts, "Device")
	}

	// IP address
	parts = append(parts, host.IP)

	// Vendor if available and not already shown
	if host.Vendor != "" && host != moxaDevice && !strings.Contains(strings.ToLower(host.Vendor), "cisco") {
		vendor := host.Vendor
		if len(vendor) > 15 {
			vendor = vendor[:12] + "..."
		}
		parts = append(parts, fmt.Sprintf("[%s]", vendor))
	}

	// Primary role
	if len(host.Roles) > 0 {
		parts = append(parts, fmt.Sprintf("(%s)", host.Roles[0]))
	}

	return strings.Join(parts, "\\n")
}

// getKeyNetworkHosts returns the most important hosts for network view
func getKeyNetworkHosts(hosts []*types.Host) []*types.Host {
	// Sort by importance (ICS score + role significance)
	type hostScore struct {
		host  *types.Host
		score int
	}

	var scored []hostScore
	for _, host := range hosts {
		score := host.ICSScore*3 + host.ITScore
		if len(host.Roles) > 0 {
			score += 5 // Boost for identified roles
		}
		if strings.Contains(strings.ToLower(host.DeviceName), "plc") {
			score += 10 // PLCs are very important
		}
		scored = append(scored, hostScore{host: host, score: score})
	}

	// Sort by score descending
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	// Return top 5 hosts per network
	var result []*types.Host
	limit := 5
	if len(scored) < limit {
		limit = len(scored)
	}

	for i := 0; i < limit; i++ {
		result = append(result, scored[i].host)
	}

	return result
}

func writeJSON(g *types.Graph, path string) error {
	out := struct {
		Hosts map[string]*types.Host `json:"hosts"`
		Edges []*types.Edge          `json:"edges"`
	}{
		Hosts: g.Hosts,
	}
	for _, e := range g.Edges {
		out.Edges = append(out.Edges, e)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
