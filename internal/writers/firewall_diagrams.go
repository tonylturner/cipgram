package writers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cipgram/internal/interfaces"
)

// FirewallDiagramGenerator creates diagrams from firewall configuration data only
type FirewallDiagramGenerator struct {
	model *interfaces.NetworkModel
}

// NewFirewallDiagramGenerator creates a new firewall diagram generator
func NewFirewallDiagramGenerator(model *interfaces.NetworkModel) *FirewallDiagramGenerator {
	return &FirewallDiagramGenerator{
		model: model,
	}
}

// GenerateNetworkTopologyDiagram creates a network topology diagram from firewall config
func (g *FirewallDiagramGenerator) GenerateNetworkTopologyDiagram(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	// Generate firewall-centric network topology diagram
	fmt.Fprintln(w, "digraph FirewallTopology {")
	fmt.Fprintln(w, "  rankdir=LR;") // Left-to-right layout works better for firewall diagrams
	fmt.Fprintln(w, "  node [fontname=\"Arial\", fontsize=10];")
	fmt.Fprintln(w, "  edge [fontname=\"Arial\", fontsize=9];")
	fmt.Fprintln(w, "  bgcolor=white;")
	fmt.Fprintln(w, "  splines=ortho;") // Use orthogonal lines for cleaner look
	fmt.Fprintln(w, "  nodesep=1.0;")
	fmt.Fprintln(w, "  ranksep=2.0;")
	fmt.Fprintln(w, "")

	// Add title and metadata
	fmt.Fprintf(w, "  label=\"Firewall Network Topology\\n%s\\nGenerated: %s\";\n",
		g.model.Metadata.Source, g.model.Metadata.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, "  labelloc=t;")
	fmt.Fprintln(w, "  fontsize=14;")
	fmt.Fprintln(w, "")

	// Generate firewall-centric topology
	g.generateFirewallCentricTopology(w)

	fmt.Fprintln(w, "}")
	return nil
}

// GenerateIEC62443ZoneDiagram creates an IEC 62443 compliant zone diagram
func (g *FirewallDiagramGenerator) GenerateIEC62443ZoneDiagram(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	fmt.Fprintln(w, "digraph IEC62443Zones {")
	fmt.Fprintln(w, "  rankdir=TB;")
	fmt.Fprintln(w, "  node [fontname=\"Arial\", fontsize=10];")
	fmt.Fprintln(w, "  edge [fontname=\"Arial\", fontsize=9, penwidth=2];")
	fmt.Fprintln(w, "  bgcolor=\"#f8f9fa\";")
	fmt.Fprintln(w, "")

	// Add IEC 62443 title
	fmt.Fprintln(w, "  label=\"IEC 62443 Zone & Conduit Analysis\\nFirewall Configuration Analysis\";")
	fmt.Fprintln(w, "  labelloc=t;")
	fmt.Fprintln(w, "  fontsize=16;")
	fmt.Fprintln(w, "  fontname=\"Arial Bold\";")
	fmt.Fprintln(w, "")

	// Group networks by IEC 62443 zones
	zoneNetworks := g.groupNetworksByZone()

	// Generate each zone as a cluster
	for zone, networks := range zoneNetworks {
		g.generateIEC62443Zone(w, zone, networks)
	}

	// Generate conduits (connections between zones)
	g.generateConduits(w, zoneNetworks)

	// Add IEC 62443 legend
	g.generateIEC62443Legend(w)

	fmt.Fprintln(w, "}")
	return nil
}

// generateZoneClusters creates clustered zones for network topology
func (g *FirewallDiagramGenerator) generateZoneClusters(w *bufio.Writer) {
	zoneNetworks := g.groupNetworksByZone()

	for zone, networks := range zoneNetworks {
		if len(networks) == 0 {
			continue
		}

		clusterName := strings.ReplaceAll(string(zone), " ", "_")
		fmt.Fprintf(w, "  subgraph cluster_%s {\n", clusterName)
		fmt.Fprintf(w, "    label=\"%s\";\n", zone)

		// Zone-specific styling
		switch zone {
		case interfaces.ManufacturingZone:
			fmt.Fprintln(w, "    style=filled;")
			fmt.Fprintln(w, "    bgcolor=\"#e8f5e8\";")
			fmt.Fprintln(w, "    color=\"#2e7d32\";")
		case interfaces.DMZZone:
			fmt.Fprintln(w, "    style=filled;")
			fmt.Fprintln(w, "    bgcolor=\"#fff3e0\";")
			fmt.Fprintln(w, "    color=\"#f57c00\";")
		case interfaces.RemoteAccessZone:
			fmt.Fprintln(w, "    style=filled;")
			fmt.Fprintln(w, "    bgcolor=\"#e1f5fe\";")
			fmt.Fprintln(w, "    color=\"#0277bd\";")
		default:
			fmt.Fprintln(w, "    style=filled;")
			fmt.Fprintln(w, "    bgcolor=\"#f3e5f5\";")
			fmt.Fprintln(w, "    color=\"#7b1fa2\";")
		}

		fmt.Fprintln(w, "    penwidth=2;")
		fmt.Fprintln(w, "    fontsize=12;")
		fmt.Fprintln(w, "    fontname=\"Arial Bold\";")
		fmt.Fprintln(w, "")

		// Add placeholder for networks (will be filled by generateNetworkSegments)
		for _, network := range networks {
			fmt.Fprintf(w, "    \"%s\";\n", network.ID)
		}

		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w, "")
	}
}

// generateNetworkSegments creates individual network segment nodes
func (g *FirewallDiagramGenerator) generateNetworkSegments(w *bufio.Writer) {
	for _, segment := range g.model.Networks {
		label := g.buildNetworkSegmentLabel(segment)
		color := g.getSegmentColor(segment)

		fmt.Fprintf(w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", style=\"filled,rounded\", shape=box];\n",
			segment.ID, label, color)
	}
	fmt.Fprintln(w, "")
}

// generateSecurityPolicyFlows creates edges representing security policies
func (g *FirewallDiagramGenerator) generateSecurityPolicyFlows(w *bufio.Writer) {
	fmt.Fprintln(w, "  // Security Policy Flows")

	for _, policy := range g.model.Policies {
		if policy.Source.CIDR == "any" || policy.Destination.CIDR == "any" {
			continue // Skip overly broad rules for clarity
		}

		// Map network references to actual network segments
		srcNetwork := g.findNetworkByReference(policy.Source.CIDR)
		dstNetwork := g.findNetworkByReference(policy.Destination.CIDR)

		if srcNetwork != "" && dstNetwork != "" && srcNetwork != dstNetwork {
			edgeColor := "green"
			edgeStyle := "solid"

			if policy.Action == interfaces.Deny {
				edgeColor = "red"
				edgeStyle = "dashed"
			}

			label := fmt.Sprintf("%s\\n%s", policy.Action, policy.Protocol)
			if policy.Description != "" {
				label = fmt.Sprintf("%s\\n%s", label, g.truncateString(policy.Description, 20))
			}

			fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\", style=\"%s\"];\n",
				srcNetwork, dstNetwork, label, edgeColor, edgeStyle)
		}
	}
	fmt.Fprintln(w, "")
}

// generateFirewallLegend adds a legend for firewall diagrams
func (g *FirewallDiagramGenerator) generateFirewallLegend(w *bufio.Writer) {
	fmt.Fprintln(w, "  // Legend")
	fmt.Fprintln(w, "  subgraph cluster_legend {")
	fmt.Fprintln(w, "    label=\"Legend\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#ffffff\";")
	fmt.Fprintln(w, "    color=\"#666666\";")
	fmt.Fprintln(w, "    fontsize=10;")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    legend_allow [label=\"ALLOW\", color=\"green\", style=\"solid\", shape=\"plaintext\"];")
	fmt.Fprintln(w, "    legend_deny [label=\"DENY\", color=\"red\", style=\"dashed\", shape=\"plaintext\"];")
	fmt.Fprintln(w, "    legend_high [label=\"High Risk\", fillcolor=\"#ffcdd2\", style=\"filled\", shape=\"box\"];")
	fmt.Fprintln(w, "    legend_medium [label=\"Medium Risk\", fillcolor=\"#fff3e0\", style=\"filled\", shape=\"box\"];")
	fmt.Fprintln(w, "    legend_low [label=\"Low Risk\", fillcolor=\"#e8f5e8\", style=\"filled\", shape=\"box\"];")
	fmt.Fprintln(w, "  }")
}

// generateIEC62443Zone creates a zone cluster for IEC 62443 diagram
func (g *FirewallDiagramGenerator) generateIEC62443Zone(w *bufio.Writer, zone interfaces.IEC62443Zone, networks []*interfaces.NetworkSegment) {
	if len(networks) == 0 {
		return
	}

	clusterName := strings.ReplaceAll(string(zone), " ", "_")
	fmt.Fprintf(w, "  subgraph cluster_%s {\n", clusterName)
	fmt.Fprintf(w, "    label=\"%s\";\n", zone)

	// IEC 62443 zone styling
	switch zone {
	case interfaces.ManufacturingZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#c8e6c9\";")
		fmt.Fprintln(w, "    color=\"#1b5e20\";")
	case interfaces.DMZZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#ffe0b2\";")
		fmt.Fprintln(w, "    color=\"#e65100\";")
	case interfaces.EnterpriseZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#e1bee7\";")
		fmt.Fprintln(w, "    color=\"#4a148c\";")
	case interfaces.RemoteAccessZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#b3e5fc\";")
		fmt.Fprintln(w, "    color=\"#01579b\";")
	default:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#f5f5f5\";")
		fmt.Fprintln(w, "    color=\"#424242\";")
	}

	fmt.Fprintln(w, "    penwidth=3;")
	fmt.Fprintln(w, "    fontsize=14;")
	fmt.Fprintln(w, "    fontname=\"Arial Bold\";")
	fmt.Fprintln(w, "")

	// Add network segments within zone
	for _, network := range networks {
		label := fmt.Sprintf("%s\\n%s\\nRisk: %s", network.ID, network.CIDR, network.Risk)
		fmt.Fprintf(w, "    \"%s\" [label=\"%s\", shape=\"box\", style=\"rounded,filled\", fillcolor=\"white\"];\n",
			network.ID, label)
	}

	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w, "")
}

// generateConduits creates conduit connections between zones
func (g *FirewallDiagramGenerator) generateConduits(w *bufio.Writer, zoneNetworks map[interfaces.IEC62443Zone][]*interfaces.NetworkSegment) {
	fmt.Fprintln(w, "  // Conduits (Zone Connections)")

	// Track zone pairs to avoid duplicates
	zonePairs := make(map[string]bool)

	for _, policy := range g.model.Policies {
		srcZone := g.getZoneForNetwork(policy.Source.CIDR)
		dstZone := g.getZoneForNetwork(policy.Destination.CIDR)

		if srcZone != "" && dstZone != "" && srcZone != dstZone {
			pairKey := fmt.Sprintf("%s-%s", srcZone, dstZone)
			reversePairKey := fmt.Sprintf("%s-%s", dstZone, srcZone)

			if !zonePairs[pairKey] && !zonePairs[reversePairKey] {
				zonePairs[pairKey] = true

				// Create conduit connection
				conduitLabel := fmt.Sprintf("Conduit\\n%s ↔ %s", srcZone, dstZone)
				fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s\", style=\"bold\", penwidth=3, color=\"#333333\"];\n",
					g.getZoneRepresentative(srcZone, zoneNetworks),
					g.getZoneRepresentative(dstZone, zoneNetworks),
					conduitLabel)
			}
		}
	}
	fmt.Fprintln(w, "")
}

// generateIEC62443Legend adds IEC 62443 specific legend
func (g *FirewallDiagramGenerator) generateIEC62443Legend(w *bufio.Writer) {
	fmt.Fprintln(w, "  // IEC 62443 Legend")
	fmt.Fprintln(w, "  subgraph cluster_iec_legend {")
	fmt.Fprintln(w, "    label=\"IEC 62443 Zones\";")
	fmt.Fprintln(w, "    style=filled;")
	fmt.Fprintln(w, "    bgcolor=\"#ffffff\";")
	fmt.Fprintln(w, "    color=\"#333333\";")
	fmt.Fprintln(w, "    fontsize=12;")
	fmt.Fprintln(w, "    fontname=\"Arial Bold\";")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    mfg_zone [label=\"Manufacturing Zone\\n(Level 0-2)\", fillcolor=\"#c8e6c9\", style=\"filled,rounded\", shape=\"box\"];")
	fmt.Fprintln(w, "    dmz_zone [label=\"DMZ Zone\\n(Network Perimeter)\", fillcolor=\"#ffe0b2\", style=\"filled,rounded\", shape=\"box\"];")
	fmt.Fprintln(w, "    ent_zone [label=\"Enterprise Zone\\n(Level 3-5)\", fillcolor=\"#e1bee7\", style=\"filled,rounded\", shape=\"box\"];")
	fmt.Fprintln(w, "    remote_zone [label=\"Remote Access Zone\\n(VPN/Remote)\", fillcolor=\"#b3e5fc\", style=\"filled,rounded\", shape=\"box\"];")
	fmt.Fprintln(w, "  }")
}

// generateFirewallCentricTopology creates a traditional network diagram with firewall at center
func (g *FirewallDiagramGenerator) generateFirewallCentricTopology(w *bufio.Writer) {
	// Create the central firewall node
	fmt.Fprintln(w, "  // Central Firewall")
	fmt.Fprintln(w, "  firewall [")
	fmt.Fprintln(w, "    label=\"🔥 Firewall\\n(OPNsense)\\n\\nInterfaces:\";")
	fmt.Fprintln(w, "    shape=box;")
	fmt.Fprintln(w, "    style=\"filled,rounded\";")
	fmt.Fprintln(w, "    fillcolor=\"#e3f2fd\";")
	fmt.Fprintln(w, "    color=\"#1976d2\";")
	fmt.Fprintln(w, "    penwidth=3;")
	fmt.Fprintln(w, "    fontsize=12;")
	fmt.Fprintln(w, "    fontname=\"Arial Bold\";")
	fmt.Fprintln(w, "  ];")
	fmt.Fprintln(w, "")

	// Create network nodes for each interface/network
	fmt.Fprintln(w, "  // Network Segments")
	for _, network := range g.model.Networks {
		g.generateNetworkNode(w, network)
	}
	fmt.Fprintln(w, "")

	// Connect firewall to networks
	fmt.Fprintln(w, "  // Firewall to Network Connections")
	for _, network := range g.model.Networks {
		g.generateFirewallToNetworkConnection(w, network)
	}
	fmt.Fprintln(w, "")

	// Add rule annotations
	fmt.Fprintln(w, "  // Security Rules (as edge labels)")
	g.generateRuleAnnotations(w)
}

// generateNetworkNode creates a node for a network segment
func (g *FirewallDiagramGenerator) generateNetworkNode(w *bufio.Writer, network *interfaces.NetworkSegment) {
	nodeID := fmt.Sprintf("net_%s", network.ID)

	// Build the network label with all relevant information
	label := fmt.Sprintf("%s", network.ID)
	if network.CIDR != "" {
		label += fmt.Sprintf("\\n%s", network.CIDR)
	}
	if network.Name != "" {
		label += fmt.Sprintf("\\n(%s)", network.Name)
	}

	// Add zone information
	label += fmt.Sprintf("\\n\\nZone: %s", network.Zone)
	label += fmt.Sprintf("\\nRisk: %s", network.Risk)

	// Add interface information if available
	if network.Purpose != "" {
		label += fmt.Sprintf("\\nType: %s", network.Purpose)
	}

	// Choose colors based on zone
	fillColor := g.getZoneColor(network.Zone)
	borderColor := g.getZoneBorderColor(network.Zone)

	fmt.Fprintf(w, "  %s [\n", nodeID)
	fmt.Fprintf(w, "    label=\"%s\";\n", label)
	fmt.Fprintln(w, "    shape=box;")
	fmt.Fprintln(w, "    style=\"filled,rounded\";")
	fmt.Fprintf(w, "    fillcolor=\"%s\";\n", fillColor)
	fmt.Fprintf(w, "    color=\"%s\";\n", borderColor)
	fmt.Fprintln(w, "    penwidth=2;")
	fmt.Fprintln(w, "    fontsize=10;")
	fmt.Fprintln(w, "  ];")
}

// generateFirewallToNetworkConnection creates connection from firewall to network
func (g *FirewallDiagramGenerator) generateFirewallToNetworkConnection(w *bufio.Writer, network *interfaces.NetworkSegment) {
	nodeID := fmt.Sprintf("net_%s", network.ID)

	// Create interface label
	interfaceLabel := network.ID
	if network.CIDR != "" {
		interfaceLabel += fmt.Sprintf("\\n%s", network.CIDR)
	}

	fmt.Fprintf(w, "  firewall -> %s [\n", nodeID)
	fmt.Fprintf(w, "    label=\"%s\";\n", interfaceLabel)
	fmt.Fprintln(w, "    fontsize=9;")
	fmt.Fprintln(w, "    color=\"#666666\";")
	fmt.Fprintln(w, "    penwidth=2;")
	fmt.Fprintln(w, "  ];")
}

// generateRuleAnnotations adds security rule information as annotations
func (g *FirewallDiagramGenerator) generateRuleAnnotations(w *bufio.Writer) {
	if len(g.model.Policies) == 0 {
		return
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  // Security Rules Summary")
	fmt.Fprintln(w, "  rules_summary [")
	fmt.Fprintln(w, "    label=\"🔒 Security Rules Summary\\n\\n")

	// Show first few important rules
	ruleCount := 0
	for _, policy := range g.model.Policies {
		if ruleCount >= 5 { // Limit to 5 rules for readability
			break
		}

		action := "ALLOW"
		if policy.Action == "DENY" || policy.Action == "DROP" || policy.Action == "REJECT" {
			action = "DENY"
		}

		// Handle NetworkRange source
		source := "any"
		if policy.Source.CIDR != "" {
			source = policy.Source.CIDR
		} else if len(policy.Source.IPs) > 0 {
			source = policy.Source.IPs[0] // Show first IP
			if len(policy.Source.IPs) > 1 {
				source += ",..."
			}
		}

		// Handle NetworkRange destination
		destination := "any"
		if policy.Destination.CIDR != "" {
			destination = policy.Destination.CIDR
		} else if len(policy.Destination.IPs) > 0 {
			destination = policy.Destination.IPs[0] // Show first IP
			if len(policy.Destination.IPs) > 1 {
				destination += ",..."
			}
		}

		fmt.Fprintf(w, "    %s: %s → %s\\n", action, source, destination)
		ruleCount++
	}

	if len(g.model.Policies) > 5 {
		fmt.Fprintf(w, "    ... and %d more rules", len(g.model.Policies)-5)
	}

	fmt.Fprintln(w, "\";")
	fmt.Fprintln(w, "    shape=note;")
	fmt.Fprintln(w, "    style=\"filled,rounded\";")
	fmt.Fprintln(w, "    fillcolor=\"#fff9c4\";")
	fmt.Fprintln(w, "    color=\"#f57f17\";")
	fmt.Fprintln(w, "    fontsize=9;")
	fmt.Fprintln(w, "  ];")
}

// getZoneColor returns the fill color for a zone
func (g *FirewallDiagramGenerator) getZoneColor(zone interfaces.IEC62443Zone) string {
	switch zone {
	case interfaces.ManufacturingZone:
		return "#c8e6c9" // Light green
	case interfaces.DMZZone:
		return "#ffe0b2" // Light orange
	case interfaces.EnterpriseZone:
		return "#e1bee7" // Light purple
	case interfaces.RemoteAccessZone:
		return "#b3e5fc" // Light blue
	default:
		return "#f5f5f5" // Light gray
	}
}

// getZoneBorderColor returns the border color for a zone
func (g *FirewallDiagramGenerator) getZoneBorderColor(zone interfaces.IEC62443Zone) string {
	switch zone {
	case interfaces.ManufacturingZone:
		return "#2e7d32" // Dark green
	case interfaces.DMZZone:
		return "#f57c00" // Dark orange
	case interfaces.EnterpriseZone:
		return "#7b1fa2" // Dark purple
	case interfaces.RemoteAccessZone:
		return "#0277bd" // Dark blue
	default:
		return "#666666" // Dark gray
	}
}

// Helper functions

func (g *FirewallDiagramGenerator) groupNetworksByZone() map[interfaces.IEC62443Zone][]*interfaces.NetworkSegment {
	zoneNetworks := make(map[interfaces.IEC62443Zone][]*interfaces.NetworkSegment)

	for _, network := range g.model.Networks {
		zoneNetworks[network.Zone] = append(zoneNetworks[network.Zone], network)
	}

	return zoneNetworks
}

func (g *FirewallDiagramGenerator) buildNetworkSegmentLabel(segment *interfaces.NetworkSegment) string {
	label := segment.ID
	if segment.Name != "" {
		label += "\\n" + segment.Name
	}
	if segment.CIDR != "" {
		label += "\\n" + segment.CIDR
	}
	if segment.Purpose != "" {
		label += "\\n(" + segment.Purpose + ")"
	}
	return label
}

func (g *FirewallDiagramGenerator) getSegmentColor(segment *interfaces.NetworkSegment) string {
	switch segment.Risk {
	case interfaces.HighRisk:
		return "#ffcdd2"
	case interfaces.MediumRisk:
		return "#fff3e0"
	case interfaces.LowRisk:
		return "#e8f5e8"
	default:
		return "#f5f5f5"
	}
}

func (g *FirewallDiagramGenerator) findNetworkByReference(ref string) string {
	// Map OPNsense network references to our network segments
	for id := range g.model.Networks {
		if id == ref || strings.Contains(ref, id) {
			return id
		}
	}
	return ""
}

func (g *FirewallDiagramGenerator) getZoneForNetwork(networkRef string) interfaces.IEC62443Zone {
	networkID := g.findNetworkByReference(networkRef)
	if networkID != "" {
		if network, exists := g.model.Networks[networkID]; exists {
			return network.Zone
		}
	}
	return ""
}

func (g *FirewallDiagramGenerator) getZoneRepresentative(zone interfaces.IEC62443Zone, zoneNetworks map[interfaces.IEC62443Zone][]*interfaces.NetworkSegment) string {
	if networks, exists := zoneNetworks[zone]; exists && len(networks) > 0 {
		return networks[0].ID
	}
	return string(zone)
}

func (g *FirewallDiagramGenerator) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
