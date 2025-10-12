package writers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cipgram/pkg/types"
)

// FirewallDiagramGenerator creates diagrams from firewall configuration data only
type FirewallDiagramGenerator struct {
	model *types.NetworkModel
}

// NewFirewallDiagramGenerator creates a new firewall diagram generator
func NewFirewallDiagramGenerator(model *types.NetworkModel) *FirewallDiagramGenerator {
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

// GenerateFirewallRulesSummary creates a detailed firewall rules summary file
func (g *FirewallDiagramGenerator) GenerateFirewallRulesSummary(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create rules summary file: %v", err)
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	defer w.Flush()

	// Write header
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "                            FIREWALL RULES SUMMARY\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "Configuration: %s\n", g.model.Metadata.Source)
	fmt.Fprintf(w, "Generated: %s\n", g.model.Metadata.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Total Networks: %d | Total Policies: %d\n", len(g.model.Networks), len(g.model.Policies))
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════════\n\n")

	// Network Segments Summary
	fmt.Fprintf(w, "📊 NETWORK SEGMENTS\n")
	fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────────\n")
	for _, network := range g.model.Networks {
		fmt.Fprintf(w, "• %-15s | %-18s | %-20s | %-12s | %s\n",
			network.ID,
			network.CIDR,
			network.Zone,
			network.Risk,
			network.Purpose)
	}
	fmt.Fprintf(w, "\n")

	// Security Policies Detail
	if len(g.model.Policies) > 0 {
		fmt.Fprintf(w, "🔒 SECURITY POLICIES\n")
		fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(w, "%-6s | %-8s | %-20s | %-20s | %-12s | %-15s | %s\n",
			"#", "ACTION", "SOURCE", "DESTINATION", "PROTOCOL", "PORTS", "DESCRIPTION")
		fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────────\n")

		for i, policy := range g.model.Policies {
			// Format source
			source := "any"
			if policy.Source.CIDR != "" && policy.Source.CIDR != "any" {
				source = policy.Source.CIDR
			} else if len(policy.Source.IPs) > 0 {
				source = strings.Join(policy.Source.IPs, ",")
				if len(source) > 18 {
					source = source[:15] + "..."
				}
			}

			// Format destination
			destination := "any"
			if policy.Destination.CIDR != "" && policy.Destination.CIDR != "any" {
				destination = policy.Destination.CIDR
			} else if len(policy.Destination.IPs) > 0 {
				destination = strings.Join(policy.Destination.IPs, ",")
				if len(destination) > 18 {
					destination = destination[:15] + "..."
				}
			}

			// Format protocol
			protocol := string(policy.Protocol)
			if protocol == "" {
				protocol = "any"
			}

			// Format ports
			ports := "any"
			if len(policy.Ports) > 0 {
				var portStrs []string
				for _, port := range policy.Ports {
					if port.Number > 0 {
						// Extract service name from protocol field if it contains ":"
						if strings.Contains(port.Protocol, ":") {
							parts := strings.Split(port.Protocol, ":")
							if len(parts) >= 2 {
								serviceName := strings.Join(parts[1:], ":")
								portStrs = append(portStrs, fmt.Sprintf("%d(%s)", port.Number, serviceName))
							} else {
								portStrs = append(portStrs, fmt.Sprintf("%d", port.Number))
							}
						} else {
							portStrs = append(portStrs, fmt.Sprintf("%d", port.Number))
						}
					} else {
						// Port 0 means it's an alias - extract from protocol
						if strings.Contains(port.Protocol, ":") {
							parts := strings.Split(port.Protocol, ":")
							if len(parts) >= 2 {
								aliasName := strings.Join(parts[1:], ":")
								portStrs = append(portStrs, aliasName)
							}
						}
					}
				}
				if len(portStrs) > 0 {
					ports = strings.Join(portStrs, ",")
					if len(ports) > 13 {
						ports = ports[:10] + "..."
					}
				}
			}

			// Format description - highlight implicit default deny
			description := policy.Description
			if description == "" {
				description = "No description"
			}
			if len(description) > 40 {
				description = description[:37] + "..."
			}

			// Special formatting for implicit default deny
			ruleNumber := fmt.Sprintf("%d", i+1)
			if policy.ID == "implicit-default-deny" {
				ruleNumber = "∞"                 // Use infinity symbol for implicit rule
				description = "🔒 " + description // Add lock emoji
			}

			fmt.Fprintf(w, "%-6s | %-8s | %-20s | %-20s | %-12s | %-15s | %s\n",
				ruleNumber,
				policy.Action,
				source,
				destination,
				protocol,
				ports,
				description)
		}
	} else {
		fmt.Fprintf(w, "🔒 SECURITY POLICIES\n")
		fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(w, "No explicit firewall rules found in configuration.\n")
		fmt.Fprintf(w, "This may indicate default allow/deny policies or incomplete rule parsing.\n")
	}

	fmt.Fprintf(w, "\n")

	// Zone-based Risk Assessment
	fmt.Fprintf(w, "⚠️  RISK ASSESSMENT BY ZONE\n")
	fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────────\n")

	zoneRisks := make(map[types.IEC62443Zone][]string)
	for _, network := range g.model.Networks {
		zoneRisks[network.Zone] = append(zoneRisks[network.Zone],
			fmt.Sprintf("%s (%s)", network.ID, network.CIDR))
	}

	for zone, networks := range zoneRisks {
		var riskLevel string
		switch zone {
		case types.IndustrialZone:
			riskLevel = "HIGH RISK - Critical OT systems"
		case types.DMZZone:
			riskLevel = "MEDIUM RISK - Internet exposed"
		case types.EnterpriseZone:
			riskLevel = "LOW RISK - IT systems"
		case types.RemoteAccessZone:
			riskLevel = "LOW RISK - Controlled access"
		default:
			riskLevel = "UNKNOWN RISK"
		}

		fmt.Fprintf(w, "• %-25s: %s\n", zone, riskLevel)
		for _, network := range networks {
			fmt.Fprintf(w, "  └─ %s\n", network)
		}
		fmt.Fprintf(w, "\n")
	}

	// Recommendations with specific rule analysis
	fmt.Fprintf(w, "💡 SEGMENTATION RECOMMENDATIONS\n")
	fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(w, "🔒 IMPLICIT DEFAULT DENY: OPNsense has a built-in default deny rule (∞) that\n")
	fmt.Fprintf(w, "   blocks all traffic not explicitly allowed by the rules above. This provides\n")
	fmt.Fprintf(w, "   a secure-by-default stance - only explicitly permitted traffic flows.\n")
	fmt.Fprintf(w, "\n")

	// Analyze rules for specific security issues
	fmt.Fprintf(w, "🚨 CRITICAL SECURITY ISSUES IDENTIFIED:\n")
	fmt.Fprintf(w, "\n")

	// Find and highlight dangerous rules
	anyToAnyRules := []string{}
	manufacturingZoneRisks := []string{}
	dmzRisks := []string{}

	for i, policy := range g.model.Policies {
		if policy.ID == "implicit-default-deny" {
			continue // Skip the implicit rule
		}

		ruleNum := fmt.Sprintf("#%d", i+1)
		isAnySource := policy.Source.CIDR == "any" || policy.Source.CIDR == ""
		isAnyDest := policy.Destination.CIDR == "any" || policy.Destination.CIDR == ""
		isAnyPorts := len(policy.Ports) == 0

		// Identify any-to-any rules and overly broad rules
		if policy.Action == "ALLOW" {
			// Check for any source to any destination
			if isAnySource && isAnyDest {
				anyToAnyRules = append(anyToAnyRules, fmt.Sprintf("   %s: %s", ruleNum, policy.Description))
			} else if isAnyDest && isAnyPorts && (string(policy.Protocol) == "any" || string(policy.Protocol) == "") {
				// Check for specific source to any destination with any protocol/ports (also very dangerous)
				anyToAnyRules = append(anyToAnyRules, fmt.Sprintf("   %s: %s (Source: %s → ANY destination, ANY protocol/ports)", ruleNum, policy.Description, policy.Source.CIDR))
			}
		}

		// Manufacturing zone specific risks - check by actual zone classification, not interface name
		if policy.Action == "ALLOW" {
			// Find the network this rule applies to and check its zone
			for _, network := range g.model.Networks {
				if network.ID == policy.Zone ||
					(policy.Zone == "lan" && network.ID == "lan") ||
					(strings.Contains(policy.Zone, "opt") && network.ID == policy.Zone) {

					if network.Zone == types.IndustrialZone {
						if (isAnyDest && isAnyPorts) || (isAnySource && isAnyDest) {
							manufacturingZoneRisks = append(manufacturingZoneRisks,
								fmt.Sprintf("   %s (%s - %s): %s", ruleNum, policy.Zone, network.Zone, policy.Description))
						}
					}
					break
				}
			}
		}

		// DMZ specific risks (opt5 is DMZ)
		if policy.Zone == "opt5" && policy.Action == "ALLOW" && (isAnyDest || isAnySource) {
			dmzRisks = append(dmzRisks, fmt.Sprintf("   %s: %s", ruleNum, policy.Description))
		}
	}

	if len(anyToAnyRules) > 0 {
		fmt.Fprintf(w, "❌ ANY-TO-ANY RULES (Highest Risk):\n")
		for _, rule := range anyToAnyRules {
			fmt.Fprintf(w, "%s\n", rule)
		}
		fmt.Fprintf(w, "   → These rules bypass all network segmentation!\n")
		fmt.Fprintf(w, "\n")
	}

	if len(manufacturingZoneRisks) > 0 {
		fmt.Fprintf(w, "⚠️  INDUSTRIAL ZONE RISKS (High Risk - Critical OT Systems):\n")
		for _, rule := range manufacturingZoneRisks {
			fmt.Fprintf(w, "%s\n", rule)
		}
		fmt.Fprintf(w, "   → OT networks should have restricted, specific destinations only!\n")
		fmt.Fprintf(w, "\n")
	}

	if len(dmzRisks) > 0 {
		fmt.Fprintf(w, "🌐 DMZ ZONE RISKS (Internet-Exposed Systems):\n")
		for _, rule := range dmzRisks {
			fmt.Fprintf(w, "%s\n", rule)
		}
		fmt.Fprintf(w, "   → DMZ should have minimal, controlled access patterns!\n")
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "🎯 PRIORITY ACTIONS (Fix These First):\n")

	// Generate dynamic priority actions based on actual analysis
	priorityCount := 1
	foundIssues := false

	// Analyze each risky rule and generate specific recommendations
	for _, rule := range anyToAnyRules {
		foundIssues = true
		fmt.Fprintf(w, "%d. 🚨 URGENT: %s\n", priorityCount, rule)
		fmt.Fprintf(w, "   → Replace with specific source/destination networks and required ports only\n")
		priorityCount++
	}

	for _, rule := range manufacturingZoneRisks {
		foundIssues = true
		fmt.Fprintf(w, "%d. 🚨 URGENT: %s\n", priorityCount, rule)
		fmt.Fprintf(w, "   → OT networks should only access specific MES/Historian/DNS servers\n")
		priorityCount++
	}

	for _, rule := range dmzRisks {
		foundIssues = true
		fmt.Fprintf(w, "%d. ⚠️  REVIEW: %s\n", priorityCount, rule)
		fmt.Fprintf(w, "   → DMZ access should be limited to specific external endpoints\n")
		priorityCount++
	}

	// Additional dynamic analysis based on actual policy patterns
	broadRules := 0
	goodDenyRules := 0
	totalAllowRules := 0
	criticalRisks := 0

	for _, policy := range g.model.Policies {
		if policy.ID == "implicit-default-deny" {
			continue
		}

		if policy.Action == "ALLOW" {
			totalAllowRules++
			// Check for overly broad rules - be more aggressive in detection
			if (policy.Source.CIDR == "any" || policy.Source.CIDR == "") && len(policy.Ports) == 0 {
				broadRules++
			}
			// Also flag rules that go to "any" destination with any protocol
			if (policy.Destination.CIDR == "any" || policy.Destination.CIDR == "") &&
				(string(policy.Protocol) == "any" || string(policy.Protocol) == "") && len(policy.Ports) == 0 {
				criticalRisks++
			}
		} else if policy.Action == "DENY" || policy.Action == "BLOCK" {
			goodDenyRules++
		}
	}

	// Generate recommendations based on rule patterns - be more critical
	if criticalRisks > 0 && !foundIssues {
		fmt.Fprintf(w, "%d. 🚨 CRITICAL: Found %d rules allowing ANY destination with ANY protocol!\n", priorityCount, criticalRisks)
		fmt.Fprintf(w, "   → These rules completely bypass network segmentation - immediate fix required!\n")
		priorityCount++
		foundIssues = true
	}

	if broadRules > 0 && !foundIssues {
		fmt.Fprintf(w, "%d. ⚠️  REVIEW: Found %d overly permissive ALLOW rules\n", priorityCount, broadRules)
		fmt.Fprintf(w, "   → Consider adding specific port restrictions and destination limits\n")
		priorityCount++
		foundIssues = true
	}

	if goodDenyRules > 0 {
		fmt.Fprintf(w, "%d. ✅ GOOD: Found %d explicit DENY rules - excellent defense in depth!\n", priorityCount, goodDenyRules)
		fmt.Fprintf(w, "   → Keep these rules and consider adding logging for monitoring\n")
		priorityCount++
	}

	if totalAllowRules < 5 && criticalRisks == 0 && len(anyToAnyRules) == 0 && len(manufacturingZoneRisks) == 0 {
		fmt.Fprintf(w, "%d. 💡 SUGGESTION: Configuration has %d ALLOW rules - appears well-controlled\n", priorityCount, totalAllowRules)
		fmt.Fprintf(w, "   → Monitor actual traffic patterns to ensure rules aren't too restrictive\n")
		priorityCount++
	}

	// Only show "no critical violations" if we really found no issues
	if !foundIssues && goodDenyRules == 0 && totalAllowRules > 0 && criticalRisks == 0 {
		fmt.Fprintf(w, "✅ No critical rule violations detected in this configuration.\n")
		fmt.Fprintf(w, "   → Consider adding explicit DENY rules before default deny for better logging\n")
		fmt.Fprintf(w, "   → Monitor traffic patterns and tighten rules based on actual usage\n")
	}

	if totalAllowRules == 0 {
		fmt.Fprintf(w, "ℹ️  No explicit ALLOW rules found - all traffic blocked by default deny.\n")
		fmt.Fprintf(w, "   → Add specific ALLOW rules for required business communications\n")
	}

	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "📋 DETAILED SEGMENTATION IMPROVEMENTS:\n")

	// Generate dynamic segmentation improvements based on actual networks found
	manufacturingZones := []string{}
	enterpriseZones := []string{}
	dmzZones := []string{}

	for _, network := range g.model.Networks {
		switch network.Zone {
		case types.IndustrialZone:
			manufacturingZones = append(manufacturingZones, network.ID)
		case types.EnterpriseZone:
			enterpriseZones = append(enterpriseZones, network.ID)
		case types.DMZZone:
			dmzZones = append(dmzZones, network.ID)
		}
	}

	if len(manufacturingZones) > 0 {
		fmt.Fprintf(w, "• Industrial Zones (%s): Restrict to specific MES/Historian/DNS servers\n",
			strings.Join(manufacturingZones, ","))
		fmt.Fprintf(w, "  - Implement strict protocol controls (Modbus, OPC-UA, EtherNet/IP only)\n")
		fmt.Fprintf(w, "  - Block internet access except for specific vendor support tunnels\n")
	}

	if len(enterpriseZones) > 0 {
		fmt.Fprintf(w, "• Enterprise Zones (%s): Limit maintenance access to specific bastion/jump hosts\n",
			strings.Join(enterpriseZones, ","))
		fmt.Fprintf(w, "  - Implement time-based access controls for maintenance windows\n")
		fmt.Fprintf(w, "  - Require VPN/2FA for remote administrative access\n")
	}

	if len(dmzZones) > 0 {
		fmt.Fprintf(w, "• DMZ Zones (%s): Implement strict egress filtering, specific vendor VPN endpoints\n",
			strings.Join(dmzZones, ","))
		fmt.Fprintf(w, "  - Allow only required external services (NTP, vendor support, updates)\n")
		fmt.Fprintf(w, "  - Block all lateral movement to internal networks\n")
	}

	// Add recommendations for inter-zone communication
	if goodDenyRules > 0 {
		fmt.Fprintf(w, "• Inter-zone Controls: Current DENY rules are excellent - maintain these!\n")
		fmt.Fprintf(w, "  - Consider adding logging to monitor blocked traffic patterns\n")
	} else {
		fmt.Fprintf(w, "• Inter-zone Controls: Consider adding explicit DENY rules between zones\n")
		fmt.Fprintf(w, "  - Block Industrial → Enterprise communication by default\n")
		fmt.Fprintf(w, "  - Block DMZ → Internal network communication\n")
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "🔍 MONITORING RECOMMENDATIONS:\n")

	// Generate dynamic monitoring recommendations based on actual findings
	if len(anyToAnyRules) > 0 || len(manufacturingZoneRisks) > 0 {
		fmt.Fprintf(w, "• Enable detailed logging on risky ALLOW rules to understand traffic patterns\n")
	}

	if len(manufacturingZones) > 0 {
		fmt.Fprintf(w, "• Monitor Industrial Zone (%s) outbound connections for anomalies\n",
			strings.Join(manufacturingZones, ","))
		fmt.Fprintf(w, "• Set up alerts for unexpected OT protocol usage or destinations\n")
	}

	if len(dmzZones) > 0 {
		fmt.Fprintf(w, "• Monitor DMZ Zone (%s) for suspicious inbound/outbound connections\n",
			strings.Join(dmzZones, ","))
	}

	fmt.Fprintf(w, "• Set up alerts for any traffic hitting the implicit default deny rule (∞)\n")

	if totalAllowRules > 10 {
		fmt.Fprintf(w, "• With %d ALLOW rules, consider rule utilization analysis to remove unused rules\n", totalAllowRules)
	}

	if goodDenyRules > 0 {
		fmt.Fprintf(w, "• Monitor DENY rule hits to validate security policies are working\n")
	}

	fmt.Fprintf(w, "• Implement time-based access controls for maintenance windows\n")
	fmt.Fprintf(w, "• Regular review of firewall logs for policy violations and anomalies\n")
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "End of Firewall Rules Summary\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════════\n")

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
		case types.IndustrialZone:
			fmt.Fprintln(w, "    style=filled;")
			fmt.Fprintln(w, "    bgcolor=\"#e8f5e8\";")
			fmt.Fprintln(w, "    color=\"#2e7d32\";")
		case types.DMZZone:
			fmt.Fprintln(w, "    style=filled;")
			fmt.Fprintln(w, "    bgcolor=\"#fff3e0\";")
			fmt.Fprintln(w, "    color=\"#f57c00\";")
		case types.RemoteAccessZone:
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

			if policy.Action == types.Deny {
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
func (g *FirewallDiagramGenerator) generateIEC62443Zone(w *bufio.Writer, zone types.IEC62443Zone, networks []*types.NetworkSegment) {
	if len(networks) == 0 {
		return
	}

	clusterName := strings.ReplaceAll(string(zone), " ", "_")
	fmt.Fprintf(w, "  subgraph cluster_%s {\n", clusterName)
	fmt.Fprintf(w, "    label=\"%s\";\n", zone)

	// IEC 62443 zone styling
	switch zone {
	case types.IndustrialZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#c8e6c9\";")
		fmt.Fprintln(w, "    color=\"#1b5e20\";")
	case types.DMZZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#ffe0b2\";")
		fmt.Fprintln(w, "    color=\"#e65100\";")
	case types.EnterpriseZone:
		fmt.Fprintln(w, "    style=\"filled,bold\";")
		fmt.Fprintln(w, "    bgcolor=\"#e1bee7\";")
		fmt.Fprintln(w, "    color=\"#4a148c\";")
	case types.RemoteAccessZone:
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
func (g *FirewallDiagramGenerator) generateConduits(w *bufio.Writer, zoneNetworks map[types.IEC62443Zone][]*types.NetworkSegment) {
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
	fmt.Fprintln(w, "    industrial_zone [label=\"Industrial Zone\\n(Level 0-2)\", fillcolor=\"#c8e6c9\", style=\"filled,rounded\", shape=\"box\"];")
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
func (g *FirewallDiagramGenerator) generateNetworkNode(w *bufio.Writer, network *types.NetworkSegment) {
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
func (g *FirewallDiagramGenerator) generateFirewallToNetworkConnection(w *bufio.Writer, network *types.NetworkSegment) {
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
func (g *FirewallDiagramGenerator) getZoneColor(zone types.IEC62443Zone) string {
	switch zone {
	case types.IndustrialZone:
		return "#c8e6c9" // Light green
	case types.DMZZone:
		return "#ffe0b2" // Light orange
	case types.EnterpriseZone:
		return "#e1bee7" // Light purple
	case types.RemoteAccessZone:
		return "#b3e5fc" // Light blue
	default:
		return "#f5f5f5" // Light gray
	}
}

// getZoneBorderColor returns the border color for a zone
func (g *FirewallDiagramGenerator) getZoneBorderColor(zone types.IEC62443Zone) string {
	switch zone {
	case types.IndustrialZone:
		return "#2e7d32" // Dark green
	case types.DMZZone:
		return "#f57c00" // Dark orange
	case types.EnterpriseZone:
		return "#7b1fa2" // Dark purple
	case types.RemoteAccessZone:
		return "#0277bd" // Dark blue
	default:
		return "#666666" // Dark gray
	}
}

// Helper functions

func (g *FirewallDiagramGenerator) groupNetworksByZone() map[types.IEC62443Zone][]*types.NetworkSegment {
	zoneNetworks := make(map[types.IEC62443Zone][]*types.NetworkSegment)

	for _, network := range g.model.Networks {
		zoneNetworks[network.Zone] = append(zoneNetworks[network.Zone], network)
	}

	return zoneNetworks
}

func (g *FirewallDiagramGenerator) buildNetworkSegmentLabel(segment *types.NetworkSegment) string {
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

func (g *FirewallDiagramGenerator) getSegmentColor(segment *types.NetworkSegment) string {
	switch segment.Risk {
	case types.HighRisk:
		return "#ffcdd2"
	case types.MediumRisk:
		return "#fff3e0"
	case types.LowRisk:
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

func (g *FirewallDiagramGenerator) getZoneForNetwork(networkRef string) types.IEC62443Zone {
	networkID := g.findNetworkByReference(networkRef)
	if networkID != "" {
		if network, exists := g.model.Networks[networkID]; exists {
			return network.Zone
		}
	}
	return ""
}

func (g *FirewallDiagramGenerator) getZoneRepresentative(zone types.IEC62443Zone, zoneNetworks map[types.IEC62443Zone][]*types.NetworkSegment) string {
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
