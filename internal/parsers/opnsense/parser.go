package opnsense

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"cipgram/internal/interfaces"
)

// OPNsenseParser implements InputSource for OPNsense firewall configurations
type OPNsenseParser struct {
	configPath string
	config     *OPNsenseConfig
}

// NewOPNsenseParser creates a new OPNsense configuration parser
func NewOPNsenseParser(configPath string) *OPNsenseParser {
	return &OPNsenseParser{
		configPath: configPath,
	}
}

// Parse implements InputSource.Parse for OPNsense configs
func (p *OPNsenseParser) Parse() (*interfaces.NetworkModel, error) {
	// Load and parse XML configuration
	if err := p.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	model := &interfaces.NetworkModel{
		Assets:   make(map[string]*interfaces.Asset),
		Networks: make(map[string]*interfaces.NetworkSegment),
		Flows:    make(map[interfaces.FlowKey]*interfaces.Flow),
		Policies: []*interfaces.SecurityPolicy{},
		Metadata: p.GetMetadata(),
	}

	// Parse network interfaces and create segments
	if err := p.parseInterfaces(model); err != nil {
		return nil, fmt.Errorf("failed to parse interfaces: %v", err)
	}

	// Parse firewall rules and create policies
	if err := p.parseFirewallRules(model); err != nil {
		return nil, fmt.Errorf("failed to parse firewall rules: %v", err)
	}

	// Parse aliases for network groupings
	if err := p.parseAliases(model); err != nil {
		return nil, fmt.Errorf("failed to parse aliases: %v", err)
	}

	// Infer zones and risk levels
	p.inferZones(model)
	p.assessRisk(model)

	return model, nil
}

// GetMetadata implements InputSource.GetMetadata
func (p *OPNsenseParser) GetMetadata() interfaces.InputMetadata {
	info, _ := os.Stat(p.configPath)
	size := int64(0)
	modTime := time.Now()

	if info != nil {
		size = info.Size()
		modTime = info.ModTime()
	}

	return interfaces.InputMetadata{
		Source:    p.configPath,
		Type:      interfaces.InputTypeOPNsense,
		Timestamp: modTime,
		Size:      size,
		Hash:      "", // TODO: Calculate file hash
	}
}

// GetType implements InputSource.GetType
func (p *OPNsenseParser) GetType() interfaces.InputType {
	return interfaces.InputTypeOPNsense
}

// loadConfig loads and parses the OPNsense XML configuration file
func (p *OPNsenseParser) loadConfig() error {
	file, err := os.Open(p.configPath)
	if err != nil {
		return fmt.Errorf("cannot open config file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("cannot read config file: %v", err)
	}

	var config OPNsenseConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("cannot parse XML config: %v", err)
	}

	p.config = &config
	return nil
}

// parseInterfaces creates network segments from OPNsense interfaces
func (p *OPNsenseParser) parseInterfaces(model *interfaces.NetworkModel) error {
	allInterfaces := p.config.Interfaces.GetAllInterfaces()

	for name, iface := range allInterfaces {
		if iface == nil {
			continue // Skip nil interfaces
		}

		// Skip explicitly disabled interfaces (enable="0")
		// If no enable field is present, treat as enabled (OPNsense default)
		if iface.Enable == "0" {
			continue
		}

		// Skip virtual and internal interfaces for now
		if iface.Virtual == "1" || iface.Internal == "1" {
			continue
		}

		// Create network segment
		segment := &interfaces.NetworkSegment{
			ID:       name,
			Name:     iface.Descr,
			Assets:   []*interfaces.Asset{},
			Policies: []*interfaces.SecurityPolicy{},
			Purpose:  p.inferPurpose(iface.Descr, name),
		}

		// Build CIDR from IP and subnet
		if iface.IPAddr != "" && iface.IPAddr != "dhcp" && iface.Subnet != "" {
			segment.CIDR = p.buildCIDR(iface.IPAddr, iface.Subnet)
		}

		// Infer zone based on interface name/description
		segment.Zone = p.inferZoneFromInterface(name, iface)

		model.Networks[segment.ID] = segment
	}

	return nil
}

// parseFirewallRules creates security policies from firewall rules
func (p *OPNsenseParser) parseFirewallRules(model *interfaces.NetworkModel) error {
	for i, rule := range p.config.Filter.Rules {
		// Generate ID: use UUID if available, otherwise create one from index
		ruleID := rule.UUID
		if ruleID == "" {
			ruleID = fmt.Sprintf("rule-%d", i+1)
		}

		policy := &interfaces.SecurityPolicy{
			ID:          ruleID,
			Description: rule.Descr,
			Enabled:     true, // OPNsense doesn't have disabled field in this format
			Action:      p.mapRuleAction(rule.Type),
			Zone:        rule.Interface,
		}

		// Parse source and destination
		policy.Source = p.parseRuleTarget(rule.Source)
		policy.Destination = p.parseRuleTarget(rule.Destination)

		// Parse protocol and ports
		if rule.Protocol != "" {
			policy.Protocol = interfaces.Protocol(rule.Protocol)
		}

		// Parse ports and add them to the policy
		policy.Ports = p.parsePorts(rule.SrcPort, rule.DstPort, rule.Protocol)

		model.Policies = append(model.Policies, policy)
	}

	// Add implicit default deny rule (OPNsense behavior)
	defaultDeny := &interfaces.SecurityPolicy{
		ID:          "implicit-default-deny",
		Description: "Implicit default deny (built-in OPNsense behavior)",
		Enabled:     true,
		Action:      "DENY",
		Zone:        "all",
		Source: interfaces.NetworkRange{
			CIDR: "any",
			IPs:  []string{},
		},
		Destination: interfaces.NetworkRange{
			CIDR: "any",
			IPs:  []string{},
		},
		Protocol: "any",
		Ports:    []interfaces.Port{},
	}

	model.Policies = append(model.Policies, defaultDeny)

	return nil
}

// parseAliases processes network aliases for grouping
func (p *OPNsenseParser) parseAliases(model *interfaces.NetworkModel) error {
	// OPNsense aliases help identify network groupings
	// This can be used to enhance our network segments
	return nil // TODO: Implement alias parsing
}

// inferZones assigns IEC 62443 zones based on network analysis
func (p *OPNsenseParser) inferZones(model *interfaces.NetworkModel) {
	for _, segment := range model.Networks {
		if segment.Zone == "" {
			segment.Zone = p.inferZoneFromSegment(segment)
		}
	}
}

// assessRisk evaluates risk levels for network segments
func (p *OPNsenseParser) assessRisk(model *interfaces.NetworkModel) {
	for _, segment := range model.Networks {
		segment.Risk = p.calculateSegmentRisk(segment, model.Policies)
	}
}

// Helper functions

func (p *OPNsenseParser) buildCIDR(ip, subnet string) string {
	if ip == "" || subnet == "" {
		return ""
	}

	// Subnet is already in CIDR format (e.g., "24")
	return fmt.Sprintf("%s/%s", ip, subnet)
}

func (p *OPNsenseParser) parseRuleTarget(target RuleTarget) interfaces.NetworkRange {
	if target.Any == "1" {
		return interfaces.NetworkRange{
			CIDR: "any",
			IPs:  []string{},
		}
	}

	if target.Network != "" {
		// Handle network references like "lan", "wan", "opt5ip", etc.
		return interfaces.NetworkRange{
			CIDR: target.Network,
			IPs:  []string{},
		}
	}

	return interfaces.NetworkRange{}
}

func (p *OPNsenseParser) inferZoneFromInterface(name string, iface *Interface) interfaces.IEC62443Zone {
	purpose := p.inferPurpose(iface.Descr, name)

	switch {
	case strings.Contains(strings.ToLower(name), "wan"):
		return interfaces.DMZZone // WAN typically goes to DMZ
	case strings.Contains(strings.ToLower(name), "lan"):
		return interfaces.IndustrialZone // LAN often contains OT devices
	case strings.Contains(strings.ToLower(purpose), "production"):
		return interfaces.IndustrialZone
	case strings.Contains(strings.ToLower(purpose), "dmz"):
		return interfaces.DMZZone
	case strings.Contains(strings.ToLower(purpose), "management"):
		return interfaces.EnterpriseZone
	case strings.Contains(strings.ToLower(purpose), "corporate"):
		return interfaces.EnterpriseZone
	case strings.Contains(strings.ToLower(name), "wireguard") || strings.Contains(strings.ToLower(iface.Descr), "wireguard"):
		return interfaces.RemoteAccessZone
	// Check for industrial terms directly in interface description
	case strings.Contains(strings.ToLower(iface.Descr), "cell") ||
		strings.Contains(strings.ToLower(iface.Descr), "line") ||
		strings.Contains(strings.ToLower(iface.Descr), "plant") ||
		strings.Contains(strings.ToLower(iface.Descr), "factory") ||
		strings.Contains(strings.ToLower(iface.Descr), "manufacturing") ||
		strings.Contains(strings.ToLower(iface.Descr), "industrial") ||
		strings.Contains(strings.ToLower(iface.Descr), "scada") ||
		strings.Contains(strings.ToLower(iface.Descr), "control") ||
		strings.Contains(strings.ToLower(iface.Descr), "process") ||
		strings.Contains(strings.ToLower(iface.Descr), "automation"):
		return interfaces.IndustrialZone
	// Check for corporate/IT terms directly in interface description
	case strings.Contains(strings.ToLower(iface.Descr), "corp") ||
		strings.Contains(strings.ToLower(iface.Descr), "corporate") ||
		strings.Contains(strings.ToLower(iface.Descr), "office") ||
		strings.Contains(strings.ToLower(iface.Descr), "business") ||
		strings.Contains(strings.ToLower(iface.Descr), "enterprise"):
		return interfaces.EnterpriseZone
	// "site" is ambiguous - could be manufacturing site or corporate site
	// Default to Enterprise for general site infrastructure
	case strings.Contains(strings.ToLower(iface.Descr), "site"):
		return interfaces.EnterpriseZone
	default:
		return interfaces.EnterpriseZone
	}
}

// parsePorts parses port specifications from OPNsense rules
func (p *OPNsenseParser) parsePorts(srcPort, dstPort, protocol string) []interfaces.Port {
	var ports []interfaces.Port

	// Parse destination ports (most common)
	if dstPort != "" {
		ports = append(ports, p.parsePortString(dstPort, "destination", protocol)...)
	}

	// Parse source ports (less common)
	if srcPort != "" {
		ports = append(ports, p.parsePortString(srcPort, "source", protocol)...)
	}

	return ports
}

// parsePortString parses a port string like "22,443" or "8080-8090" or "OT_MGMT_PORTS"
func (p *OPNsenseParser) parsePortString(portStr, direction, protocol string) []interfaces.Port {
	var ports []interfaces.Port

	if portStr == "" {
		return ports
	}

	// Handle aliases (like "OT_MGMT_PORTS", "VENDOR_VPN_PORTS")
	if !strings.Contains(portStr, ",") && !strings.Contains(portStr, "-") && !isNumeric(portStr) {
		// This is likely an alias - resolve it if possible, otherwise use as-is
		resolvedPorts := p.resolvePortAlias(portStr)
		if resolvedPorts != "" {
			portStr = resolvedPorts
		} else {
			// Keep the alias name for display - use port 0 with protocol containing the alias
			ports = append(ports, interfaces.Port{
				Number:   0,                                       // Unknown port number
				Protocol: fmt.Sprintf("%s:%s", protocol, portStr), // Include alias in protocol
			})
			return ports
		}
	}

	// Split by commas for multiple ports
	portParts := strings.Split(portStr, ",")
	for _, part := range portParts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "-") {
			// Handle port ranges like "8080-8090"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				startPort := parsePortNumber(strings.TrimSpace(rangeParts[0]))
				endPort := parsePortNumber(strings.TrimSpace(rangeParts[1]))

				if startPort > 0 && endPort > 0 && endPort >= startPort {
					// For ranges, just add the start port with range info in protocol
					ports = append(ports, interfaces.Port{
						Number:   uint16(startPort),
						Protocol: fmt.Sprintf("%s:%d-%d", protocol, startPort, endPort),
					})
				}
			}
		} else {
			// Single port
			portNum := parsePortNumber(part)
			if portNum > 0 {
				portName := getPortName(portNum)
				protocol_with_name := fmt.Sprintf("%s:%s", protocol, portName)
				ports = append(ports, interfaces.Port{
					Number:   uint16(portNum),
					Protocol: protocol_with_name,
				})
			}
		}
	}

	return ports
}

// resolvePortAlias tries to resolve port aliases from the configuration
func (p *OPNsenseParser) resolvePortAlias(aliasName string) string {
	// Look through aliases to find port type aliases
	for _, alias := range p.config.Aliases.Alias {
		if alias.Name == aliasName && alias.Type == "port" {
			return alias.Address
		}
	}
	return ""
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// parsePortNumber converts a string to a port number
func parsePortNumber(s string) int {
	if !isNumeric(s) {
		return 0
	}

	num := 0
	for _, r := range s {
		num = num*10 + int(r-'0')
	}

	if num > 65535 {
		return 0 // Invalid port
	}

	return num
}

// getPortName returns common service names for well-known ports
func getPortName(port int) string {
	wellKnownPorts := map[int]string{
		22:   "SSH",
		23:   "Telnet",
		53:   "DNS",
		80:   "HTTP",
		123:  "NTP",
		443:  "HTTPS",
		502:  "Modbus",
		1194: "OpenVPN",
		1883: "MQTT",
		3389: "RDP",
		4840: "OPC-UA",
		8086: "InfluxDB",
		8883: "MQTTS",
	}

	if name, exists := wellKnownPorts[port]; exists {
		return name
	}

	return fmt.Sprintf("Port-%d", port)
}

func (p *OPNsenseParser) inferPurpose(descr, ifName string) string {
	lower := strings.ToLower(descr + " " + ifName)

	// Industrial/OT terms - expanded list
	if strings.Contains(lower, "production") || strings.Contains(lower, "ot") ||
		strings.Contains(lower, "cell") || strings.Contains(lower, "line") ||
		strings.Contains(lower, "plant") || strings.Contains(lower, "factory") ||
		strings.Contains(lower, "manufacturing") || strings.Contains(lower, "industrial") ||
		strings.Contains(lower, "scada") || strings.Contains(lower, "hmi") ||
		strings.Contains(lower, "plc") || strings.Contains(lower, "control") ||
		strings.Contains(lower, "process") || strings.Contains(lower, "automation") ||
		strings.Contains(lower, "field") || strings.Contains(lower, "shop") ||
		strings.Contains(lower, "assembly") || strings.Contains(lower, "packaging") ||
		strings.Contains(lower, "machining") || strings.Contains(lower, "welding") ||
		strings.Contains(lower, "robotics") || strings.Contains(lower, "cnc") {
		return "Production OT"
	}
	if strings.Contains(lower, "dmz") {
		return "DMZ"
	}
	if strings.Contains(lower, "management") || strings.Contains(lower, "admin") {
		return "Management"
	}
	if strings.Contains(lower, "wan") || strings.Contains(lower, "internet") {
		return "Internet"
	}
	// Corporate/IT terms
	if strings.Contains(lower, "corp") || strings.Contains(lower, "corporate") ||
		strings.Contains(lower, "office") || strings.Contains(lower, "business") ||
		strings.Contains(lower, "enterprise") || strings.Contains(lower, "it") {
		return "Corporate IT"
	}
	// Site-wide infrastructure
	if strings.Contains(lower, "site") || strings.Contains(lower, "campus") ||
		strings.Contains(lower, "facility") {
		return "Site Infrastructure"
	}

	return "General"
}

func (p *OPNsenseParser) inferZoneFromSegment(segment *interfaces.NetworkSegment) interfaces.IEC62443Zone {
	// Use interface name from segment ID to infer zone
	return p.inferZoneFromInterface(segment.ID, &Interface{
		Descr: segment.Name,
	})
}

func (p *OPNsenseParser) mapRuleAction(ruleType string) interfaces.RuleAction {
	switch strings.ToLower(ruleType) {
	case "pass":
		return interfaces.Allow
	case "block", "reject":
		return interfaces.Deny
	default:
		return interfaces.Deny
	}
}

func (p *OPNsenseParser) calculateSegmentRisk(segment *interfaces.NetworkSegment, policies []*interfaces.SecurityPolicy) interfaces.RiskLevel {
	// Simple risk assessment based on zone and policies
	switch segment.Zone {
	case interfaces.IndustrialZone:
		return interfaces.HighRisk // Critical OT systems
	case interfaces.DMZZone:
		return interfaces.MediumRisk
	default:
		return interfaces.LowRisk
	}
}
