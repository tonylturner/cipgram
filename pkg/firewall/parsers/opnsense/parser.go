package opnsense

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"cipgram/pkg/types"
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
func (p *OPNsenseParser) Parse() (*types.NetworkModel, error) {
	// Load and parse XML configuration
	if err := p.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	model := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: []*types.SecurityPolicy{},
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
func (p *OPNsenseParser) GetMetadata() types.InputMetadata {
	info, _ := os.Stat(p.configPath)
	size := int64(0)
	modTime := time.Now()

	if info != nil {
		size = info.Size()
		modTime = info.ModTime()
	}

	return types.InputMetadata{
		Source:    p.configPath,
		Type:      types.InputTypeOPNsense,
		Timestamp: modTime,
		Size:      size,
		Hash:      calculateFileHash(p.configPath),
	}
}

// GetType implements InputSource.GetType
func (p *OPNsenseParser) GetType() types.InputType {
	return types.InputTypeOPNsense
}

// Validate implements FirewallParser.Validate
func (p *OPNsenseParser) Validate() error {
	// Check if config file exists
	if _, err := os.Stat(p.configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", p.configPath)
	}

	// Try to load and parse the config to validate XML structure
	if err := p.loadConfig(); err != nil {
		return fmt.Errorf("invalid OPNsense configuration: %v", err)
	}

	return nil
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
func (p *OPNsenseParser) parseInterfaces(model *types.NetworkModel) error {
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
		segment := &types.NetworkSegment{
			ID:       name,
			Name:     iface.Descr,
			Assets:   []*types.Asset{},
			Policies: []*types.SecurityPolicy{},
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
func (p *OPNsenseParser) parseFirewallRules(model *types.NetworkModel) error {
	for i, rule := range p.config.Filter.Rules {
		// Generate ID: use UUID if available, otherwise create one from index
		ruleID := rule.UUID
		if ruleID == "" {
			ruleID = fmt.Sprintf("rule-%d", i+1)
		}

		policy := &types.SecurityPolicy{
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
			policy.Protocol = types.Protocol(rule.Protocol)
		}

		// Parse ports and add them to the policy
		policy.Ports = p.parsePorts(rule.SrcPort, rule.DstPort, rule.Protocol)

		model.Policies = append(model.Policies, policy)
	}

	// Add implicit default deny rule (OPNsense behavior)
	defaultDeny := &types.SecurityPolicy{
		ID:          "implicit-default-deny",
		Description: "Implicit default deny (built-in OPNsense behavior)",
		Enabled:     true,
		Action:      "DENY",
		Zone:        "all",
		Source: types.NetworkRange{
			CIDR: "any",
			IPs:  []string{},
		},
		Destination: types.NetworkRange{
			CIDR: "any",
			IPs:  []string{},
		},
		Protocol: "any",
		Ports:    []types.Port{},
	}

	model.Policies = append(model.Policies, defaultDeny)

	return nil
}

// parseAliases processes network aliases for grouping
func (p *OPNsenseParser) parseAliases(model *types.NetworkModel) error {
	// OPNsense aliases help identify network groupings and can enhance our network segments
	// Implementation plan:
	// 1. Parse p.config.Aliases.Alias array
	// 2. For each alias of type "network" or "host":
	//    - Extract CIDR ranges or individual IPs
	//    - Associate with existing network segments
	//    - Create new segments if needed
	// 3. For port aliases: enhance security policy port mappings
	// 4. Update segment names and descriptions based on alias names

	if p.config == nil || len(p.config.Aliases.Alias) == 0 {
		return nil // No aliases to process
	}

	log.Printf("Found %d aliases in configuration (parsing not yet implemented)", len(p.config.Aliases.Alias))
	return nil
}

// inferZones assigns IEC 62443 zones based on network analysis
func (p *OPNsenseParser) inferZones(model *types.NetworkModel) {
	for _, segment := range model.Networks {
		if segment.Zone == "" {
			segment.Zone = p.inferZoneFromSegment(segment)
		}
	}
}

// assessRisk evaluates risk levels for network segments
func (p *OPNsenseParser) assessRisk(model *types.NetworkModel) {
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

func (p *OPNsenseParser) parseRuleTarget(target RuleTarget) types.NetworkRange {
	if target.Any == "1" {
		return types.NetworkRange{
			CIDR: "any",
			IPs:  []string{},
		}
	}

	if target.Network != "" {
		// Handle network references like "lan", "wan", "opt5ip", etc.
		return types.NetworkRange{
			CIDR: target.Network,
			IPs:  []string{},
		}
	}

	return types.NetworkRange{}
}

func (p *OPNsenseParser) inferZoneFromInterface(name string, iface *Interface) types.IEC62443Zone {
	purpose := p.inferPurpose(iface.Descr, name)

	switch {
	case strings.Contains(strings.ToLower(name), "wan"):
		return types.DMZZone // WAN typically goes to DMZ
	case strings.Contains(strings.ToLower(name), "lan"):
		return types.IndustrialZone // LAN often contains OT devices
	case strings.Contains(strings.ToLower(purpose), "production"):
		return types.IndustrialZone
	case strings.Contains(strings.ToLower(purpose), "dmz"):
		return types.DMZZone
	case strings.Contains(strings.ToLower(purpose), "management"):
		return types.EnterpriseZone
	case strings.Contains(strings.ToLower(purpose), "corporate"):
		return types.EnterpriseZone
	case strings.Contains(strings.ToLower(name), "wireguard") || strings.Contains(strings.ToLower(iface.Descr), "wireguard"):
		return types.RemoteAccessZone
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
		return types.IndustrialZone
	// Check for corporate/IT terms directly in interface description
	case strings.Contains(strings.ToLower(iface.Descr), "corp") ||
		strings.Contains(strings.ToLower(iface.Descr), "corporate") ||
		strings.Contains(strings.ToLower(iface.Descr), "office") ||
		strings.Contains(strings.ToLower(iface.Descr), "business") ||
		strings.Contains(strings.ToLower(iface.Descr), "enterprise"):
		return types.EnterpriseZone
	// "site" is ambiguous - could be manufacturing site or corporate site
	// Default to Enterprise for general site infrastructure
	case strings.Contains(strings.ToLower(iface.Descr), "site"):
		return types.EnterpriseZone
	default:
		return types.EnterpriseZone
	}
}

// parsePorts parses port specifications from OPNsense rules
func (p *OPNsenseParser) parsePorts(srcPort, dstPort, protocol string) []types.Port {
	var ports []types.Port

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
func (p *OPNsenseParser) parsePortString(portStr, direction, protocol string) []types.Port {
	var ports []types.Port

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
			ports = append(ports, types.Port{
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
					ports = append(ports, types.Port{
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
				ports = append(ports, types.Port{
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

// parsePortNumber converts a string to a port number using standard library
func parsePortNumber(s string) int {
	if s == "" {
		return 0
	}

	num, err := strconv.Atoi(s)
	if err != nil {
		return 0 // Invalid number format
	}

	if num < 0 || num > 65535 {
		return 0 // Invalid port range
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

func (p *OPNsenseParser) inferZoneFromSegment(segment *types.NetworkSegment) types.IEC62443Zone {
	// Use interface name from segment ID to infer zone
	return p.inferZoneFromInterface(segment.ID, &Interface{
		Descr: segment.Name,
	})
}

func (p *OPNsenseParser) mapRuleAction(ruleType string) types.RuleAction {
	switch strings.ToLower(ruleType) {
	case "pass":
		return types.Allow
	case "block", "reject":
		return types.Deny
	default:
		return types.Deny
	}
}

func (p *OPNsenseParser) calculateSegmentRisk(segment *types.NetworkSegment, policies []*types.SecurityPolicy) types.RiskLevel {
	// Simple risk assessment based on zone and policies
	switch segment.Zone {
	case types.IndustrialZone:
		return types.HighRisk // Critical OT systems
	case types.DMZZone:
		return types.MediumRisk
	default:
		return types.LowRisk
	}
}

// calculateFileHash computes SHA256 hash of a file for integrity checking
func calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Warning: Failed to calculate file hash for %s: %v", filePath, err)
		return ""
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		log.Printf("Warning: Failed to calculate file hash for %s: %v", filePath, err)
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
