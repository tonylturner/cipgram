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
		if iface == nil || iface.Enable != "1" {
			continue // Skip disabled or nil interfaces
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
	for _, rule := range p.config.Filter.Rules {
		// Skip rules without UUID (malformed)
		if rule.UUID == "" {
			continue
		}

		policy := &interfaces.SecurityPolicy{
			ID:          rule.UUID,
			Description: rule.Descr,
			Enabled:     true, // OPNsense doesn't have disabled field in this format
			Action:      p.mapRuleAction(rule.Type),
			Zone:        rule.Interface,
		}

		// Parse source and destination
		policy.Source = p.parseRuleTarget(rule.Source)
		policy.Destination = p.parseRuleTarget(rule.Destination)

		// Parse protocol
		if rule.Protocol != "" {
			policy.Protocol = interfaces.Protocol(rule.Protocol)
		}

		model.Policies = append(model.Policies, policy)
	}

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
		return interfaces.ManufacturingZone // LAN often contains OT devices
	case strings.Contains(strings.ToLower(purpose), "production"):
		return interfaces.ManufacturingZone
	case strings.Contains(strings.ToLower(purpose), "dmz"):
		return interfaces.DMZZone
	case strings.Contains(strings.ToLower(purpose), "management"):
		return interfaces.EnterpriseZone
	case strings.Contains(strings.ToLower(name), "wireguard") || strings.Contains(strings.ToLower(iface.Descr), "wireguard"):
		return interfaces.RemoteAccessZone
	default:
		return interfaces.EnterpriseZone
	}
}

func (p *OPNsenseParser) inferPurpose(descr, ifName string) string {
	lower := strings.ToLower(descr + " " + ifName)

	if strings.Contains(lower, "production") || strings.Contains(lower, "ot") {
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
	case interfaces.ManufacturingZone:
		return interfaces.HighRisk // Critical OT systems
	case interfaces.DMZZone:
		return interfaces.MediumRisk
	default:
		return interfaces.LowRisk
	}
}
