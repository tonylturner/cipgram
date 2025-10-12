package firewall

import (
	"cipgram/pkg/firewall/parsers/firewalla"
	"cipgram/pkg/firewall/parsers/fortigate"
	"cipgram/pkg/firewall/parsers/iptables"
	"cipgram/pkg/firewall/parsers/opnsense"
	"cipgram/pkg/firewall/parsers/vyatta"
	"cipgram/pkg/types"
	"fmt"
)

// FirewallParser defines the interface for all firewall configuration parsers
type FirewallParser interface {
	Parse() (*types.NetworkModel, error)
	GetType() types.InputType
	GetMetadata() types.InputMetadata
	Validate() error
}

// ParserFactory creates appropriate parser based on firewall type
type ParserFactory struct{}

// NewParser creates a parser for the given firewall configuration file
func (f *ParserFactory) NewParser(configPath string, firewallType types.InputType) (FirewallParser, error) {
	switch firewallType {
	case types.InputTypeOPNsense:
		return opnsense.NewOPNsenseParser(configPath), nil
	case types.InputTypeFortiGate:
		return fortigate.NewFortiGateParser(configPath), nil
	case types.InputTypeVyatta:
		return vyatta.NewVyattaParser(configPath), nil
	case types.InputTypeIptables:
		return iptables.NewIptablesParser(configPath), nil
	case types.InputTypeFirewalla:
		return firewalla.NewFirewallaParser(configPath), nil
	default:
		return nil, fmt.Errorf("unsupported firewall type: %s", firewallType)
	}
}

// DetectFirewallType attempts to detect firewall type from config file
func DetectFirewallType(configPath string) (types.InputType, error) {
	// TODO: Implement auto-detection logic based on file content
	// For now, return unknown and require explicit type specification
	return "", fmt.Errorf("firewall type auto-detection not yet implemented")
}

// Common firewall configuration structures
type CommonFirewallConfig struct {
	Interfaces  []Interface
	Rules       []Rule
	NATPolicies []NATPolicy
	VPNConfigs  []VPNConfig
}

type Interface struct {
	Name        string
	Description string
	IPAddress   string
	Subnet      string
	Zone        string
	Enabled     bool
}

type Rule struct {
	ID          string
	Name        string
	Source      types.NetworkRange
	Destination types.NetworkRange
	Ports       []types.Port
	Protocol    types.Protocol
	Action      types.RuleAction
	Zone        string
	Enabled     bool
	Description string
}

type NATPolicy struct {
	ID                    string
	Source                types.NetworkRange
	Destination           types.NetworkRange
	TranslatedSource      types.NetworkRange
	TranslatedDestination types.NetworkRange
	Description           string
}

type VPNConfig struct {
	ID             string
	Type           string
	RemoteGateway  string
	LocalNetworks  []string
	RemoteNetworks []string
	Description    string
}
