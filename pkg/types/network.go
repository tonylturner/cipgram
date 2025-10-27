package types

import (
	"time"
)

// InputSource defines the interface for different input types (PCAP, firewall configs, etc.)
type InputSource interface {
	Parse() (*NetworkModel, error)
	GetMetadata() InputMetadata
	GetType() InputType
}

// InputType represents different types of input sources
type InputType string

const (
	InputTypePCAP      InputType = "pcap"
	InputTypeOPNsense  InputType = "opnsense"
	InputTypePfSense   InputType = "pfsense"
	InputTypeFortiGate InputType = "fortigate"
	InputTypeVyatta    InputType = "vyatta"
	InputTypeIptables  InputType = "iptables"
	InputTypeFirewalla InputType = "firewalla"
)

// InputMetadata contains information about the input source
type InputMetadata struct {
	Source    string
	Type      InputType
	Timestamp time.Time
	Size      int64
	Hash      string // For integrity checking
}

// NetworkModel represents the unified data model from all input sources
type NetworkModel struct {
	Assets   map[string]*Asset
	Networks map[string]*NetworkSegment
	Flows    map[FlowKey]*Flow
	Policies []*SecurityPolicy
	Metadata InputMetadata
}

// AnalysisResult represents the output of network analysis
type AnalysisResult struct {
	Model           *NetworkModel
	Summary         *AnalysisSummary
	Risks           []*RiskAssessment
	Recommendations []*Recommendation
}

// AnalysisSummary provides high-level analysis statistics
type AnalysisSummary struct {
	TotalAssets      int
	TotalNetworks    int
	TotalPolicies    int
	TotalFlows       int
	ProtocolsFound   []Protocol
	ZonesIdentified  []IEC62443Zone
	RiskDistribution map[RiskLevel]int
}

// RiskAssessment represents identified security risks
type RiskAssessment struct {
	ID          string
	Type        string
	Severity    RiskLevel
	Description string
	Assets      []string
	Networks    []string
	Policies    []string
}

// Recommendation represents security improvement suggestions
type Recommendation struct {
	ID          string
	Priority    int
	Category    string
	Title       string
	Description string
	Actions     []string
}

// ParserConfig represents configuration options for parsers
type ParserConfig struct {
	EnableVendorLookup   bool
	EnableHostnameResolv bool
	FastMode             bool
	MaxNodes             int
	TimeoutSeconds       int
}
