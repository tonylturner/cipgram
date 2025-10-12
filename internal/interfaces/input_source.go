package interfaces

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
	InputTypePfSense   InputType = "pfsense"   // Future
	InputTypeFortiGate InputType = "fortigate" // Future
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
	Policies []*SecurityPolicy // NEW: from firewall configs
	Metadata InputMetadata
}

// Asset represents a network device/host with enhanced segmentation context
type Asset struct {
	ID           string
	IP           string
	MAC          string
	Hostname     string
	DeviceName   string
	Vendor       string
	PurdueLevel  PurdueLevel
	IEC62443Zone IEC62443Zone // NEW: for 62443 compliance
	Roles        []string
	Protocols    []Protocol
	Criticality  CriticalityLevel // NEW: for risk assessment
	Exposure     ExposureLevel    // NEW: internet, corporate, OT-only
}

// NetworkSegment represents a logical or physical network segment
type NetworkSegment struct {
	ID       string
	CIDR     string
	Name     string
	Zone     IEC62443Zone
	Assets   []*Asset
	Policies []*SecurityPolicy
	Risk     RiskLevel
	Purpose  string // "Production", "Development", "DMZ", etc.
}

// SecurityPolicy represents firewall rules and network policies
type SecurityPolicy struct {
	ID          string
	Source      NetworkRange
	Destination NetworkRange
	Ports       []Port
	Protocol    Protocol
	Action      RuleAction
	Zone        string
	Description string
	Enabled     bool
}

// Flow represents communication between assets
type Flow struct {
	Source      string
	Destination string
	Protocol    Protocol
	Ports       []Port
	Packets     int64
	Bytes       int64
	FirstSeen   time.Time
	LastSeen    time.Time
	Allowed     bool // NEW: based on firewall policies
}

// New types for enhanced segmentation planning
type PurdueLevel string
type IEC62443Zone string
type CriticalityLevel string
type ExposureLevel string
type RiskLevel string
type RuleAction string
type Protocol string

// Constants for new types
const (
	// Purdue Model Levels
	L1      PurdueLevel = "Level 1"
	L2      PurdueLevel = "Level 2"
	L3      PurdueLevel = "Level 3"
	Unknown PurdueLevel = "Unknown"

	// IEC 62443 Zones
	IndustrialZone   IEC62443Zone = "Industrial Zone"
	DMZZone          IEC62443Zone = "DMZ Zone"
	EnterpriseZone   IEC62443Zone = "Enterprise Zone"
	SafetyZone       IEC62443Zone = "Safety Zone"
	RemoteAccessZone IEC62443Zone = "Remote Access Zone"

	// Criticality Levels
	CriticalAsset CriticalityLevel = "Critical"
	HighAsset     CriticalityLevel = "High"
	MediumAsset   CriticalityLevel = "Medium"
	LowAsset      CriticalityLevel = "Low"

	// Exposure Levels
	InternetExposed  ExposureLevel = "Internet"
	CorporateExposed ExposureLevel = "Corporate"
	OTOnly           ExposureLevel = "OT Only"

	// Risk Levels
	HighRisk   RiskLevel = "High"
	MediumRisk RiskLevel = "Medium"
	LowRisk    RiskLevel = "Low"

	// Rule Actions
	Allow RuleAction = "ALLOW"
	Deny  RuleAction = "DENY"
	Log   RuleAction = "LOG"
)

// Supporting types
type FlowKey struct {
	SrcIP, DstIP string
	Proto        Protocol
}

type NetworkRange struct {
	CIDR string
	IPs  []string
}

type Port struct {
	Number   uint16
	Protocol string
}
