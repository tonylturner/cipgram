package types

import (
	"fmt"
	"time"
)

// Protocol represents different industrial and IT protocols
type Protocol string

const (
	// Unknown protocol
	ProtoUnknown Protocol = "Unknown"

	// Industrial Ethernet protocols
	ProtoENIP_Explicit Protocol = "ENIP-TCP-44818"
	ProtoENIP_Implicit Protocol = "ENIP-UDP-2222"
	ProtoModbus        Protocol = "Modbus-TCP-502"
	ProtoDNP3          Protocol = "DNP3-TCP-20000"
	ProtoBACnet        Protocol = "BACnet-UDP-47808"
	ProtoOPCClassic    Protocol = "OPC-TCP-135"
	ProtoOPCUA         Protocol = "OPC-UA-TCP-4840"
	ProtoS7Comm        Protocol = "S7Comm-TCP-102"
	ProtoFins          Protocol = "FINS-TCP-9600"
	ProtoSlmp          Protocol = "SLMP-TCP-5007"
	ProtoMelsecQ       Protocol = "MelsecQ-TCP-1025"
	ProtoOmronTCP      Protocol = "Omron-TCP-20547"
	ProtoCCLink        Protocol = "CC-Link-UDP-18246"
	ProtoSINEC         Protocol = "SINEC-TCP-8834"
	ProtoProfinetDCP   Protocol = "Profinet-DCP-L2-0x8892"
	ProtoProfinetRT    Protocol = "Profinet-RT-L2-0x8892"
	ProtoProconOS      Protocol = "ProconOS-TCP-20547"
	ProtoEGD           Protocol = "EGD-UDP-18246"
	ProtoSRTP          Protocol = "SRTP-TCP-18246"
	ProtoModbusRTU     Protocol = "Modbus-RTU-Serial"

	// Standard IT protocols
	ProtoHTTP   Protocol = "HTTP-TCP-80"
	ProtoHTTPS  Protocol = "HTTPS-TCP-443"
	ProtoSSH    Protocol = "SSH-TCP-22"
	ProtoTelnet Protocol = "Telnet-TCP-23"
	ProtoSNMP   Protocol = "SNMP-UDP-161"
	ProtoFTP    Protocol = "FTP-TCP-21"
	ProtoSMTP   Protocol = "SMTP-TCP-25"
	ProtoDNS    Protocol = "DNS-UDP-53"
	ProtoNTP    Protocol = "NTP-UDP-123"
	ProtoARP    Protocol = "ARP"
	ProtoICMP   Protocol = "ICMP"
	ProtoICMPv6 Protocol = "ICMPv6"
	ProtoDHCP   Protocol = "DHCP"
	ProtoTFTP   Protocol = "TFTP-UDP-69"
	ProtoLDAP   Protocol = "LDAP-TCP-389"
	ProtoRDP    Protocol = "RDP-TCP-3389"
	ProtoVNC    Protocol = "VNC-TCP-5900"
)

// PurdueLevel represents the Purdue Model levels for industrial systems
type PurdueLevel string

const (
	L0      PurdueLevel = "Level 0"   // Physical Process
	L1      PurdueLevel = "Level 1"   // Basic Control
	L2      PurdueLevel = "Level 2"   // Supervisory Control
	L3      PurdueLevel = "Level 3"   // Operations Management
	L3_5    PurdueLevel = "Level 3.5" // DMZ
	L4      PurdueLevel = "Level 4"   // Business Planning
	L5      PurdueLevel = "Level 5"   // Enterprise Network
	Unknown PurdueLevel = "Unknown"
)

// IEC62443Zone represents network security zones based on IEC 62443 principles
type IEC62443Zone string

const (
	IndustrialZone   IEC62443Zone = "Industrial Zone"
	DMZZone          IEC62443Zone = "DMZ Zone"
	EnterpriseZone   IEC62443Zone = "Enterprise Zone"
	SafetyZone       IEC62443Zone = "Safety Zone"
	RemoteAccessZone IEC62443Zone = "Remote Access Zone"
)

// CriticalityLevel represents asset criticality for risk assessment
type CriticalityLevel string

const (
	CriticalAsset CriticalityLevel = "Critical"
	HighAsset     CriticalityLevel = "High"
	MediumAsset   CriticalityLevel = "Medium"
	LowAsset      CriticalityLevel = "Low"
)

// ExposureLevel represents network exposure level
type ExposureLevel string

const (
	InternetExposed  ExposureLevel = "Internet"
	CorporateExposed ExposureLevel = "Corporate"
	OTOnly           ExposureLevel = "OT Only"
)

// RiskLevel represents overall risk assessment
type RiskLevel string

const (
	HighRisk   RiskLevel = "High"
	MediumRisk RiskLevel = "Medium"
	LowRisk    RiskLevel = "Low"
)

// RuleAction represents firewall rule actions
type RuleAction string

const (
	Allow  RuleAction = "ALLOW"
	Deny   RuleAction = "DENY"
	Drop   RuleAction = "DROP"
	Reject RuleAction = "REJECT"
	Log    RuleAction = "LOG"
)

// FlowKey uniquely identifies a network flow
type FlowKey struct {
	SrcIP string   `json:"src_ip"`
	DstIP string   `json:"dst_ip"`
	Proto Protocol `json:"protocol"`
}

// String returns a string representation for use as map keys
func (fk FlowKey) String() string {
	return fmt.Sprintf("%s->%s:%s", fk.SrcIP, fk.DstIP, fk.Proto)
}

// NetworkRange represents a range of network addresses
type NetworkRange struct {
	CIDR string
	IPs  []string
}

// Port represents a network port with protocol information
type Port struct {
	Number   uint16
	Protocol string
}

// Edge represents a network connection between two hosts
type Edge struct {
	Src           string      `json:"src"`
	Dst           string      `json:"dst"`
	Protocol      Protocol    `json:"protocol"`
	Packets       int         `json:"packets"`
	Bytes         int64       `json:"bytes"`
	FirstSeen     time.Time   `json:"first_seen"`
	LastSeen      time.Time   `json:"last_seen"`
	InferredLevel PurdueLevel `json:"inferred_level"`
	Notes         []string    `json:"notes,omitempty"`
	// CIP extras (best-effort)
	CIPService     string `json:"cip_service,omitempty"`
	CIPServiceCode string `json:"cip_service_code,omitempty"`
}

// Host represents a network device/host
type Host struct {
	IP            string          `json:"ip"`
	MAC           string          `json:"mac,omitempty"`
	Hostname      string          `json:"hostname,omitempty"`
	DeviceName    string          `json:"device_name,omitempty"` // From protocol detection
	Vendor        string          `json:"vendor,omitempty"`      // From MAC OUI
	PortsSeen     map[uint16]bool `json:"ports_seen"`
	ICSScore      int             `json:"ics_score"`
	ITScore       int             `json:"it_score"`
	InferredLevel PurdueLevel     `json:"inferred_level"`
	Roles         []string        `json:"roles,omitempty"`
	MulticastPeer bool            `json:"multicast_peer"`

	// Stats built from edges (for heuristic classification)
	PeersByProtoInitiated map[Protocol]map[string]bool `json:"-"`
	PeersByProtoReceived  map[Protocol]map[string]bool `json:"-"`
	InitiatedCounts       map[Protocol]int             `json:"-"`
	ReceivedCounts        map[Protocol]int             `json:"-"`

	// Mapping override (from YAML)
	OverrideLevel *PurdueLevel `json:"override_level,omitempty"`
	OverrideRole  string       `json:"override_role,omitempty"`
}

// Graph represents the network topology
type Graph struct {
	Hosts map[string]*Host  `json:"hosts"`
	Edges map[FlowKey]*Edge `json:"edges"`
}

// Asset represents a network device/host with enhanced segmentation context
type Asset struct {
	ID                    string
	IP                    string
	MAC                   string
	Hostname              string
	DeviceName            string
	Vendor                string
	OS                    string // Operating system from fingerprinting
	Model                 string // Device model from fingerprinting
	Version               string // Software/firmware version
	PurdueLevel           PurdueLevel
	IEC62443Zone          IEC62443Zone
	Roles                 []string
	Protocols             []Protocol
	Criticality           CriticalityLevel
	Exposure              ExposureLevel
	FingerprintingDetails map[string]interface{} // Enhanced fingerprinting metadata
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
	Allowed     bool // Based on firewall policies
}

// Configuration mapping types
type MappingTable struct {
	Mappings []SubnetMapping `yaml:"mappings"`
}

type SubnetMapping struct {
	CIDR  string      `yaml:"cidr"`
	Level PurdueLevel `yaml:"level"`
	Role  string      `yaml:"role,omitempty"`
}

// DiagramType represents different diagram layouts
type DiagramType string

const (
	PurdueDiagram  DiagramType = "purdue"
	NetworkDiagram DiagramType = "network"
	BothDiagrams   DiagramType = "both"
)

// AnalysisType represents different types of analysis
type AnalysisType string

const (
	AnalysisTypePCAP     AnalysisType = "pcap"
	AnalysisTypeFirewall AnalysisType = "firewall"
	AnalysisTypeCombined AnalysisType = "combined"
)
