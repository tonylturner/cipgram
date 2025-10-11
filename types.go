package main

import (
	"time"
)

// Protocol constants and data types
type Protocol string

const (
	ProtoUnknown       Protocol = "Unknown"
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
)

type PurdueLevel string

const (
	L1      PurdueLevel = "Level 1"
	L2      PurdueLevel = "Level 2"
	L3      PurdueLevel = "Level 3"
	Unknown PurdueLevel = "Unknown"
)

type FlowKey struct {
	SrcIP, DstIP string
	Proto        Protocol
}

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

type Graph struct {
	Hosts map[string]*Host  `json:"hosts"`
	Edges map[FlowKey]*Edge `json:"edges"`
}

type MappingTable struct {
	Mappings []SubnetMapping `yaml:"mappings"`
}

type SubnetMapping struct {
	CIDR  string      `yaml:"cidr"`
	Level PurdueLevel `yaml:"level"`
	Role  string      `yaml:"role,omitempty"`
}
