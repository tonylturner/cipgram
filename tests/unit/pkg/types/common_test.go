package types_test

import (
	"cipgram/pkg/types"
	"testing"
	"time"
)

// Test Protocol constants and validation
func TestProtocolConstants(t *testing.T) {
	tests := []struct {
		name     string
		protocol types.Protocol
		expected string
	}{
		{"ENIP Explicit", types.ProtoENIP_Explicit, "ENIP-TCP-44818"},
		{"Modbus TCP", types.ProtoModbus, "Modbus-TCP-502"},
		{"DNP3", types.ProtoDNP3, "DNP3-TCP-20000"},
		{"OPC-UA", types.ProtoOPCUA, "OPC-UA-TCP-4840"},
		{"HTTP", types.ProtoHTTP, "HTTP-TCP-80"},
		{"HTTPS", types.ProtoHTTPS, "HTTPS-TCP-443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.protocol) != tt.expected {
				t.Errorf("Protocol %s = %v, expected %v", tt.name, string(tt.protocol), tt.expected)
			}
		})
	}
}

// Test PurdueLevel constants
func TestPurdueLevelConstants(t *testing.T) {
	tests := []struct {
		name     string
		level    types.PurdueLevel
		expected string
	}{
		{"Level 0", types.L0, "Level 0"},
		{"Level 1", types.L1, "Level 1"},
		{"Level 2", types.L2, "Level 2"},
		{"Level 3", types.L3, "Level 3"},
		{"Level 3.5 DMZ", types.L3_5, "Level 3.5"},
		{"Level 4", types.L4, "Level 4"},
		{"Level 5", types.L5, "Level 5"},
		{"Unknown", types.Unknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.level) != tt.expected {
				t.Errorf("PurdueLevel %s = %v, expected %v", tt.name, string(tt.level), tt.expected)
			}
		})
	}
}

// Test types.FlowKey functionality
func TestFlowKey(t *testing.T) {
	tests := []struct {
		name  string
		key1  types.FlowKey
		key2  types.FlowKey
		equal bool
	}{
		{
			name:  "Identical flows should be equal",
			key1:  types.FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: types.ProtoModbus},
			key2:  types.FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: types.ProtoModbus},
			equal: true,
		},
		{
			name:  "Different protocols should not be equal",
			key1:  types.FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: types.ProtoModbus},
			key2:  types.FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: types.ProtoENIP_Explicit},
			equal: false,
		},
		{
			name:  "Different IPs should not be equal",
			key1:  types.FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: types.ProtoModbus},
			key2:  types.FlowKey{SrcIP: "192.168.1.11", DstIP: "192.168.1.20", Proto: types.ProtoModbus},
			equal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := (tt.key1 == tt.key2)
			if equal != tt.equal {
				t.Errorf("types.FlowKey equality test %s failed: got %v, expected %v", tt.name, equal, tt.equal)
			}
		})
	}
}

// Test types.Edge structure
func TestEdge(t *testing.T) {
	now := time.Now()
	edge := &types.Edge{
		Src:           "192.168.1.10",
		Dst:           "192.168.1.20",
		Protocol:      types.ProtoModbus,
		Packets:       100,
		Bytes:         5000,
		FirstSeen:     now,
		LastSeen:      now.Add(time.Minute),
		InferredLevel: types.L2,
	}

	// Test basic field assignments
	if edge.Src != "192.168.1.10" {
		t.Errorf("types.Edge.Src = %v, expected 192.168.1.10", edge.Src)
	}
	if edge.Protocol != types.ProtoModbus {
		t.Errorf("types.Edge.Protocol = %v, expected %v", edge.Protocol, types.ProtoModbus)
	}
	if edge.Packets != 100 {
		t.Errorf("types.Edge.Packets = %v, expected 100", edge.Packets)
	}
	if edge.InferredLevel != types.L2 {
		t.Errorf("types.Edge.InferredLevel = %v, expected %v", edge.InferredLevel, types.L2)
	}
}

// Test types.Host structure
func TestHost(t *testing.T) {
	host := &types.Host{
		IP:            "192.168.1.10",
		MAC:           "aa:bb:cc:dd:ee:ff",
		Hostname:      "plc-001",
		Vendor:        "Allen-Bradley",
		InferredLevel: types.L1,
		Roles:         []string{"PLC", "ModbusServer"},
		PortsSeen:     make(map[uint16]bool),
	}

	// Test basic assignments
	if host.IP != "192.168.1.10" {
		t.Errorf("types.Host.IP = %v, expected 192.168.1.10", host.IP)
	}
	if host.InferredLevel != types.L1 {
		t.Errorf("types.Host.InferredLevel = %v, expected %v", host.InferredLevel, types.L1)
	}
	if len(host.Roles) != 2 {
		t.Errorf("types.Host.Roles length = %v, expected 2", len(host.Roles))
	}

	// Test ports seen functionality
	host.PortsSeen[502] = true   // Modbus
	host.PortsSeen[44818] = true // ENIP

	if !host.PortsSeen[502] {
		t.Error("types.Host should have port 502 marked as seen")
	}
	if !host.PortsSeen[44818] {
		t.Error("types.Host should have port 44818 marked as seen")
	}
	if host.PortsSeen[80] {
		t.Error("types.Host should not have port 80 marked as seen")
	}
}

// Test types.IEC62443Zone constants
func TestIEC62443ZoneConstants(t *testing.T) {
	tests := []struct {
		name     string
		zone     types.IEC62443Zone
		expected string
	}{
		{"Industrial Zone", types.IndustrialZone, "Industrial Zone"},
		{"DMZ Zone", types.DMZZone, "DMZ Zone"},
		{"Enterprise Zone", types.EnterpriseZone, "Enterprise Zone"},
		{"Safety Zone", types.SafetyZone, "Safety Zone"},
		{"Remote Access Zone", types.RemoteAccessZone, "Remote Access Zone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.zone) != tt.expected {
				t.Errorf("types.IEC62443Zone %s = %v, expected %v", tt.name, string(tt.zone), tt.expected)
			}
		})
	}
}

// Test RuleAction constants
func TestRuleActionConstants(t *testing.T) {
	tests := []struct {
		name     string
		action   types.RuleAction
		expected string
	}{
		{"types.Allow", types.Allow, "ALLOW"},
		{"types.Deny", types.Deny, "DENY"},
		{"types.Drop", types.Drop, "DROP"},
		{"types.Reject", types.Reject, "REJECT"},
		{"types.Log", types.Log, "LOG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("RuleAction %s = %v, expected %v", tt.name, string(tt.action), tt.expected)
			}
		})
	}
}
