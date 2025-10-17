package types

import (
	"testing"
	"time"
)

// Test Protocol constants and validation
func TestProtocolConstants(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		expected string
	}{
		{"ENIP Explicit", ProtoENIP_Explicit, "ENIP-TCP-44818"},
		{"Modbus TCP", ProtoModbus, "Modbus-TCP-502"},
		{"DNP3", ProtoDNP3, "DNP3-TCP-20000"},
		{"OPC-UA", ProtoOPCUA, "OPC-UA-TCP-4840"},
		{"HTTP", ProtoHTTP, "HTTP-TCP-80"},
		{"HTTPS", ProtoHTTPS, "HTTPS-TCP-443"},
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
		level    PurdueLevel
		expected string
	}{
		{"Level 0", L0, "Level 0"},
		{"Level 1", L1, "Level 1"},
		{"Level 2", L2, "Level 2"},
		{"Level 3", L3, "Level 3"},
		{"Level 3.5 DMZ", L3_5, "Level 3.5"},
		{"Level 4", L4, "Level 4"},
		{"Level 5", L5, "Level 5"},
		{"Unknown", Unknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.level) != tt.expected {
				t.Errorf("PurdueLevel %s = %v, expected %v", tt.name, string(tt.level), tt.expected)
			}
		})
	}
}

// Test FlowKey functionality
func TestFlowKey(t *testing.T) {
	tests := []struct {
		name  string
		key1  FlowKey
		key2  FlowKey
		equal bool
	}{
		{
			name:  "Identical flows should be equal",
			key1:  FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: ProtoModbus},
			key2:  FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: ProtoModbus},
			equal: true,
		},
		{
			name:  "Different protocols should not be equal",
			key1:  FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: ProtoModbus},
			key2:  FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: ProtoENIP_Explicit},
			equal: false,
		},
		{
			name:  "Different IPs should not be equal",
			key1:  FlowKey{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", Proto: ProtoModbus},
			key2:  FlowKey{SrcIP: "192.168.1.11", DstIP: "192.168.1.20", Proto: ProtoModbus},
			equal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := (tt.key1 == tt.key2)
			if equal != tt.equal {
				t.Errorf("FlowKey equality test %s failed: got %v, expected %v", tt.name, equal, tt.equal)
			}
		})
	}
}

// Test Edge structure
func TestEdge(t *testing.T) {
	now := time.Now()
	edge := &Edge{
		Src:           "192.168.1.10",
		Dst:           "192.168.1.20",
		Protocol:      ProtoModbus,
		Packets:       100,
		Bytes:         5000,
		FirstSeen:     now,
		LastSeen:      now.Add(time.Minute),
		InferredLevel: L2,
	}

	// Test basic field assignments
	if edge.Src != "192.168.1.10" {
		t.Errorf("Edge.Src = %v, expected 192.168.1.10", edge.Src)
	}
	if edge.Protocol != ProtoModbus {
		t.Errorf("Edge.Protocol = %v, expected %v", edge.Protocol, ProtoModbus)
	}
	if edge.Packets != 100 {
		t.Errorf("Edge.Packets = %v, expected 100", edge.Packets)
	}
	if edge.InferredLevel != L2 {
		t.Errorf("Edge.InferredLevel = %v, expected %v", edge.InferredLevel, L2)
	}
}

// Test Host structure
func TestHost(t *testing.T) {
	host := &Host{
		IP:            "192.168.1.10",
		MAC:           "aa:bb:cc:dd:ee:ff",
		Hostname:      "plc-001",
		Vendor:        "Allen-Bradley",
		InferredLevel: L1,
		Roles:         []string{"PLC", "ModbusServer"},
		PortsSeen:     make(map[uint16]bool),
	}

	// Test basic assignments
	if host.IP != "192.168.1.10" {
		t.Errorf("Host.IP = %v, expected 192.168.1.10", host.IP)
	}
	if host.InferredLevel != L1 {
		t.Errorf("Host.InferredLevel = %v, expected %v", host.InferredLevel, L1)
	}
	if len(host.Roles) != 2 {
		t.Errorf("Host.Roles length = %v, expected 2", len(host.Roles))
	}

	// Test ports seen functionality
	host.PortsSeen[502] = true   // Modbus
	host.PortsSeen[44818] = true // ENIP

	if !host.PortsSeen[502] {
		t.Error("Host should have port 502 marked as seen")
	}
	if !host.PortsSeen[44818] {
		t.Error("Host should have port 44818 marked as seen")
	}
	if host.PortsSeen[80] {
		t.Error("Host should not have port 80 marked as seen")
	}
}

// Test IEC62443Zone constants
func TestIEC62443ZoneConstants(t *testing.T) {
	tests := []struct {
		name     string
		zone     IEC62443Zone
		expected string
	}{
		{"Industrial Zone", IndustrialZone, "Industrial Zone"},
		{"DMZ Zone", DMZZone, "DMZ Zone"},
		{"Enterprise Zone", EnterpriseZone, "Enterprise Zone"},
		{"Safety Zone", SafetyZone, "Safety Zone"},
		{"Remote Access Zone", RemoteAccessZone, "Remote Access Zone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.zone) != tt.expected {
				t.Errorf("IEC62443Zone %s = %v, expected %v", tt.name, string(tt.zone), tt.expected)
			}
		})
	}
}

// Test RuleAction constants
func TestRuleActionConstants(t *testing.T) {
	tests := []struct {
		name     string
		action   RuleAction
		expected string
	}{
		{"Allow", Allow, "ALLOW"},
		{"Deny", Deny, "DENY"},
		{"Drop", Drop, "DROP"},
		{"Reject", Reject, "REJECT"},
		{"Log", Log, "LOG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("RuleAction %s = %v, expected %v", tt.name, string(tt.action), tt.expected)
			}
		})
	}
}
