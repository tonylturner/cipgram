package opnsense

import (
	"reflect"
	"testing"

	"cipgram/pkg/types"
)

func TestParsePortNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Valid port 80", "80", 80},
		{"Valid port 443", "443", 443},
		{"Valid port 502", "502", 502},
		{"Valid port 44818", "44818", 44818},
		{"Empty string", "", 0},
		{"Invalid string", "abc", 0},
		{"Mixed string", "12a3", 0},
		{"Port too large", "99999", 0},
		{"Zero port", "0", 0},
		{"Max valid port", "65535", 65535},
		{"Port exceeding max", "65536", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePortNumber(tt.input)
			if result != tt.expected {
				t.Errorf("parsePortNumber(%s) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid number", "123", true},
		{"Single digit", "5", true},
		{"Zero", "0", true},
		{"Large number", "44818", true},
		{"Empty string", "", false},
		{"Letters", "abc", false},
		{"Mixed", "12a3", false},
		{"Decimal", "12.3", false},
		{"Negative", "-123", false},
		{"With spaces", " 123 ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNumeric(tt.input)
			if result != tt.expected {
				t.Errorf("isNumeric(%s) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetPortName(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		expected string
	}{
		{"SSH", 22, "SSH"},
		{"Telnet", 23, "Telnet"},
		{"DNS", 53, "DNS"},
		{"HTTP", 80, "HTTP"},
		{"HTTPS", 443, "HTTPS"},
		{"Modbus", 502, "Modbus"},
		{"OPC-UA", 4840, "OPC-UA"},
		{"Unknown port", 12345, "Port-12345"},
		{"High port", 50000, "Port-50000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPortName(tt.port)
			if result != tt.expected {
				t.Errorf("getPortName(%d) = %s, expected %s", tt.port, result, tt.expected)
			}
		})
	}
}

func TestMapRuleAction(t *testing.T) {
	parser := &OPNsenseParser{}

	tests := []struct {
		name     string
		ruleType string
		expected types.RuleAction
	}{
		{"Pass rule", "pass", types.Allow},
		{"Block rule", "block", types.Deny},
		{"Reject rule", "reject", types.Deny},
		{"Mixed case pass", "PASS", types.Allow}, // Function is case insensitive
		{"Unknown rule", "unknown", types.Deny},
		{"Empty rule", "", types.Deny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.mapRuleAction(tt.ruleType)
			if result != tt.expected {
				t.Errorf("mapRuleAction(%s) = %v, expected %v", tt.ruleType, result, tt.expected)
			}
		})
	}
}

func TestInferPurpose(t *testing.T) {
	parser := &OPNsenseParser{}

	tests := []struct {
		name     string
		descr    string
		ifName   string
		expected string
	}{
		{"Production network", "Production Line A", "opt1", "Production OT"},
		{"SCADA system", "SCADA Network", "opt2", "Production OT"},
		{"HMI interface", "HMI Interface", "opt3", "Production OT"},
		{"PLC network", "PLC Communications", "opt4", "Production OT"},
		{"Manufacturing", "Manufacturing Cell 1", "opt5", "Production OT"},
		{"DMZ network", "DMZ Network", "dmz", "DMZ"},
		{"Management", "Management Network", "mgmt", "Management"},
		{"Corporate", "Corporate IT", "corp", "Corporate IT"},
		{"Office network", "Office Network", "office", "Corporate IT"},
		{"WAN interface", "WAN Connection", "wan", "Internet"},
		{"Site network", "Site Infrastructure", "site", "Corporate IT"}, // Maps to Corporate IT in actual code
		{"General interface", "General Network", "lan", "General"},
		{"Unknown", "", "", "General"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.inferPurpose(tt.descr, tt.ifName)
			if result != tt.expected {
				t.Errorf("inferPurpose(%s, %s) = %s, expected %s", tt.descr, tt.ifName, result, tt.expected)
			}
		})
	}
}

func TestInferZoneFromInterface(t *testing.T) {
	parser := &OPNsenseParser{}

	tests := []struct {
		name     string
		ifName   string
		iface    *Interface
		expected types.IEC62443Zone
	}{
		{
			name:     "WAN interface",
			ifName:   "wan",
			iface:    &Interface{Descr: "WAN Connection"},
			expected: types.DMZZone,
		},
		{
			name:     "LAN interface",
			ifName:   "lan",
			iface:    &Interface{Descr: "LAN Network"},
			expected: types.IndustrialZone,
		},
		{
			name:     "Production interface",
			ifName:   "opt1",
			iface:    &Interface{Descr: "Production Line A"},
			expected: types.IndustrialZone,
		},
		{
			name:     "SCADA interface",
			ifName:   "opt2",
			iface:    &Interface{Descr: "SCADA Network"},
			expected: types.IndustrialZone,
		},
		{
			name:     "Corporate interface",
			ifName:   "corp",
			iface:    &Interface{Descr: "Corporate Network"},
			expected: types.EnterpriseZone,
		},
		{
			name:     "Management interface",
			ifName:   "mgmt",
			iface:    &Interface{Descr: "Management Network"},
			expected: types.EnterpriseZone,
		},
		{
			name:     "DMZ interface",
			ifName:   "dmz",
			iface:    &Interface{Descr: "DMZ Network"},
			expected: types.DMZZone,
		},
		{
			name:     "WireGuard VPN",
			ifName:   "wg0",
			iface:    &Interface{Descr: "WireGuard VPN"},
			expected: types.RemoteAccessZone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.inferZoneFromInterface(tt.ifName, tt.iface)
			if result != tt.expected {
				t.Errorf("inferZoneFromInterface(%s, %v) = %v, expected %v",
					tt.ifName, tt.iface.Descr, result, tt.expected)
			}
		})
	}
}

func TestBuildCIDR(t *testing.T) {
	parser := &OPNsenseParser{}

	tests := []struct {
		name     string
		ip       string
		subnet   string
		expected string
	}{
		{"Standard network", "192.168.1.1", "24", "192.168.1.1/24"},
		{"Class A network", "10.0.0.1", "8", "10.0.0.1/8"},
		{"Host route", "172.16.1.10", "32", "172.16.1.10/32"},
		{"Empty IP", "", "24", ""},
		{"Empty subnet", "192.168.1.1", "", ""},
		{"Both empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.buildCIDR(tt.ip, tt.subnet)
			if result != tt.expected {
				t.Errorf("buildCIDR(%s, %s) = %s, expected %s", tt.ip, tt.subnet, result, tt.expected)
			}
		})
	}
}

func TestParseRuleTarget(t *testing.T) {
	parser := &OPNsenseParser{}

	tests := []struct {
		name     string
		target   RuleTarget
		expected types.NetworkRange
	}{
		{
			name:   "Any target",
			target: RuleTarget{Any: "1"},
			expected: types.NetworkRange{
				CIDR: "any",
				IPs:  []string{},
			},
		},
		{
			name:   "Network target",
			target: RuleTarget{Network: "lan"},
			expected: types.NetworkRange{
				CIDR: "lan",
				IPs:  []string{},
			},
		},
		{
			name:     "Empty target",
			target:   RuleTarget{},
			expected: types.NetworkRange{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.parseRuleTarget(tt.target)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseRuleTarget(%+v) = %+v, expected %+v", tt.target, result, tt.expected)
			}
		})
	}
}

func TestCalculateSegmentRisk(t *testing.T) {
	parser := &OPNsenseParser{}

	tests := []struct {
		name     string
		segment  *types.NetworkSegment
		expected types.RiskLevel
	}{
		{
			name: "Industrial Zone",
			segment: &types.NetworkSegment{
				Zone: types.IndustrialZone,
			},
			expected: types.HighRisk,
		},
		{
			name: "DMZ Zone",
			segment: &types.NetworkSegment{
				Zone: types.DMZZone,
			},
			expected: types.MediumRisk,
		},
		{
			name: "Enterprise Zone",
			segment: &types.NetworkSegment{
				Zone: types.EnterpriseZone,
			},
			expected: types.LowRisk,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.calculateSegmentRisk(tt.segment, nil)
			if result != tt.expected {
				t.Errorf("calculateSegmentRisk(%v) = %v, expected %v",
					tt.segment.Zone, result, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance-critical functions
func BenchmarkParsePortNumber(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parsePortNumber("44818")
	}
}

func BenchmarkIsNumeric(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isNumeric("44818")
	}
}

func BenchmarkInferPurpose(b *testing.B) {
	parser := &OPNsenseParser{}
	for i := 0; i < b.N; i++ {
		parser.inferPurpose("Production Line A Manufacturing Cell", "opt1")
	}
}
