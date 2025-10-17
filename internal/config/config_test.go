package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"cipgram/pkg/types"
)

func TestMatchesCIDR(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{
			name:     "IP in subnet",
			ip:       "192.168.1.10",
			cidr:     "192.168.1.0/24",
			expected: true,
		},
		{
			name:     "IP not in subnet",
			ip:       "192.168.2.10",
			cidr:     "192.168.1.0/24",
			expected: false,
		},
		{
			name:     "Invalid CIDR",
			ip:       "192.168.1.10",
			cidr:     "invalid-cidr",
			expected: false,
		},
		{
			name:     "Single host CIDR",
			ip:       "192.168.1.10",
			cidr:     "192.168.1.10/32",
			expected: true,
		},
		{
			name:     "Large subnet",
			ip:       "10.0.100.50",
			cidr:     "10.0.0.0/16",
			expected: true,
		},
		{
			name:     "IPv6 address in IPv4 CIDR",
			ip:       "::1",
			cidr:     "192.168.1.0/24",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil && tt.ip != "::1" { // Allow for IPv6 test case
				t.Fatalf("Invalid test IP: %s", tt.ip)
			}

			result := matchesCIDR(ip, tt.cidr)
			if result != tt.expected {
				t.Errorf("matchesCIDR(%s, %s) = %v, expected %v", tt.ip, tt.cidr, result, tt.expected)
			}
		})
	}
}

func TestApplyMapping(t *testing.T) {
	// Create test mapping table
	mapping := &types.MappingTable{
		Mappings: []types.SubnetMapping{
			{
				CIDR:  "192.168.1.0/24",
				Level: types.L1,
				Role:  "Production PLCs",
			},
			{
				CIDR:  "192.168.2.0/24",
				Level: types.L2,
				Role:  "SCADA Systems",
			},
			{
				CIDR:  "10.0.0.0/16",
				Level: types.L4,
				Role:  "Corporate Network",
			},
		},
	}

	// Create level variables to take addresses
	level1 := types.L1
	level2 := types.L2
	level4 := types.L4

	tests := []struct {
		name          string
		hostIP        string
		expectedLevel *types.PurdueLevel
		expectedRole  string
		shouldMatch   bool
	}{
		{
			name:          "Match production PLCs",
			hostIP:        "192.168.1.10",
			expectedLevel: &level1,
			expectedRole:  "Production PLCs",
			shouldMatch:   true,
		},
		{
			name:          "Match SCADA systems",
			hostIP:        "192.168.2.15",
			expectedLevel: &level2,
			expectedRole:  "SCADA Systems",
			shouldMatch:   true,
		},
		{
			name:          "Match corporate network",
			hostIP:        "10.0.50.100",
			expectedLevel: &level4,
			expectedRole:  "Corporate Network",
			shouldMatch:   true,
		},
		{
			name:          "No match",
			hostIP:        "172.16.1.10",
			expectedLevel: nil,
			expectedRole:  "",
			shouldMatch:   false,
		},
		{
			name:          "Invalid IP",
			hostIP:        "invalid-ip",
			expectedLevel: nil,
			expectedRole:  "",
			shouldMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := &types.Host{
				IP: tt.hostIP,
			}

			ApplyMapping(mapping, host)

			if tt.shouldMatch {
				if host.OverrideLevel == nil {
					t.Errorf("Expected override level to be set, but it was nil")
					return
				}
				if *host.OverrideLevel != *tt.expectedLevel {
					t.Errorf("OverrideLevel = %v, expected %v", *host.OverrideLevel, *tt.expectedLevel)
				}
				if host.OverrideRole != tt.expectedRole {
					t.Errorf("OverrideRole = %v, expected %v", host.OverrideRole, tt.expectedRole)
				}
			} else {
				if host.OverrideLevel != nil {
					t.Errorf("Expected no override level, but got %v", *host.OverrideLevel)
				}
				if host.OverrideRole != "" {
					t.Errorf("Expected no override role, but got %v", host.OverrideRole)
				}
			}
		})
	}
}

func TestApplyMappingNilTable(t *testing.T) {
	host := &types.Host{
		IP: "192.168.1.10",
	}

	// Test with nil mapping
	ApplyMapping(nil, host)

	if host.OverrideLevel != nil {
		t.Errorf("Expected no override with nil mapping, but got level %v", *host.OverrideLevel)
	}
}

func TestLoadMappingEmptyPath(t *testing.T) {
	mapping, err := loadMapping("")
	if err != nil {
		t.Errorf("Expected no error with empty path, got: %v", err)
	}
	if mapping == nil {
		t.Error("Expected non-nil mapping with empty path")
	}
	if mapping.Mappings != nil && len(mapping.Mappings) != 0 {
		t.Errorf("Expected empty mappings, got %d mappings", len(mapping.Mappings))
	}
}

func TestLoadMappingValidFile(t *testing.T) {
	// Create a temporary YAML file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_config.yaml")

	yamlContent := `mappings:
  - cidr: "192.168.1.0/24"
    level: "Level 1" 
    role: "Production PLCs"
  - cidr: "192.168.2.0/24"
    level: "Level 2"
    role: "SCADA Systems"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	mapping, err := loadMapping(configFile)
	if err != nil {
		t.Errorf("Expected no error loading valid config, got: %v", err)
	}

	if mapping == nil {
		t.Fatal("Expected non-nil mapping")
	}

	if len(mapping.Mappings) != 2 {
		t.Errorf("Expected 2 mappings, got %d", len(mapping.Mappings))
	}

	// Check first mapping
	if mapping.Mappings[0].CIDR != "192.168.1.0/24" {
		t.Errorf("First mapping CIDR = %v, expected 192.168.1.0/24", mapping.Mappings[0].CIDR)
	}
	if mapping.Mappings[0].Level != types.L1 {
		t.Errorf("First mapping Level = %v, expected %v", mapping.Mappings[0].Level, types.L1)
	}
	if mapping.Mappings[0].Role != "Production PLCs" {
		t.Errorf("First mapping Role = %v, expected 'Production PLCs'", mapping.Mappings[0].Role)
	}
}

func TestLoadMappingInvalidFile(t *testing.T) {
	// Test with non-existent file
	_, err := loadMapping("/non/existent/file.yaml")
	if err == nil {
		t.Error("Expected error loading non-existent file, got nil")
	}

	// Test with invalid YAML
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")

	invalidYAML := `invalid: yaml: content:
  - missing: quotes"
  - broken structure
`

	err = os.WriteFile(invalidFile, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid YAML file: %v", err)
	}

	_, err = loadMapping(invalidFile)
	if err == nil {
		t.Error("Expected error loading invalid YAML, got nil")
	}
}

// Benchmark tests for performance
func BenchmarkMatchesCIDR(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	cidr := "192.168.1.0/24"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchesCIDR(ip, cidr)
	}
}

func BenchmarkApplyMapping(b *testing.B) {
	mapping := &types.MappingTable{
		Mappings: []types.SubnetMapping{
			{CIDR: "192.168.1.0/24", Level: types.L1, Role: "Production"},
			{CIDR: "192.168.2.0/24", Level: types.L2, Role: "SCADA"},
			{CIDR: "10.0.0.0/16", Level: types.L4, Role: "Corporate"},
		},
	}

	host := &types.Host{IP: "192.168.1.50"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset host for each iteration
		host.OverrideLevel = nil
		host.OverrideRole = ""
		ApplyMapping(mapping, host)
	}
}
