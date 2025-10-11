package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

// loadMapping loads YAML configuration
func loadMapping(path string) (*MappingTable, error) {
	if path == "" {
		return &MappingTable{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %v", err)
	}

	var m MappingTable
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse YAML: %v", err)
	}

	return &m, nil
}

// apply applies subnet mapping overrides to a host
func (m *MappingTable) apply(h *Host) {
	if m == nil || m.Subnets == nil {
		return
	}
	
	for subnet, mapping := range m.Subnets {
		// Simple subnet matching (could be enhanced)
		if matchesSubnet(h.IP, subnet) {
			h.OverrideLevel = &mapping.Level
			if mapping.Role != "" {
				h.OverrideRole = mapping.Role
			}
			break
		}
	}
}

// matchesSubnet performs basic subnet matching
func matchesSubnet(ip, subnet string) bool {
	// Simple prefix matching for now
	// Could be enhanced with proper CIDR parsing
	return len(ip) >= len(subnet) && ip[:len(subnet)] == subnet
}
