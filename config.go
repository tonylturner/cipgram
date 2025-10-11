package main

import (
	"fmt"
	"net"
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

// apply applies subnet mapping overrides to a host using proper CIDR matching
func (m *MappingTable) apply(h *Host) {
	if m == nil || m.Mappings == nil {
		return
	}

	hostIP := net.ParseIP(h.IP)
	if hostIP == nil {
		return // Invalid IP address
	}

	for _, mapping := range m.Mappings {
		if matchesCIDR(hostIP, mapping.CIDR) {
			h.OverrideLevel = &mapping.Level
			if mapping.Role != "" {
				h.OverrideRole = mapping.Role
			}
			break
		}
	}
}

// matchesCIDR performs proper CIDR subnet matching
func matchesCIDR(ip net.IP, cidr string) bool {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false // Invalid CIDR
	}
	return subnet.Contains(ip)
}
