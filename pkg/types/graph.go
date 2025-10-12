package types

import (
	"strings"
)

// Graph and host management functions
func newGraph() *Graph {
	return &Graph{
		Hosts: make(map[string]*Host),
		Edges: make(map[FlowKey]*Edge),
	}
}

func (g *Graph) getHost(ip string) *Host {
	h := g.Hosts[ip]
	if h == nil {
		h = &Host{
			IP:                    ip,
			PortsSeen:             make(map[uint16]bool),
			PeersByProtoInitiated: make(map[Protocol]map[string]bool),
			PeersByProtoReceived:  make(map[Protocol]map[string]bool),
			InitiatedCounts:       make(map[Protocol]int),
			ReceivedCounts:        make(map[Protocol]int),
		}
		g.Hosts[ip] = h
	}
	h.ensureMaps()
	return h
}

func (h *Host) ensureMaps() {
	if h.PeersByProtoInitiated == nil {
		h.PeersByProtoInitiated = map[Protocol]map[string]bool{}
	}
	if h.PeersByProtoReceived == nil {
		h.PeersByProtoReceived = map[Protocol]map[string]bool{}
	}
	if h.InitiatedCounts == nil {
		h.InitiatedCounts = map[Protocol]int{}
	}
	if h.ReceivedCounts == nil {
		h.ReceivedCounts = map[Protocol]int{}
	}
	if h.PortsSeen == nil {
		h.PortsSeen = map[uint16]bool{}
	}
}

// filterGraph applies relationship-focused simplification
func filterGraph(g *Graph, hideUnknown bool, maxNodes int) *Graph {
	filtered := newGraph()

	// Step 1: Filter hosts by classification (not packet count)
	significantHosts := make(map[string]*Host)
	for ip, host := range g.Hosts {
		// Include if has clear role or good ICS score
		include := false

		if !hideUnknown || host.InferredLevel != Unknown {
			include = true
		}

		// Always include hosts with ICS protocols or clear roles
		if host.ICSScore > 0 || len(host.Roles) > 0 {
			include = true
		}

		if include {
			significantHosts[ip] = host
		}
	}

	// Step 2: Include all edges between significant hosts
	significantEdges := make(map[FlowKey]*Edge)
	for key, edge := range g.Edges {
		if _, srcExists := significantHosts[edge.Src]; srcExists {
			if _, dstExists := significantHosts[edge.Dst]; dstExists {
				significantEdges[key] = edge
			}
		}
	}

	// Step 3: Build filtered graph
	for ip, host := range significantHosts {
		filtered.Hosts[ip] = host
	}
	filtered.Edges = significantEdges

	return filtered
}

// createSummaryGraph creates a simplified overview
func createSummaryGraph(g *Graph) *Graph {
	// For now, just return the same graph
	// Could implement grouping logic here
	return g
}

// deduplicateHosts removes duplicate hosts based on MAC address and merges their data
func deduplicateHosts(g *Graph) {
	// Group hosts by MAC address
	macGroups := make(map[string][]*Host)

	for _, host := range g.Hosts {
		if host.MAC != "" {
			macGroups[host.MAC] = append(macGroups[host.MAC], host)
		}
	}

	// Merge duplicate hosts
	for _, hosts := range macGroups {
		if len(hosts) <= 1 {
			continue // No duplicates
		}

		// Find the "best" host (most complete information)
		primaryHost := findPrimaryHost(hosts)

		// Merge data from other hosts
		for _, host := range hosts {
			if host.IP == primaryHost.IP {
				continue // Skip the primary host
			}

			// Merge port information
			for port := range host.PortsSeen {
				primaryHost.PortsSeen[port] = true
			}

			// Merge protocol counts
			for proto, count := range host.InitiatedCounts {
				primaryHost.InitiatedCounts[proto] += count
			}
			for proto, count := range host.ReceivedCounts {
				primaryHost.ReceivedCounts[proto] += count
			}

			// Merge peer information
			for proto, peers := range host.PeersByProtoInitiated {
				if primaryHost.PeersByProtoInitiated[proto] == nil {
					primaryHost.PeersByProtoInitiated[proto] = make(map[string]bool)
				}
				for peer := range peers {
					primaryHost.PeersByProtoInitiated[proto][peer] = true
				}
			}
			for proto, peers := range host.PeersByProtoReceived {
				if primaryHost.PeersByProtoReceived[proto] == nil {
					primaryHost.PeersByProtoReceived[proto] = make(map[string]bool)
				}
				for peer := range peers {
					primaryHost.PeersByProtoReceived[proto][peer] = true
				}
			}

			// Merge roles (avoid duplicates)
			for _, role := range host.Roles {
				hasRole := false
				for _, existingRole := range primaryHost.Roles {
					if existingRole == role {
						hasRole = true
						break
					}
				}
				if !hasRole {
					primaryHost.Roles = append(primaryHost.Roles, role)
				}
			}

			// Update best available information
			if primaryHost.Hostname == "" && host.Hostname != "" {
				primaryHost.Hostname = host.Hostname
			}
			if primaryHost.DeviceName == "" && host.DeviceName != "" {
				primaryHost.DeviceName = host.DeviceName
			}
			if primaryHost.Vendor == "" && host.Vendor != "" {
				primaryHost.Vendor = host.Vendor
			}

			// Remove the duplicate host
			delete(g.Hosts, host.IP)
		}

		// Update edges to point to primary host
		updateEdgesForMergedHost(g, hosts, primaryHost)
	}
}

// findPrimaryHost selects the best host from a group of duplicates
func findPrimaryHost(hosts []*Host) *Host {
	var best *Host
	bestScore := -1

	for _, host := range hosts {
		score := 0

		// Prefer hosts with hostname
		if host.Hostname != "" {
			score += 10
		}

		// Prefer hosts with device name
		if host.DeviceName != "" {
			score += 5
		}

		// Prefer hosts with vendor info
		if host.Vendor != "" {
			score += 3
		}

		// Prefer hosts with roles
		score += len(host.Roles) * 2

		// Prefer hosts with higher ICS score
		score += host.ICSScore

		// Prefer non-multicast addresses for primary
		if !strings.Contains(host.IP, "255") && !strings.Contains(host.IP, "0.0.0.0") {
			score += 5
		}

		if score > bestScore {
			bestScore = score
			best = host
		}
	}

	return best
}

// updateEdgesForMergedHost updates all edges to use the primary host IP
func updateEdgesForMergedHost(g *Graph, duplicateHosts []*Host, primaryHost *Host) {
	// Create map of old IPs to primary IP
	ipMap := make(map[string]string)
	for _, host := range duplicateHosts {
		if host.IP != primaryHost.IP {
			ipMap[host.IP] = primaryHost.IP
		}
	}

	// Update edges
	newEdges := make(map[FlowKey]*Edge)

	for key, edge := range g.Edges {
		newKey := key

		// Update source IP if it was merged
		if newIP, exists := ipMap[key.SrcIP]; exists {
			newKey.SrcIP = newIP
			edge.Src = newIP
		}

		// Update destination IP if it was merged
		if newIP, exists := ipMap[key.DstIP]; exists {
			newKey.DstIP = newIP
			edge.Dst = newIP
		}

		// Merge edges with same key
		if existingEdge, exists := newEdges[newKey]; exists {
			existingEdge.Packets += edge.Packets
			existingEdge.Bytes += edge.Bytes
			if edge.FirstSeen.Before(existingEdge.FirstSeen) {
				existingEdge.FirstSeen = edge.FirstSeen
			}
			if edge.LastSeen.After(existingEdge.LastSeen) {
				existingEdge.LastSeen = edge.LastSeen
			}
		} else {
			newEdges[newKey] = edge
		}
	}

	g.Edges = newEdges
}
