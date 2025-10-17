package detection

import (
	"cipgram/pkg/pcap/core"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PortBasedDetector implements protocol detection based on port numbers
type PortBasedDetector struct {
	tcpPorts map[uint16][]ProtocolMapping
	udpPorts map[uint16][]ProtocolMapping
}

// ProtocolMapping represents a protocol mapping for a port
type ProtocolMapping struct {
	Protocol    string
	Confidence  float32
	Description string
	Category    string
}

// NewPortBasedDetector creates a new port-based detector
func NewPortBasedDetector() *PortBasedDetector {
	detector := &PortBasedDetector{
		tcpPorts: make(map[uint16][]ProtocolMapping),
		udpPorts: make(map[uint16][]ProtocolMapping),
	}

	detector.initializePortMappings()
	return detector
}

// DetectByPort detects protocol based on port numbers
func (pbd *PortBasedDetector) DetectByPort(packet gopacket.Packet) *core.DetectionResult {
	// Check TCP ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		// Check destination port first (server port)
		if mappings, exists := pbd.tcpPorts[dstPort]; exists {
			return pbd.createResult(mappings, "TCP", dstPort, true)
		}

		// Check source port (for return traffic)
		if mappings, exists := pbd.tcpPorts[srcPort]; exists {
			return pbd.createResult(mappings, "TCP", srcPort, false)
		}
	}

	// Check UDP ports
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		// Check destination port first
		if mappings, exists := pbd.udpPorts[dstPort]; exists {
			return pbd.createResult(mappings, "UDP", dstPort, true)
		}

		// Check source port
		if mappings, exists := pbd.udpPorts[srcPort]; exists {
			return pbd.createResult(mappings, "UDP", srcPort, false)
		}
	}

	return nil
}

// createResult creates a detection result from port mappings
func (pbd *PortBasedDetector) createResult(mappings []ProtocolMapping, transport string, port uint16, isDestination bool) *core.DetectionResult {
	if len(mappings) == 0 {
		return nil
	}

	// Use the first (highest priority) mapping
	mapping := mappings[0]

	// Adjust confidence based on direction
	confidence := mapping.Confidence
	if !isDestination {
		confidence *= 0.9 // Slightly lower confidence for source port matches
	}

	return &core.DetectionResult{
		Protocol:   mapping.Protocol,
		Confidence: confidence,
		Method:     core.MethodPort,
		Details: map[string]interface{}{
			"transport":   transport,
			"port":        port,
			"direction":   map[bool]string{true: "destination", false: "source"}[isDestination],
			"description": mapping.Description,
			"category":    mapping.Category,
		},
	}
}

// GetSupportedProtocols returns all protocols supported by port-based detection
func (pbd *PortBasedDetector) GetSupportedProtocols() []string {
	protocols := make(map[string]bool)

	// Collect TCP protocols
	for _, mappings := range pbd.tcpPorts {
		for _, mapping := range mappings {
			protocols[mapping.Protocol] = true
		}
	}

	// Collect UDP protocols
	for _, mappings := range pbd.udpPorts {
		for _, mapping := range mappings {
			protocols[mapping.Protocol] = true
		}
	}

	// Convert to slice
	var result []string
	for protocol := range protocols {
		result = append(result, protocol)
	}

	return result
}

// initializePortMappings initializes the port-to-protocol mappings
func (pbd *PortBasedDetector) initializePortMappings() {
	// Industrial TCP protocols
	pbd.addTCPMapping(44818, "EtherNet/IP", 0.95, "EtherNet/IP Explicit Messaging", "Industrial")
	pbd.addTCPMapping(502, "Modbus TCP", 0.95, "Modbus TCP Protocol", "Industrial")
	pbd.addTCPMapping(102, "S7Comm", 0.95, "Siemens S7 Communication", "Industrial")
	pbd.addTCPMapping(4840, "OPC-UA", 0.95, "OPC Unified Architecture", "Industrial")
	pbd.addTCPMapping(20000, "DNP3", 0.95, "Distributed Network Protocol", "Industrial")
	pbd.addTCPMapping(9600, "FINS", 0.90, "Omron FINS Protocol", "Industrial")
	pbd.addTCPMapping(5007, "SLMP", 0.90, "Seamless Message Protocol", "Industrial")
	pbd.addTCPMapping(135, "OPC Classic", 0.85, "OPC Classic/RPC Endpoint", "Industrial")
	pbd.addTCPMapping(8834, "SINEC", 0.90, "Siemens SINEC Protocol", "Industrial")
	pbd.addTCPMapping(18246, "EGD", 0.80, "Ethernet Global Data", "Industrial")
	pbd.addTCPMapping(20547, "Omron TCP", 0.85, "Omron TCP Protocol", "Industrial")
	pbd.addTCPMapping(1025, "Melsec Q", 0.80, "Mitsubishi Melsec Q Series", "Industrial")

	// Industrial UDP protocols
	pbd.addUDPMapping(2222, "EtherNet/IP I/O", 0.95, "EtherNet/IP Implicit I/O", "Industrial")
	pbd.addUDPMapping(47808, "BACnet", 0.95, "Building Automation and Control", "Industrial")
	pbd.addUDPMapping(18246, "CC-Link", 0.80, "CC-Link Protocol", "Industrial")

	// Standard IT TCP protocols
	pbd.addTCPMapping(80, "HTTP", 0.90, "Hypertext Transfer Protocol", "Web")
	pbd.addTCPMapping(443, "HTTPS", 0.95, "HTTP over TLS/SSL", "Web")
	pbd.addTCPMapping(22, "SSH", 0.95, "Secure Shell", "Remote Access")
	pbd.addTCPMapping(23, "Telnet", 0.90, "Telnet Protocol", "Remote Access")
	pbd.addTCPMapping(21, "FTP", 0.90, "File Transfer Protocol", "File Transfer")
	pbd.addTCPMapping(25, "SMTP", 0.90, "Simple Mail Transfer Protocol", "Email")
	pbd.addTCPMapping(110, "POP3", 0.90, "Post Office Protocol v3", "Email")
	pbd.addTCPMapping(143, "IMAP", 0.90, "Internet Message Access Protocol", "Email")
	pbd.addTCPMapping(993, "IMAPS", 0.90, "IMAP over SSL", "Email")
	pbd.addTCPMapping(995, "POP3S", 0.90, "POP3 over SSL", "Email")
	pbd.addTCPMapping(389, "LDAP", 0.90, "Lightweight Directory Access Protocol", "Directory")
	pbd.addTCPMapping(636, "LDAPS", 0.90, "LDAP over SSL", "Directory")
	pbd.addTCPMapping(3389, "RDP", 0.95, "Remote Desktop Protocol", "Remote Access")
	pbd.addTCPMapping(5900, "VNC", 0.90, "Virtual Network Computing", "Remote Access")

	// Database protocols
	pbd.addTCPMapping(1433, "SQL Server", 0.90, "Microsoft SQL Server", "Database")
	pbd.addTCPMapping(3306, "MySQL", 0.90, "MySQL Database", "Database")
	pbd.addTCPMapping(5432, "PostgreSQL", 0.90, "PostgreSQL Database", "Database")
	pbd.addTCPMapping(6379, "Redis", 0.90, "Redis Database", "Database")
	pbd.addTCPMapping(27017, "MongoDB", 0.90, "MongoDB Database", "Database")
	pbd.addTCPMapping(1521, "Oracle TNS", 0.90, "Oracle Database", "Database")

	// Windows/SMB protocols
	pbd.addTCPMapping(139, "NetBIOS Session Service", 0.90, "NetBIOS Session Service", "Windows")
	pbd.addTCPMapping(445, "SMB/CIFS", 0.95, "Server Message Block", "Windows")
	pbd.addUDPMapping(137, "NetBIOS Name Service", 0.90, "NetBIOS Name Service", "Windows")
	pbd.addUDPMapping(138, "NetBIOS Datagram Service", 0.90, "NetBIOS Datagram Service", "Windows")

	// Standard IT UDP protocols
	pbd.addUDPMapping(53, "DNS", 0.95, "Domain Name System", "Network")
	pbd.addUDPMapping(67, "DHCP Server", 0.95, "DHCP Server", "Network")
	pbd.addUDPMapping(68, "DHCP Client", 0.95, "DHCP Client", "Network")
	pbd.addUDPMapping(123, "NTP", 0.90, "Network Time Protocol", "Network")
	pbd.addUDPMapping(161, "SNMP", 0.90, "Simple Network Management Protocol", "Network")
	pbd.addUDPMapping(162, "SNMP Trap", 0.90, "SNMP Trap", "Network")
	pbd.addUDPMapping(514, "Syslog", 0.85, "System Logging Protocol", "Network")
	pbd.addUDPMapping(1812, "RADIUS Auth", 0.90, "RADIUS Authentication", "Security")
	pbd.addUDPMapping(1813, "RADIUS Accounting", 0.90, "RADIUS Accounting", "Security")

	// VoIP protocols
	pbd.addTCPMapping(5060, "SIP", 0.90, "Session Initiation Protocol", "VoIP")
	pbd.addUDPMapping(5060, "SIP", 0.90, "Session Initiation Protocol", "VoIP")
	pbd.addTCPMapping(5061, "SIP-TLS", 0.90, "SIP over TLS", "VoIP")
	pbd.addTCPMapping(1720, "H.323", 0.85, "H.323 Protocol", "VoIP")
	pbd.addUDPMapping(5004, "RTP", 0.80, "Real-time Transport Protocol", "VoIP")

	// Development and alternative ports
	pbd.addTCPMapping(8080, "HTTP-Alt", 0.75, "HTTP Alternative Port", "Web")
	pbd.addTCPMapping(8443, "HTTPS-Alt", 0.75, "HTTPS Alternative Port", "Web")
	pbd.addTCPMapping(8000, "HTTP-Dev", 0.70, "HTTP Development Server", "Development")
	pbd.addTCPMapping(3000, "Node.js Dev", 0.70, "Node.js Development Server", "Development")
	pbd.addTCPMapping(4200, "Angular Dev Server", 0.70, "Angular Development Server", "Development")
	pbd.addTCPMapping(5000, "Flask Dev", 0.70, "Flask Development Server", "Development")

	// Add development port ranges (5000-5999)
	for port := uint16(5000); port <= 5999; port++ {
		pbd.addTCPMapping(port, "Development", 0.60, "Development/Testing Port", "Development")
	}

	// Message queues and streaming
	pbd.addTCPMapping(5672, "AMQP (RabbitMQ)", 0.90, "Advanced Message Queuing Protocol", "Messaging")
	pbd.addTCPMapping(9092, "Apache Kafka", 0.90, "Apache Kafka", "Messaging")
	pbd.addTCPMapping(4222, "NATS", 0.90, "NATS Messaging", "Messaging")
	pbd.addTCPMapping(1883, "MQTT", 0.90, "Message Queuing Telemetry Transport", "IoT")
	pbd.addTCPMapping(8883, "MQTT-TLS", 0.90, "MQTT over TLS", "IoT")

	// Monitoring and management
	pbd.addTCPMapping(9090, "Prometheus", 0.85, "Prometheus Monitoring", "Monitoring")
	pbd.addTCPMapping(8086, "InfluxDB", 0.85, "InfluxDB Time Series Database", "Monitoring")
	pbd.addTCPMapping(9200, "Elasticsearch", 0.85, "Elasticsearch", "Search")
	pbd.addTCPMapping(5601, "Kibana", 0.85, "Kibana Dashboard", "Monitoring")
	pbd.addTCPMapping(3001, "Grafana Alternative", 0.80, "Grafana Alternative Port", "Monitoring")

	// Container and Orchestration protocols
	pbd.addTCPMapping(2376, "Docker", 0.95, "Docker Daemon API", "Container")
	pbd.addTCPMapping(2377, "Docker Swarm", 0.95, "Docker Swarm Management", "Container")
	pbd.addTCPMapping(6443, "Kubernetes API", 0.95, "Kubernetes API Server", "Container")
	pbd.addTCPMapping(10250, "Kubelet", 0.90, "Kubernetes Kubelet", "Container")
	pbd.addTCPMapping(10251, "Kube-Scheduler", 0.90, "Kubernetes Scheduler", "Container")
	pbd.addTCPMapping(10252, "Kube-Controller", 0.90, "Kubernetes Controller Manager", "Container")
	pbd.addTCPMapping(2379, "etcd Client", 0.90, "etcd Client API", "Container")
	pbd.addTCPMapping(2380, "etcd Peer", 0.90, "etcd Peer Communication", "Container")

	// IoT and Edge protocols
	pbd.addTCPMapping(5683, "CoAP", 0.85, "Constrained Application Protocol", "IoT")
	pbd.addUDPMapping(5683, "CoAP", 0.85, "Constrained Application Protocol", "IoT")
	pbd.addUDPMapping(1700, "LoRaWAN", 0.85, "LoRaWAN Gateway", "IoT")

	// Streaming and Media protocols
	pbd.addTCPMapping(554, "RTSP", 0.90, "Real Time Streaming Protocol", "Media")
	pbd.addUDPMapping(554, "RTSP", 0.90, "Real Time Streaming Protocol", "Media")
	pbd.addTCPMapping(1935, "RTMP", 0.90, "Real Time Messaging Protocol", "Media")
	pbd.addUDPMapping(3478, "STUN", 0.80, "Session Traversal Utilities for NAT", "Media")

	// Additional DevOps and CI/CD tools
	pbd.addTCPMapping(8080, "Jenkins", 0.70, "Jenkins CI/CD", "DevOps")
	pbd.addTCPMapping(9000, "SonarQube", 0.75, "SonarQube Code Quality", "DevOps")
	pbd.addTCPMapping(8081, "Nexus Repository", 0.75, "Nexus Repository Manager", "DevOps")
	pbd.addTCPMapping(5000, "Docker Registry", 0.80, "Docker Registry", "Container")

	// Network Security and VPN protocols
	pbd.addUDPMapping(500, "IKE", 0.90, "Internet Key Exchange", "VPN")
	pbd.addUDPMapping(4500, "IPSec NAT-T", 0.90, "IPSec NAT Traversal", "VPN")
	pbd.addTCPMapping(1723, "PPTP", 0.85, "Point-to-Point Tunneling Protocol", "VPN")
	pbd.addUDPMapping(1194, "OpenVPN", 0.90, "OpenVPN", "VPN")
}

// addTCPMapping adds a TCP port mapping
func (pbd *PortBasedDetector) addTCPMapping(port uint16, protocol string, confidence float32, description, category string) {
	mapping := ProtocolMapping{
		Protocol:    protocol,
		Confidence:  confidence,
		Description: description,
		Category:    category,
	}

	pbd.tcpPorts[port] = append(pbd.tcpPorts[port], mapping)
}

// addUDPMapping adds a UDP port mapping
func (pbd *PortBasedDetector) addUDPMapping(port uint16, protocol string, confidence float32, description, category string) {
	mapping := ProtocolMapping{
		Protocol:    protocol,
		Confidence:  confidence,
		Description: description,
		Category:    category,
	}

	pbd.udpPorts[port] = append(pbd.udpPorts[port], mapping)
}

// GetPortMappings returns all port mappings for debugging/inspection
func (pbd *PortBasedDetector) GetPortMappings() map[string]interface{} {
	return map[string]interface{}{
		"tcp_ports":    len(pbd.tcpPorts),
		"udp_ports":    len(pbd.udpPorts),
		"tcp_mappings": pbd.tcpPorts,
		"udp_mappings": pbd.udpPorts,
	}
}

// GetProtocolsByCategory returns protocols grouped by category
func (pbd *PortBasedDetector) GetProtocolsByCategory() map[string][]string {
	categories := make(map[string][]string)

	// Process TCP mappings
	for _, mappings := range pbd.tcpPorts {
		for _, mapping := range mappings {
			categories[mapping.Category] = append(categories[mapping.Category], mapping.Protocol)
		}
	}

	// Process UDP mappings
	for _, mappings := range pbd.udpPorts {
		for _, mapping := range mappings {
			categories[mapping.Category] = append(categories[mapping.Category], mapping.Protocol)
		}
	}

	// Remove duplicates
	for category, protocols := range categories {
		unique := make(map[string]bool)
		var result []string
		for _, protocol := range protocols {
			if !unique[protocol] {
				unique[protocol] = true
				result = append(result, protocol)
			}
		}
		categories[category] = result
	}

	return categories
}
