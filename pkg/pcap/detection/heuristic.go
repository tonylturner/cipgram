package detection

import (
	"cipgram/pkg/pcap/core"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HeuristicDetector implements protocol detection using heuristic analysis
type HeuristicDetector struct {
	patterns []HeuristicPattern
}

// HeuristicPattern defines a heuristic detection pattern
type HeuristicPattern struct {
	Protocol    string
	Confidence  float32
	Description string
	Category    string
	Matcher     PatternMatcher
}

// PatternMatcher interface for different types of pattern matching
type PatternMatcher interface {
	Match(packet gopacket.Packet) bool
	GetDetails() map[string]interface{}
}

// NewHeuristicDetector creates a new heuristic detector
func NewHeuristicDetector() *HeuristicDetector {
	detector := &HeuristicDetector{
		patterns: []HeuristicPattern{},
	}

	detector.initializePatterns()
	return detector
}

// DetectByHeuristics performs heuristic-based protocol detection
func (hd *HeuristicDetector) DetectByHeuristics(packet gopacket.Packet) *core.DetectionResult {
	for _, pattern := range hd.patterns {
		if pattern.Matcher.Match(packet) {
			return &core.DetectionResult{
				Protocol:   pattern.Protocol,
				Confidence: pattern.Confidence,
				Method:     core.MethodHeuristic,
				Details: map[string]interface{}{
					"pattern":    pattern.Description,
					"category":   pattern.Category,
					"heuristics": pattern.Matcher.GetDetails(),
				},
			}
		}
	}

	return nil
}

// GetSupportedProtocols returns protocols supported by heuristic detection
func (hd *HeuristicDetector) GetSupportedProtocols() []string {
	protocols := make(map[string]bool)

	for _, pattern := range hd.patterns {
		protocols[pattern.Protocol] = true
	}

	var result []string
	for protocol := range protocols {
		result = append(result, protocol)
	}

	return result
}

// initializePatterns initializes heuristic detection patterns
func (hd *HeuristicDetector) initializePatterns() {
	// Industrial protocol patterns
	hd.addPattern("Modbus TCP", 0.85, "Modbus TCP header pattern", "Industrial",
		&ModbusTCPMatcher{})

	hd.addPattern("EtherNet/IP", 0.85, "EtherNet/IP encapsulation header", "Industrial",
		&EtherNetIPMatcher{})

	hd.addPattern("DNP3", 0.80, "DNP3 frame structure", "Industrial",
		&DNP3Matcher{})

	hd.addPattern("BACnet", 0.80, "BACnet/IP header pattern", "Industrial",
		&BACnetMatcher{})

	// Network protocol patterns
	hd.addPattern("HTTP", 0.75, "HTTP request/response patterns", "Web",
		&HTTPMatcher{})

	hd.addPattern("DNS", 0.85, "DNS query/response structure", "Network",
		&DNSMatcher{})

	hd.addPattern("DHCP", 0.80, "DHCP message patterns", "Network",
		&DHCPMatcher{})

	hd.addPattern("SSH", 0.80, "SSH protocol identification", "Remote Access",
		&SSHMatcher{})

	// Layer 2 protocol patterns
	hd.addPattern("Profinet-DCP", 0.90, "Profinet DCP frame pattern", "Industrial",
		&ProfinetDCPMatcher{})

	hd.addPattern("LLDP", 0.85, "Link Layer Discovery Protocol", "Network",
		&LLDPMatcher{})
}

// addPattern adds a heuristic pattern
func (hd *HeuristicDetector) addPattern(protocol string, confidence float32, description, category string, matcher PatternMatcher) {
	pattern := HeuristicPattern{
		Protocol:    protocol,
		Confidence:  confidence,
		Description: description,
		Category:    category,
		Matcher:     matcher,
	}

	hd.patterns = append(hd.patterns, pattern)
}

// ModbusTCPMatcher detects Modbus TCP protocol
type ModbusTCPMatcher struct{}

func (m *ModbusTCPMatcher) Match(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	// Modbus TCP header is 7 bytes: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
	if len(payload) < 7 {
		return false
	}

	// Protocol ID should be 0x0000 for Modbus TCP
	protocolID := (uint16(payload[2]) << 8) | uint16(payload[3])
	if protocolID != 0x0000 {
		return false
	}

	// Length field should be reasonable (1-252 bytes for Modbus)
	length := (uint16(payload[4]) << 8) | uint16(payload[5])
	if length < 1 || length > 252 {
		return false
	}

	// Check if we have a valid function code (1-127)
	if len(payload) >= 8 {
		functionCode := payload[7]
		return functionCode >= 1 && functionCode <= 127
	}

	return true
}

func (m *ModbusTCPMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "header_analysis",
		"checks": []string{"protocol_id", "length_field", "function_code"},
	}
}

// EtherNetIPMatcher detects EtherNet/IP protocol
type EtherNetIPMatcher struct{}

func (m *EtherNetIPMatcher) Match(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	// EtherNet/IP encapsulation header is 24 bytes minimum
	if len(payload) < 24 {
		return false
	}

	// Check command codes (first 2 bytes)
	command := (uint16(payload[0]) << 8) | uint16(payload[1])
	validCommands := []uint16{0x0065, 0x0066, 0x006F, 0x0070} // RegisterSession, UnregisterSession, SendRRData, SendUnitData

	for _, validCmd := range validCommands {
		if command == validCmd {
			return true
		}
	}

	return false
}

func (m *EtherNetIPMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "command_analysis",
		"checks": []string{"command_code", "header_length"},
	}
}

// DNP3Matcher detects DNP3 protocol
type DNP3Matcher struct{}

func (m *DNP3Matcher) Match(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	// DNP3 frame starts with 0x0564
	if len(payload) < 10 {
		return false
	}

	// Check start bytes
	if payload[0] != 0x05 || payload[1] != 0x64 {
		return false
	}

	// Check length field (should be reasonable)
	length := payload[2]
	return length >= 5
}

func (m *DNP3Matcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "frame_analysis",
		"checks": []string{"start_bytes", "length_field"},
	}
}

// BACnetMatcher detects BACnet/IP protocol
type BACnetMatcher struct{}

func (m *BACnetMatcher) Match(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	// BACnet/IP header is 4 bytes minimum
	if len(payload) < 4 {
		return false
	}

	// Check BACnet/IP type (first byte)
	bvlcType := payload[0]
	validTypes := []byte{0x81, 0x82, 0x83, 0x84} // Original-Unicast-NPDU, Original-Broadcast-NPDU, etc.

	for _, validType := range validTypes {
		if bvlcType == validType {
			return true
		}
	}

	return false
}

func (m *BACnetMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "bvlc_analysis",
		"checks": []string{"bvlc_type"},
	}
}

// HTTPMatcher detects HTTP protocol
type HTTPMatcher struct{}

func (m *HTTPMatcher) Match(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 10 {
		return false
	}

	payloadStr := string(payload[:minInt(len(payload), 100)])

	// Check for HTTP methods
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
	for _, method := range httpMethods {
		if strings.HasPrefix(payloadStr, method) {
			return true
		}
	}

	// Check for HTTP response
	if strings.HasPrefix(payloadStr, "HTTP/") {
		return true
	}

	return false
}

func (m *HTTPMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "text_analysis",
		"checks": []string{"http_methods", "http_response"},
	}
}

// DNSMatcher detects DNS protocol
type DNSMatcher struct{}

func (m *DNSMatcher) Match(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	// DNS header is 12 bytes minimum
	if len(payload) < 12 {
		return false
	}

	// Check flags field for valid DNS flags
	flags := (uint16(payload[2]) << 8) | uint16(payload[3])

	// QR bit (query/response), OPCODE (4 bits), and RCODE (4 bits) should be reasonable
	opcode := (flags >> 11) & 0xF
	rcode := flags & 0xF

	// Valid OPCODE values: 0 (standard query), 1 (inverse query), 2 (status)
	if opcode > 2 {
		return false
	}

	// Valid RCODE values: 0-5 are common
	if rcode > 5 {
		return false
	}

	return true
}

func (m *DNSMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "header_flags",
		"checks": []string{"opcode", "rcode", "header_structure"},
	}
}

// DHCPMatcher detects DHCP protocol
type DHCPMatcher struct{}

func (m *DHCPMatcher) Match(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	// DHCP message is at least 236 bytes
	if len(payload) < 236 {
		return false
	}

	// Check DHCP magic cookie (bytes 236-239)
	if len(payload) >= 240 {
		magicCookie := []byte{0x63, 0x82, 0x53, 0x63}
		for i, b := range magicCookie {
			if payload[236+i] != b {
				return false
			}
		}
		return true
	}

	return false
}

func (m *DHCPMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "magic_cookie",
		"checks": []string{"message_length", "magic_cookie"},
	}
}

// SSHMatcher detects SSH protocol
type SSHMatcher struct{}

func (m *SSHMatcher) Match(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 7 {
		return false
	}

	payloadStr := string(payload[:minInt(len(payload), 20)])

	// Check for SSH version string
	return strings.HasPrefix(payloadStr, "SSH-")
}

func (m *SSHMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "version_string",
		"checks": []string{"ssh_banner"},
	}
}

// ProfinetDCPMatcher detects Profinet DCP protocol
type ProfinetDCPMatcher struct{}

func (m *ProfinetDCPMatcher) Match(packet gopacket.Packet) bool {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return false
	}

	eth := ethLayer.(*layers.Ethernet)

	// Check for Profinet EtherType
	if eth.EthernetType != layers.EthernetType(0x8892) {
		return false
	}

	payload := eth.Payload
	if len(payload) < 4 {
		return false
	}

	// Check for DCP frame ID
	frameID := (uint16(payload[0]) << 8) | uint16(payload[1])

	// DCP frame IDs: 0xFEFE (Hello), 0xFEFD (Get), 0xFEFC (Set), etc.
	return frameID >= 0xFEFC && frameID <= 0xFEFF
}

func (m *ProfinetDCPMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "frame_id",
		"checks": []string{"ethertype", "frame_id"},
	}
}

// LLDPMatcher detects LLDP protocol
type LLDPMatcher struct{}

func (m *LLDPMatcher) Match(packet gopacket.Packet) bool {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return false
	}

	eth := ethLayer.(*layers.Ethernet)

	// Check for LLDP EtherType
	if eth.EthernetType != layers.EthernetType(0x88CC) {
		return false
	}

	payload := eth.Payload
	if len(payload) < 2 {
		return false
	}

	// LLDP frame should start with Chassis ID TLV (type 1)
	tlvType := (payload[0] >> 1) & 0x7F
	return tlvType == 1
}

func (m *LLDPMatcher) GetDetails() map[string]interface{} {
	return map[string]interface{}{
		"method": "tlv_analysis",
		"checks": []string{"ethertype", "chassis_id_tlv"},
	}
}

// Helper function
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetPatternStats returns statistics about heuristic patterns
func (hd *HeuristicDetector) GetPatternStats() map[string]interface{} {
	categories := make(map[string]int)

	for _, pattern := range hd.patterns {
		categories[pattern.Category]++
	}

	return map[string]interface{}{
		"total_patterns": len(hd.patterns),
		"categories":     categories,
		"protocols":      len(hd.GetSupportedProtocols()),
	}
}
