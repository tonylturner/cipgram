package dpi

import (
	"cipgram/pkg/pcap/core"
	"cipgram/pkg/pcap/dpi/analyzers"
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Factory functions for creating DPI analyzers

// NewHTTPAnalyzer creates a new HTTP analyzer
func NewHTTPAnalyzer() core.DPIAnalyzer {
	return analyzers.NewHTTPAnalyzer()
}

// NewModbusAnalyzer creates a new Modbus analyzer
func NewModbusAnalyzer() core.DPIAnalyzer {
	return analyzers.NewModbusAnalyzer()
}

// NewEtherNetIPAnalyzer creates a new EtherNet/IP analyzer
func NewEtherNetIPAnalyzer() core.DPIAnalyzer {
	return analyzers.NewEtherNetIPAnalyzer()
}

// NewDNP3Analyzer creates a new DNP3 analyzer
func NewDNP3Analyzer() core.DPIAnalyzer {
	return analyzers.NewDNP3Analyzer()
}

// NewTLSAnalyzer creates a new TLS analyzer
func NewTLSAnalyzer() core.DPIAnalyzer {
	return &TLSAnalyzer{}
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer() core.DPIAnalyzer {
	return &DNSAnalyzer{}
}

// NewBACnetAnalyzer creates a new BACnet analyzer
func NewBACnetAnalyzer() core.DPIAnalyzer {
	return &BACnetAnalyzer{}
}

// Placeholder analyzers for protocols not yet fully implemented

// TLSAnalyzer implements TLS/SSL protocol analysis
type TLSAnalyzer struct{}

func (t *TLSAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)

	// Check common TLS ports
	tlsPorts := []uint16{443, 993, 995, 636, 8443, 9443}
	for _, port := range tlsPorts {
		if tcp.SrcPort == layers.TCPPort(port) || tcp.DstPort == layers.TCPPort(port) {
			// Basic TLS handshake detection
			payload := tcp.Payload
			if len(payload) >= 5 {
				// Check for TLS record header
				if payload[0] == 0x16 && payload[1] == 0x03 {
					return true
				}
			}
		}
	}
	return false
}

func (t *TLSAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 5 {
		return nil
	}

	// Basic TLS record parsing
	recordType := payload[0]
	version := binary.BigEndian.Uint16(payload[1:3])
	length := binary.BigEndian.Uint16(payload[3:5])

	var subprotocol string
	switch recordType {
	case 0x16:
		subprotocol = "Handshake"
	case 0x17:
		subprotocol = "Application Data"
	case 0x15:
		subprotocol = "Alert"
	case 0x14:
		subprotocol = "Change Cipher Spec"
	default:
		subprotocol = "Unknown Record"
	}

	return &core.AnalysisResult{
		Protocol:    "TLS",
		Subprotocol: subprotocol,
		Confidence:  0.85,
		Details: map[string]interface{}{
			"record_type": recordType,
			"version":     version,
			"length":      length,
		},
		Metadata: map[string]string{
			"protocol_type": "security",
			"layer":         "presentation",
		},
	}
}

func (t *TLSAnalyzer) GetProtocolName() string {
	return "TLS"
}

func (t *TLSAnalyzer) GetConfidenceThreshold() float32 {
	return 0.8
}

// DNSAnalyzer implements DNS protocol analysis
type DNSAnalyzer struct{}

func (d *DNSAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)

	// Check DNS ports
	if udp.SrcPort == 53 || udp.DstPort == 53 || udp.SrcPort == 5353 || udp.DstPort == 5353 {
		payload := udp.Payload
		if len(payload) >= 12 {
			// Basic DNS header validation
			return d.looksLikeDNS(payload)
		}
	}
	return false
}

func (d *DNSAnalyzer) looksLikeDNS(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}

	// Check flags field for reasonable values
	flags := binary.BigEndian.Uint16(payload[2:4])

	// Opcode (should be 0-2 for standard queries)
	opcode := (flags >> 11) & 0xF

	// RCODE (response code, should be 0-5 for common responses)
	rcode := flags & 0xF

	return opcode <= 2 && rcode <= 5
}

func (d *DNSAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}

	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	if len(payload) < 12 {
		return nil
	}

	// Parse DNS header
	id := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	ancount := binary.BigEndian.Uint16(payload[6:8])

	qr := (flags >> 15) & 1
	opcode := (flags >> 11) & 0xF
	rcode := flags & 0xF

	var subprotocol string
	if qr == 0 {
		subprotocol = "Query"
	} else {
		subprotocol = "Response"
	}

	return &core.AnalysisResult{
		Protocol:    "DNS",
		Subprotocol: subprotocol,
		Confidence:  0.9,
		Details: map[string]interface{}{
			"transaction_id": id,
			"query_count":    qdcount,
			"answer_count":   ancount,
			"opcode":         opcode,
			"response_code":  rcode,
		},
		Metadata: map[string]string{
			"protocol_type": "network",
			"layer":         "application",
		},
	}
}

func (d *DNSAnalyzer) GetProtocolName() string {
	return "DNS"
}

func (d *DNSAnalyzer) GetConfidenceThreshold() float32 {
	return 0.9
}

// BACnetAnalyzer implements BACnet protocol analysis
type BACnetAnalyzer struct{}

func (b *BACnetAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)

	// Check BACnet/IP port (47808)
	if udp.SrcPort == 47808 || udp.DstPort == 47808 {
		payload := udp.Payload
		if len(payload) >= 4 {
			// Check for BACnet/IP header
			return payload[0] == 0x81 // BVLC Type
		}
	}
	return false
}

func (b *BACnetAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}

	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	if len(payload) < 4 {
		return nil
	}

	// Parse BACnet/IP header
	bvlcType := payload[0]
	bvlcFunction := payload[1]
	bvlcLength := binary.BigEndian.Uint16(payload[2:4])

	var subprotocol string
	switch bvlcFunction {
	case 0x00:
		subprotocol = "BVLC-Result"
	case 0x01:
		subprotocol = "Write-Broadcast-Distribution-Table"
	case 0x02:
		subprotocol = "Read-Broadcast-Distribution-Table"
	case 0x03:
		subprotocol = "Read-Broadcast-Distribution-Table-Ack"
	case 0x04:
		subprotocol = "Forwarded-NPDU"
	case 0x05:
		subprotocol = "Register-Foreign-Device"
	case 0x06:
		subprotocol = "Read-Foreign-Device-Table"
	case 0x07:
		subprotocol = "Read-Foreign-Device-Table-Ack"
	case 0x08:
		subprotocol = "Delete-Foreign-Device-Table-Entry"
	case 0x09:
		subprotocol = "Distribute-Broadcast-To-Network"
	case 0x0A:
		subprotocol = "Original-Unicast-NPDU"
	case 0x0B:
		subprotocol = "Original-Broadcast-NPDU"
	default:
		subprotocol = "Unknown Function"
	}

	return &core.AnalysisResult{
		Protocol:    "BACnet/IP",
		Subprotocol: subprotocol,
		Confidence:  0.9,
		Details: map[string]interface{}{
			"bvlc_type":     bvlcType,
			"bvlc_function": bvlcFunction,
			"bvlc_length":   bvlcLength,
		},
		Metadata: map[string]string{
			"protocol_type": "industrial",
			"layer":         "application",
		},
	}
}

func (b *BACnetAnalyzer) GetProtocolName() string {
	return "BACnet/IP"
}

func (b *BACnetAnalyzer) GetConfidenceThreshold() float32 {
	return 0.90
}
