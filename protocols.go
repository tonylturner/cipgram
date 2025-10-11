package main

import (
	"strings"

	"github.com/google/gopacket/layers"
)

// protFromPacket determines the industrial protocol from packet analysis
func protFromPacket(tcp *layers.TCP, udp *layers.UDP, eth *layers.Ethernet) (Protocol, string, string) {
	if tcp != nil {
		sport, dport := uint16(tcp.SrcPort), uint16(tcp.DstPort)
		
		// EtherNet/IP Explicit (TCP/44818)
		if sport == 44818 || dport == 44818 {
			return ProtoENIP_Explicit, "", ""
		}
		
		// Modbus TCP (502)
		if sport == 502 || dport == 502 {
			return ProtoModbus, "", ""
		}
		
		// DNP3 (20000)
		if sport == 20000 || dport == 20000 {
			return ProtoDNP3, "", ""
		}
		
		// OPC-UA (4840)
		if sport == 4840 || dport == 4840 {
			return ProtoOPCUA, "", ""
		}
		
		// S7Comm (102)
		if sport == 102 || dport == 102 {
			return ProtoS7Comm, "", ""
		}
		
		// FINS (9600)
		if sport == 9600 || dport == 9600 {
			return ProtoFins, "", ""
		}
		
		// SLMP (5007)
		if sport == 5007 || dport == 5007 {
			return ProtoSlmp, "", ""
		}
		
		// Check for Omron vs Mitsubishi on overlapping ports
		if sport == 20547 || dport == 20547 {
			// Need payload analysis to distinguish
			if isOmronTraffic(tcp.Payload) {
				return ProtoOmronTCP, "", ""
			}
			return ProtoProconOS, "", ""
		}
		
		if sport == 1025 || dport == 1025 {
			if isMelsecTraffic(tcp.Payload) {
				return ProtoMelsecQ, "", ""
			}
		}
		
		// OPC Classic (135)
		if sport == 135 || dport == 135 {
			return ProtoOPCClassic, "", ""
		}
		
		// SINEC (8834)
		if sport == 8834 || dport == 8834 {
			return ProtoSINEC, "", ""
		}
		
		// EGD/SRTP (18246) - need payload analysis
		if sport == 18246 || dport == 18246 {
			if isEGDTraffic(tcp.Payload) {
				return ProtoEGD, "", ""
			}
			return ProtoSRTP, "", ""
		}
	}
	
	if udp != nil {
		sport, dport := uint16(udp.SrcPort), uint16(udp.DstPort)
		
		// EtherNet/IP Implicit (UDP/2222)
		if sport == 2222 || dport == 2222 {
			return ProtoENIP_Implicit, "", ""
		}
		
		// BACnet/IP (47808)
		if sport == 47808 || dport == 47808 {
			return ProtoBACnet, "", ""
		}
		
		// CC-Link (18246)
		if sport == 18246 || dport == 18246 {
			if isCCLinkTraffic(udp.Payload) {
				return ProtoCCLink, "", ""
			}
			return ProtoEGD, "", ""
		}
	}
	
	// Layer 2 protocols
	if eth != nil {
		switch eth.EthernetType {
		case layers.EthernetType(0x8892):
			// Could be Profinet DCP or RT
			if isProfinetrDCPTraffic(eth.Payload) {
				return ProtoProfinetDCP, "", ""
			}
			return ProtoProfinetRT, "", ""
		}
	}
	
	return ProtoUnknown, "", ""
}

// Helper functions for protocol disambiguation
func isOmronTraffic(payload []byte) bool {
	// Omron FINS has specific header patterns
	if len(payload) < 4 {
		return false
	}
	// FINS header starts with specific bytes
	return payload[0] == 0x46 && payload[1] == 0x49 // "FI"
}

func isMelsecTraffic(payload []byte) bool {
	// Mitsubishi Melsec has specific patterns
	if len(payload) < 4 {
		return false
	}
	// Check for Mitsubishi protocol patterns
	return payload[0] == 0x50 && payload[1] == 0x00 // Common Melsec pattern
}

func isEGDTraffic(payload []byte) bool {
	// EGD (Ethernet Global Data) patterns
	if len(payload) < 8 {
		return false
	}
	// Check for EGD header
	return payload[0] == 0x01 && payload[1] == 0x00
}

func isCCLinkTraffic(payload []byte) bool {
	// CC-Link protocol patterns
	if len(payload) < 6 {
		return false
	}
	// Check for CC-Link specific headers
	return payload[0] == 0xCC && payload[1] == 0x4C // "CL"
}

func isProfinetrDCPTraffic(payload []byte) bool {
	// Profinet DCP vs RT disambiguation
	if len(payload) < 4 {
		return false
	}
	// DCP has specific service types
	return payload[0] == 0xFE && payload[1] == 0xFE
}

// parseENIP_CIP_FromTCP attempts to extract CIP service information from EtherNet/IP TCP payload
func parseENIP_CIP_FromTCP(payload []byte) (string, string, bool) {
	if len(payload) < 24 {
		return "", "", false
	}
	
	// EtherNet/IP encapsulation header is 24 bytes
	// CIP data starts after that
	cipData := payload[24:]
	if len(cipData) < 4 {
		return "", "", false
	}
	
	// CIP service code is first byte of CIP data
	serviceCode := cipData[0]
	
	serviceName := cipServiceName(serviceCode)
	serviceHex := "0x" + strings.ToUpper(string(rune(serviceCode)))
	
	return serviceName, serviceHex, true
}

// cipServiceName maps CIP service codes to human-readable names
func cipServiceName(code byte) string {
	switch code {
	case 0x01:
		return "GetAttrAll"
	case 0x0E:
		return "GetAttrSingle"
	case 0x10:
		return "SetAttrSingle"
	case 0x4C:
		return "CreateConnection"
	case 0x4E:
		return "DeleteConnection"
	case 0x52:
		return "MultipleServicePacket"
	case 0x54:
		return "ReadData"
	case 0x55:
		return "WriteData"
	default:
		return "UnknownCIPService"
	}
}
