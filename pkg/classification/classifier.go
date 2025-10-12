package classification

import (
	"strings"

	"cipgram/pkg/types"
)

// Enhanced protocol and vendor-based Purdue level classification
func tagHostHeuristic(h *types.Host) {
	// Respect overrides if present
	if h.OverrideLevel != nil {
		h.InferredLevel = *h.OverrideLevel
		if h.OverrideRole != "" {
			setRole(h, h.OverrideRole)
		}
		return
	}

	tagHostScores(h)

	// Get enhanced protocol statistics
	initENIPPeers := len(h.PeersByProtoInitiated[types.ProtoENIP_Explicit])
	rcvENIPPeers := len(h.PeersByProtoReceived[types.ProtoENIP_Explicit])
	initENIP := h.InitiatedCounts[types.ProtoENIP_Explicit]
	rcvENIP := h.ReceivedCounts[types.ProtoENIP_Explicit]
	initIO := h.InitiatedCounts[types.ProtoENIP_Implicit]
	rcvIO := h.ReceivedCounts[types.ProtoENIP_Implicit]
	hasIO := (initIO + rcvIO) > 0

	// Additional protocol analysis
	hasModbus := h.InitiatedCounts[types.ProtoModbus] > 0 || h.ReceivedCounts[types.ProtoModbus] > 0
	hasS7 := h.InitiatedCounts[types.ProtoS7Comm] > 0 || h.ReceivedCounts[types.ProtoS7Comm] > 0
	hasOmron := h.InitiatedCounts[types.ProtoFins] > 0 || h.ReceivedCounts[types.ProtoFins] > 0 ||
		h.InitiatedCounts[types.ProtoOmronTCP] > 0 || h.ReceivedCounts[types.ProtoOmronTCP] > 0
	hasMitsubishi := h.InitiatedCounts[types.ProtoSlmp] > 0 || h.ReceivedCounts[types.ProtoSlmp] > 0 ||
		h.InitiatedCounts[types.ProtoMelsecQ] > 0 || h.ReceivedCounts[types.ProtoMelsecQ] > 0
	hasOPCUA := h.InitiatedCounts[types.ProtoOPCUA] > 0 || h.ReceivedCounts[types.ProtoOPCUA] > 0
	hasDNP3 := h.InitiatedCounts[types.ProtoDNP3] > 0 || h.ReceivedCounts[types.ProtoDNP3] > 0
	hasBACnet := h.InitiatedCounts[types.ProtoBACnet] > 0 || h.ReceivedCounts[types.ProtoBACnet] > 0

	// Count total PLC protocols
	protocolCount := 0
	if hasModbus {
		protocolCount++
	}
	if hasS7 {
		protocolCount++
	}
	if hasOmron {
		protocolCount++
	}
	if hasMitsubishi {
		protocolCount++
	}
	if hasIO {
		protocolCount++
	}
	if initENIP > 0 || rcvENIP > 0 {
		protocolCount++
	}

	// Classification based on communication patterns, device behavior, and vendor
	switch {
	// HIGH CONFIDENCE LEVEL 1 (Field Devices)
	// PLCs: Receive explicit messages, participate in I/O, from known vendors
	case rcvENIPPeers >= 1 && hasIO && h.ITScore <= 1:
		h.InferredLevel = types.L1
		if strings.Contains(h.Vendor, "Siemens") && hasS7 {
			setRole(h, "Siemens PLC")
		} else if strings.Contains(h.Vendor, "Rockwell") || strings.Contains(h.Vendor, "Allen-Bradley") {
			setRole(h, "Rockwell PLC")
		} else if strings.Contains(h.Vendor, "Omron") && hasOmron {
			setRole(h, "Omron PLC")
		} else if strings.Contains(h.Vendor, "Mitsubishi") && hasMitsubishi {
			setRole(h, "Mitsubishi PLC")
		} else {
			setRole(h, "PLC")
		}

	// I/O Adapters/Drives: Primarily I/O traffic, multicast, minimal explicit
	case hasIO && h.MulticastPeer && initENIP == 0 && rcvENIP <= 1 && h.ITScore == 0:
		h.InferredLevel = types.L1
		setRole(h, "I/O Adapter/Drive")

	// Modbus slaves (PLCs): Receive more than initiate
	case hasModbus && h.ReceivedCounts[types.ProtoModbus] > h.InitiatedCounts[types.ProtoModbus] && h.ITScore <= 1:
		h.InferredLevel = types.L1
		if strings.Contains(h.Vendor, "Schneider") {
			setRole(h, "Schneider PLC")
		} else {
			setRole(h, "Modbus PLC")
		}

	// S7 slaves (Siemens PLCs)
	case hasS7 && h.ReceivedCounts[types.ProtoS7Comm] > h.InitiatedCounts[types.ProtoS7Comm] && h.ITScore <= 1:
		h.InferredLevel = types.L1
		setRole(h, "Siemens S7 PLC")

	// Other vendor-specific PLCs
	case hasOmron && h.ReceivedCounts[types.ProtoFins] > h.InitiatedCounts[types.ProtoFins]:
		h.InferredLevel = types.L1
		setRole(h, "Omron PLC")
	case hasMitsubishi && (h.ReceivedCounts[types.ProtoSlmp] > h.InitiatedCounts[types.ProtoSlmp]):
		h.InferredLevel = types.L1
		setRole(h, "Mitsubishi PLC")

	// HIGH CONFIDENCE LEVEL 2 (Supervisory Control)
	// HMI/Engineering: Initiates connections to multiple devices, has some IT
	case initENIPPeers >= 3 && h.ITScore >= 1:
		h.InferredLevel = types.L2
		setRole(h, "HMI/Engineering Station")

	// OPC-UA clients (typically HMIs/SCADAs)
	case hasOPCUA && h.InitiatedCounts[types.ProtoOPCUA] > h.ReceivedCounts[types.ProtoOPCUA] && h.ITScore >= 1:
		h.InferredLevel = types.L2
		setRole(h, "OPC-UA Client/HMI")

	// SCADA masters: Poll multiple devices
	case (hasModbus || hasS7 || hasOmron || hasMitsubishi) &&
		(h.InitiatedCounts[types.ProtoModbus]+h.InitiatedCounts[types.ProtoS7Comm]+
			h.InitiatedCounts[types.ProtoFins]+h.InitiatedCounts[types.ProtoSlmp]) >
			(h.ReceivedCounts[types.ProtoModbus]+h.ReceivedCounts[types.ProtoS7Comm]+
				h.ReceivedCounts[types.ProtoFins]+h.ReceivedCounts[types.ProtoSlmp]) && h.ITScore >= 1:
		h.InferredLevel = types.L2
		setRole(h, "SCADA Master")

	// LEVEL 2/3 BOUNDARY PROTOCOLS
	case hasDNP3 && h.ITScore >= 1:
		h.InferredLevel = types.L2
		setRole(h, "DNP3 Master/RTU")
	case hasBACnet:
		h.InferredLevel = types.L2
		setRole(h, "BACnet Device")
	case hasOPCUA && h.ReceivedCounts[types.ProtoOPCUA] > h.InitiatedCounts[types.ProtoOPCUA]:
		h.InferredLevel = types.L1
		setRole(h, "OPC-UA Server")

	// HIGH CONFIDENCE LEVEL 3 (Management/IT)
	// Strong IT, minimal ICS
	case h.ITScore >= 3 && h.ICSScore <= 1:
		h.InferredLevel = types.L3
		setRole(h, "IT Server/Workstation")
	case h.ITScore >= 2 && h.ICSScore == 0:
		h.InferredLevel = types.L3
		setRole(h, "IT Infrastructure")

	// MEDIUM CONFIDENCE CLASSIFICATIONS
	// Multi-protocol devices (gateways, advanced controllers)
	case protocolCount >= 2 && h.ITScore <= 1:
		if h.MulticastPeer || hasIO {
			h.InferredLevel = types.L1
			setRole(h, "Multi-types.Protocol Controller")
		} else {
			h.InferredLevel = types.L2
			setRole(h, "types.Protocol Gateway")
		}

	// Devices with clear ICS protocols but unclear role
	case h.ICSScore >= 1 && h.ITScore <= 1:
		if h.MulticastPeer && hasIO {
			h.InferredLevel = types.L1
			setRole(h, "Field Device")
		} else if initENIP > rcvENIP || h.InitiatedCounts[types.ProtoModbus] > h.ReceivedCounts[types.ProtoModbus] {
			h.InferredLevel = types.L2
			setRole(h, "Control Device")
		} else {
			h.InferredLevel = types.L1
			setRole(h, "Field Device")
		}

	// LOW CONFIDENCE / FALLBACKS - Be more aggressive about classification
	default:
		if h.MulticastPeer && h.ICSScore >= 1 {
			h.InferredLevel = types.L1
			setRole(h, "Field Device")
		} else if h.ITScore >= 2 {
			h.InferredLevel = types.L3
			setRole(h, "IT Device")
		} else if h.ICSScore >= 1 {
			h.InferredLevel = types.L2
			setRole(h, "Industrial Device")
		} else if h.ITScore >= 1 {
			h.InferredLevel = types.L3
			setRole(h, "Network Device")
		} else {
			// Default assignment based on port activity patterns
			if len(h.PortsSeen) > 0 {
				// Check for any industrial ports
				industrialPorts := []uint16{2222, 44818, 502, 102, 9600, 4840, 20000}
				hasIndustrial := false
				for _, port := range industrialPorts {
					if h.PortsSeen[port] {
						hasIndustrial = true
						break
					}
				}
				if hasIndustrial {
					h.InferredLevel = types.L1
					setRole(h, "Field Device")
				} else {
					h.InferredLevel = types.L3
					setRole(h, "Network Device")
				}
			} else {
				h.InferredLevel = types.Unknown
				setRole(h, "types.Unknown Device")
			}
		}
	}
}

func tagHostScores(h *types.Host) {
	icsPorts := []uint16{2222, 44818, 502, 20000, 47808, 4840, 102, 9600, 5007, 1025, 20547, 18246, 8834}
	itPorts := []uint16{53, 80, 443, 445, 1433, 5432, 135, 3389, 22, 23, 21, 25, 110, 143, 993, 995}
	for _, p := range icsPorts {
		if h.PortsSeen[p] {
			h.ICSScore++
		}
	}
	for _, p := range itPorts {
		if h.PortsSeen[p] {
			h.ITScore++
		}
	}
}

func setRole(h *types.Host, role string) {
	if role == "" {
		return
	}
	for _, r := range h.Roles {
		if r == role {
			return
		}
	}
	h.Roles = append(h.Roles, role)
}

// classifyEdge attempts protocol-level Purdue hint
func classifyEdge(proto types.Protocol, dstIsMulticast bool) (types.PurdueLevel, []string) {
	var notes []string

	switch proto {
	case types.ProtoENIP_Explicit:
		notes = append(notes, "EtherNet/IP Explicit (44818) → Level 1-2")
		return types.L1, notes
	case types.ProtoENIP_Implicit:
		notes = append(notes, "EtherNet/IP I/O (2222) → Level 1")
		return types.L1, notes
	case types.ProtoModbus:
		notes = append(notes, "Modbus TCP (502) → Level 1-2")
		return types.L1, notes
	case types.ProtoDNP3:
		notes = append(notes, "DNP3 (20000) → Level 2-3")
		return types.L2, notes
	case types.ProtoBACnet:
		notes = append(notes, "BACnet/IP (47808) → Level 2")
		return types.L2, notes
	case types.ProtoOPCClassic:
		notes = append(notes, "OPC Classic (135) → Level 2-3")
		return types.L2, notes
	case types.ProtoOPCUA:
		notes = append(notes, "OPC-UA (4840) → Level 1-3")
		return types.L2, notes
	case types.ProtoS7Comm:
		notes = append(notes, "S7Comm (102) Siemens → Level 1")
		return types.L1, notes
	case types.ProtoFins:
		notes = append(notes, "FINS (9600) Omron → Level 1")
		return types.L1, notes
	case types.ProtoSlmp:
		notes = append(notes, "SLMP (5007) Mitsubishi → Level 1")
		return types.L1, notes
	case types.ProtoMelsecQ:
		notes = append(notes, "MelsecQ (1025) Mitsubishi → Level 1")
		return types.L1, notes
	case types.ProtoOmronTCP:
		notes = append(notes, "Omron TCP (20547) → Level 1")
		return types.L1, notes
	case types.ProtoCCLink:
		notes = append(notes, "CC-Link (18246) Mitsubishi → Level 1")
		return types.L1, notes
	case types.ProtoSINEC:
		notes = append(notes, "SINEC (8834) Siemens → Level 2")
		return types.L2, notes
	case types.ProtoProfinetDCP:
		notes = append(notes, "Profinet DCP (types.L2) → Level 1")
		return types.L1, notes
	case types.ProtoProfinetRT:
		notes = append(notes, "Profinet RT (types.L2) → Level 1")
		return types.L1, notes
	case types.ProtoProconOS:
		notes = append(notes, "ProconOS (20547) → Level 2")
		return types.L2, notes
	case types.ProtoEGD:
		notes = append(notes, "EGD (18246) GE Ethernet Global Data → Level 1-2")
		return types.L1, notes
	case types.ProtoSRTP:
		notes = append(notes, "SRTP (18246) GE Service Request Transport → Level 2")
		return types.L2, notes
	}
	if dstIsMulticast {
		notes = append(notes, "Multicast destination → adapter/discovery (types.L1 bias)")
		return types.L1, notes
	}
	return types.Unknown, notes
}
