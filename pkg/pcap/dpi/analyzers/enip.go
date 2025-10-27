package analyzers

import (
	"cipgram/pkg/pcap/core"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EtherNetIPAnalyzer implements DPI for EtherNet/IP protocol
type EtherNetIPAnalyzer struct {
	commands    map[uint16]string
	cipServices map[uint8]string
	cipClasses  map[uint16]string
}

// NewEtherNetIPAnalyzer creates a new EtherNet/IP analyzer
func NewEtherNetIPAnalyzer() *EtherNetIPAnalyzer {
	return &EtherNetIPAnalyzer{
		commands: map[uint16]string{
			0x0065: "RegisterSession",
			0x0066: "UnregisterSession",
			0x006F: "SendRRData",
			0x0070: "SendUnitData",
			0x0063: "ListServices",
			0x0064: "ListIdentity",
		},
		cipServices: map[uint8]string{
			0x01: "Get_Attributes_All",
			0x0E: "Get_Attribute_Single",
			0x10: "Set_Attribute_Single",
			0x4C: "Create",
			0x4E: "Delete",
			0x52: "Multiple_Service_Packet",
			0x54: "Read_Tag",
			0x55: "Write_Tag",
			0x4B: "Execute_PCCC",
		},
		cipClasses: map[uint16]string{
			0x0001: "Identity",
			0x0002: "Message_Router",
			0x0004: "Assembly",
			0x0005: "Connection",
			0x0006: "Connection_Manager",
			0x0020: "Parameter",
			0x006B: "Symbol",
			0x006C: "Template",
		},
	}
}

// CanAnalyze determines if this analyzer can process the packet
func (e *EtherNetIPAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)

	// Check EtherNet/IP TCP port (44818)
	if tcp.SrcPort == 44818 || tcp.DstPort == 44818 {
		return true
	}

	// Also check if payload looks like EtherNet/IP
	payload := tcp.Payload
	if len(payload) >= 24 {
		return e.looksLikeEtherNetIP(payload)
	}

	return false
}

// Analyze performs EtherNet/IP protocol analysis
func (e *EtherNetIPAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 24 {
		return nil
	}

	// Parse EtherNet/IP encapsulation header
	enip := e.parseEtherNetIP(payload)
	if enip == nil {
		return nil
	}

	subprotocol := enip.CommandName
	if enip.CIPService != "" {
		subprotocol = fmt.Sprintf("%s (%s)", enip.CommandName, enip.CIPService)
		if enip.CIPClass != "" {
			subprotocol = fmt.Sprintf("%s, %s", subprotocol, enip.CIPClass)
		}
	}

	return &core.AnalysisResult{
		Protocol:    "EtherNet/IP",
		Subprotocol: subprotocol,
		Confidence:  enip.Confidence,
		Details:     enip.Details,
		Metadata:    enip.Metadata,
	}
}

// GetProtocolName returns the protocol name
func (e *EtherNetIPAnalyzer) GetProtocolName() string {
	return "EtherNet/IP"
}

// GetConfidenceThreshold returns the minimum confidence threshold
func (e *EtherNetIPAnalyzer) GetConfidenceThreshold() float32 {
	return 0.90
}

// EtherNetIPFrame represents a parsed EtherNet/IP frame
type EtherNetIPFrame struct {
	Command       uint16
	CommandName   string
	Length        uint16
	SessionHandle uint32
	Status        uint32
	SenderContext uint64
	Options       uint32
	Data          []byte
	CIPService    string
	CIPClass      string
	CIPInstance   uint16
	CIPAttribute  uint16
	Confidence    float32
	Details       map[string]interface{}
	Metadata      map[string]string
}

// parseEtherNetIP parses an EtherNet/IP encapsulation header
func (e *EtherNetIPAnalyzer) parseEtherNetIP(payload []byte) *EtherNetIPFrame {
	if len(payload) < 24 {
		return nil
	}

	// Parse encapsulation header (24 bytes)
	command := binary.LittleEndian.Uint16(payload[0:2])
	length := binary.LittleEndian.Uint16(payload[2:4])
	sessionHandle := binary.LittleEndian.Uint32(payload[4:8])
	status := binary.LittleEndian.Uint32(payload[8:12])
	senderContext := binary.LittleEndian.Uint64(payload[12:20])
	options := binary.LittleEndian.Uint32(payload[20:24])

	// Validate command
	commandName, exists := e.commands[command]
	if !exists {
		return nil
	}

	frame := &EtherNetIPFrame{
		Command:       command,
		CommandName:   commandName,
		Length:        length,
		SessionHandle: sessionHandle,
		Status:        status,
		SenderContext: senderContext,
		Options:       options,
		Confidence:    0.95,
		Details:       make(map[string]interface{}),
		Metadata:      make(map[string]string),
	}

	// Extract data portion
	if len(payload) > 24 {
		frame.Data = payload[24:]
	}

	// Fill in basic details
	frame.Details["command"] = commandName
	frame.Details["session_handle"] = sessionHandle
	frame.Details["status"] = status
	frame.Details["data_length"] = len(frame.Data)

	// Add metadata
	frame.Metadata["protocol_version"] = "TCP"
	frame.Metadata["command_category"] = e.categorizeCommand(command)

	// Parse CIP data if present
	if len(frame.Data) > 0 && (command == 0x006F || command == 0x0070) {
		e.parseCIPData(frame)
	}

	return frame
}

// looksLikeEtherNetIP performs heuristic check for EtherNet/IP content
func (e *EtherNetIPAnalyzer) looksLikeEtherNetIP(payload []byte) bool {
	if len(payload) < 24 {
		return false
	}

	// Check command field
	command := binary.LittleEndian.Uint16(payload[0:2])
	_, exists := e.commands[command]
	if !exists {
		return false
	}

	// Check length field (should be reasonable)
	length := binary.LittleEndian.Uint16(payload[2:4])
	if length > 65535-24 { // Max payload size
		return false
	}

	return true
}

// categorizeCommand categorizes EtherNet/IP commands
func (e *EtherNetIPAnalyzer) categorizeCommand(command uint16) string {
	switch command {
	case 0x0065, 0x0066:
		return "Session Management"
	case 0x006F, 0x0070:
		return "Data Transfer"
	case 0x0063, 0x0064:
		return "Discovery"
	default:
		return "Other"
	}
}

// parseCIPData parses CIP (Common Industrial Protocol) data
func (e *EtherNetIPAnalyzer) parseCIPData(frame *EtherNetIPFrame) {
	data := frame.Data
	if len(data) < 2 {
		return
	}

	// Skip interface handle and timeout for SendRRData
	if frame.Command == 0x006F && len(data) >= 6 {
		data = data[6:] // Skip interface handle (4 bytes) + timeout (2 bytes)
	}

	// Skip connection ID and sequence for SendUnitData
	if frame.Command == 0x0070 && len(data) >= 6 {
		data = data[6:] // Skip connection ID (4 bytes) + sequence (2 bytes)
	}

	if len(data) < 2 {
		return
	}

	// Parse CIP service code
	serviceCode := data[0]
	serviceName, exists := e.cipServices[serviceCode]
	if exists {
		frame.CIPService = serviceName
		frame.Details["cip_service"] = serviceName
		frame.Details["cip_service_code"] = serviceCode
	} else {
		frame.CIPService = fmt.Sprintf("Unknown Service (0x%02X)", serviceCode)
		frame.Details["cip_service"] = frame.CIPService
		frame.Details["cip_service_code"] = serviceCode
	}

	// Parse class/instance/attribute if present
	if len(data) >= 4 {
		e.parseCIPPath(frame, data[1:])
	}

	frame.Metadata["cip_service_category"] = e.categorizeCIPService(serviceCode)
}

// parseCIPPath parses CIP path information
func (e *EtherNetIPAnalyzer) parseCIPPath(frame *EtherNetIPFrame, data []byte) {
	if len(data) < 3 {
		return
	}

	pathSize := data[0] // Path size in words
	if pathSize == 0 || len(data) < int(pathSize*2+1) {
		return
	}

	pathData := data[1 : pathSize*2+1]

	// Simple path parsing - look for class/instance/attribute
	for i := 0; i < len(pathData)-1; i += 2 {
		segment := pathData[i]
		value := pathData[i+1]

		switch segment {
		case 0x20: // Class ID
			classID := uint16(value)
			className, exists := e.cipClasses[classID]
			if exists {
				frame.CIPClass = className
				frame.Details["cip_class"] = className
			} else {
				frame.CIPClass = fmt.Sprintf("Unknown Class (0x%04X)", classID)
				frame.Details["cip_class"] = frame.CIPClass
			}
			frame.Details["cip_class_id"] = classID

		case 0x24: // Instance ID
			frame.CIPInstance = uint16(value)
			frame.Details["cip_instance"] = frame.CIPInstance

		case 0x30: // Attribute ID
			frame.CIPAttribute = uint16(value)
			frame.Details["cip_attribute"] = frame.CIPAttribute
		}
	}
}

// categorizeCIPService categorizes CIP service codes
func (e *EtherNetIPAnalyzer) categorizeCIPService(serviceCode uint8) string {
	switch {
	case serviceCode >= 0x01 && serviceCode <= 0x1F:
		return "Object Services"
	case serviceCode >= 0x4B && serviceCode <= 0x5F:
		return "Application Services"
	case serviceCode >= 0x20 && serviceCode <= 0x3F:
		return "Connection Services"
	default:
		return "Other"
	}
}
