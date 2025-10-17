package analyzers

import (
	"cipgram/pkg/pcap/core"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNP3Analyzer implements DPI for DNP3 protocol
type DNP3Analyzer struct {
	functionCodes map[uint8]string
}

// NewDNP3Analyzer creates a new DNP3 analyzer
func NewDNP3Analyzer() *DNP3Analyzer {
	return &DNP3Analyzer{
		functionCodes: map[uint8]string{
			0x00: "Confirm",
			0x01: "Read",
			0x02: "Write",
			0x03: "Select",
			0x04: "Operate",
			0x05: "Direct Operate",
			0x06: "Direct Operate No Response",
			0x07: "Immediate Freeze",
			0x08: "Immediate Freeze No Response",
			0x09: "Freeze Clear",
			0x0A: "Freeze Clear No Response",
			0x0B: "Freeze At Time",
			0x0C: "Freeze At Time No Response",
			0x0D: "Cold Restart",
			0x0E: "Warm Restart",
			0x0F: "Initialize Data",
			0x10: "Initialize Application",
			0x11: "Start Application",
			0x12: "Stop Application",
			0x13: "Save Configuration",
			0x14: "Enable Unsolicited",
			0x15: "Disable Unsolicited",
			0x16: "Assign Class",
			0x17: "Delay Measure",
			0x18: "Record Current Time",
			0x19: "Open File",
			0x1A: "Close File",
			0x1B: "Delete File",
			0x1C: "Get File Info",
			0x1D: "Authenticate",
			0x1E: "Abort",
			0x81: "Response",
			0x82: "Unsolicited Response",
		},
	}
}

// CanAnalyze determines if this analyzer can process the packet
func (d *DNP3Analyzer) CanAnalyze(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)

	// Check DNP3 TCP port (20000)
	if tcp.SrcPort == 20000 || tcp.DstPort == 20000 {
		return true
	}

	// Also check if payload looks like DNP3
	payload := tcp.Payload
	if len(payload) >= 10 {
		return d.looksLikeDNP3(payload)
	}

	return false
}

// Analyze performs DNP3 protocol analysis
func (d *DNP3Analyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 10 {
		return nil
	}

	// Parse DNP3 frame
	dnp3 := d.parseDNP3(payload)
	if dnp3 == nil {
		return nil
	}

	subprotocol := dnp3.FunctionName
	if dnp3.ObjectCount > 0 {
		subprotocol = fmt.Sprintf("%s (%d objects)", dnp3.FunctionName, dnp3.ObjectCount)
	}

	return &core.AnalysisResult{
		Protocol:    "DNP3",
		Subprotocol: subprotocol,
		Confidence:  dnp3.Confidence,
		Details:     dnp3.Details,
		Metadata:    dnp3.Metadata,
	}
}

// GetProtocolName returns the protocol name
func (d *DNP3Analyzer) GetProtocolName() string {
	return "DNP3"
}

// GetConfidenceThreshold returns the minimum confidence threshold
func (d *DNP3Analyzer) GetConfidenceThreshold() float32 {
	return 0.85
}

// DNP3Frame represents a parsed DNP3 frame
type DNP3Frame struct {
	Start        uint16
	Length       uint8
	Control      uint8
	Destination  uint16
	Source       uint16
	FunctionCode uint8
	FunctionName string
	IIN          uint16 // Internal Indication
	ObjectCount  int
	Objects      []DNP3Object
	Confidence   float32
	Details      map[string]interface{}
	Metadata     map[string]string
}

// DNP3Object represents a DNP3 data object
type DNP3Object struct {
	Group     uint8
	Variation uint8
	Qualifier uint8
	Range     string
}

// parseDNP3 parses a DNP3 frame
func (d *DNP3Analyzer) parseDNP3(payload []byte) *DNP3Frame {
	if len(payload) < 10 {
		return nil
	}

	// Check start bytes (0x0564)
	start := binary.BigEndian.Uint16(payload[0:2])
	if start != 0x0564 {
		return nil
	}

	// Parse header
	length := payload[2]
	control := payload[3]
	destination := binary.LittleEndian.Uint16(payload[4:6])
	source := binary.LittleEndian.Uint16(payload[6:8])

	// Validate length
	if length < 5 || int(length) > len(payload)-3 {
		return nil
	}

	// Calculate and verify checksum (simple validation)
	if !d.validateChecksum(payload[:length+3]) {
		return nil
	}

	frame := &DNP3Frame{
		Start:       start,
		Length:      length,
		Control:     control,
		Destination: destination,
		Source:      source,
		Confidence:  0.90,
		Details:     make(map[string]interface{}),
		Metadata:    make(map[string]string),
	}

	// Parse application layer if present
	if len(payload) > 10 {
		d.parseApplicationLayer(frame, payload[10:])
	}

	// Fill in details
	frame.Details["destination"] = destination
	frame.Details["source"] = source
	frame.Details["control"] = control
	frame.Details["length"] = length

	// Add metadata
	frame.Metadata["protocol_version"] = "3.0"
	frame.Metadata["frame_type"] = d.categorizeControl(control)

	return frame
}

// looksLikeDNP3 performs heuristic check for DNP3 content
func (d *DNP3Analyzer) looksLikeDNP3(payload []byte) bool {
	if len(payload) < 10 {
		return false
	}

	// Check start bytes
	if payload[0] != 0x05 || payload[1] != 0x64 {
		return false
	}

	// Check length field
	length := payload[2]
	if length < 5 || int(length) > len(payload)-3 {
		return false
	}

	return true
}

// validateChecksum performs basic checksum validation
func (d *DNP3Analyzer) validateChecksum(data []byte) bool {
	// DNP3 uses CRC-16, but for simplicity we'll do basic validation
	// In a full implementation, you'd calculate the actual CRC
	return len(data) >= 10
}

// parseApplicationLayer parses DNP3 application layer
func (d *DNP3Analyzer) parseApplicationLayer(frame *DNP3Frame, data []byte) {
	if len(data) < 2 {
		return
	}

	// Parse application control and function code
	appControl := data[0]
	functionCode := data[1]

	frame.FunctionCode = functionCode
	functionName, exists := d.functionCodes[functionCode]
	if exists {
		frame.FunctionName = functionName
	} else {
		frame.FunctionName = fmt.Sprintf("Unknown Function (0x%02X)", functionCode)
	}

	frame.Details["function_code"] = functionCode
	frame.Details["function_name"] = frame.FunctionName
	frame.Details["app_control"] = appControl

	// Parse IIN (Internal Indication) for responses
	if functionCode == 0x81 || functionCode == 0x82 {
		if len(data) >= 4 {
			frame.IIN = binary.LittleEndian.Uint16(data[2:4])
			frame.Details["iin"] = frame.IIN
			frame.Metadata["iin_flags"] = d.parseIIN(frame.IIN)
		}
	}

	// Parse objects if present
	objectData := data[2:]
	if functionCode == 0x81 || functionCode == 0x82 {
		objectData = data[4:] // Skip IIN for responses
	}

	if len(objectData) > 0 {
		frame.Objects = d.parseObjects(objectData)
		frame.ObjectCount = len(frame.Objects)
		frame.Details["object_count"] = frame.ObjectCount
	}

	frame.Metadata["function_category"] = d.categorizeFunctionCode(functionCode)
}

// parseObjects parses DNP3 data objects
func (d *DNP3Analyzer) parseObjects(data []byte) []DNP3Object {
	var objects []DNP3Object
	offset := 0

	for offset < len(data)-2 {
		if offset+3 > len(data) {
			break
		}

		group := data[offset]
		variation := data[offset+1]
		qualifier := data[offset+2]

		obj := DNP3Object{
			Group:     group,
			Variation: variation,
			Qualifier: qualifier,
			Range:     d.parseRange(qualifier, data[offset+3:]),
		}

		objects = append(objects, obj)

		// Skip to next object (simplified - would need proper parsing)
		offset += 3 + d.getRangeSize(qualifier)
		if offset >= len(data) {
			break
		}
	}

	return objects
}

// parseRange parses object range based on qualifier
func (d *DNP3Analyzer) parseRange(qualifier uint8, data []byte) string {
	// Simplified range parsing
	switch qualifier & 0x0F {
	case 0x00, 0x01:
		if len(data) >= 2 {
			start := binary.LittleEndian.Uint16(data[0:2])
			return fmt.Sprintf("Start: %d", start)
		}
	case 0x07, 0x08:
		if len(data) >= 1 {
			count := data[0]
			return fmt.Sprintf("Count: %d", count)
		}
	}
	return "Unknown"
}

// getRangeSize returns the size of range data based on qualifier
func (d *DNP3Analyzer) getRangeSize(qualifier uint8) int {
	switch qualifier & 0x0F {
	case 0x00, 0x01:
		return 2 // 16-bit range
	case 0x07, 0x08:
		return 1 // 8-bit count
	default:
		return 0
	}
}

// parseIIN parses Internal Indication flags
func (d *DNP3Analyzer) parseIIN(iin uint16) string {
	var flags []string

	if iin&0x0001 != 0 {
		flags = append(flags, "ALL_STATIONS")
	}
	if iin&0x0002 != 0 {
		flags = append(flags, "CLASS_1_EVENTS")
	}
	if iin&0x0004 != 0 {
		flags = append(flags, "CLASS_2_EVENTS")
	}
	if iin&0x0008 != 0 {
		flags = append(flags, "CLASS_3_EVENTS")
	}
	if iin&0x0010 != 0 {
		flags = append(flags, "NEED_TIME")
	}
	if iin&0x0020 != 0 {
		flags = append(flags, "LOCAL_CONTROL")
	}
	if iin&0x0040 != 0 {
		flags = append(flags, "DEVICE_TROUBLE")
	}
	if iin&0x0080 != 0 {
		flags = append(flags, "DEVICE_RESTART")
	}

	if len(flags) == 0 {
		return "None"
	}

	result := ""
	for i, flag := range flags {
		if i > 0 {
			result += ", "
		}
		result += flag
	}
	return result
}

// categorizeControl categorizes control field
func (d *DNP3Analyzer) categorizeControl(control uint8) string {
	dir := (control & 0x80) != 0
	prm := (control & 0x40) != 0

	if dir && prm {
		return "Request from Master"
	} else if !dir && !prm {
		return "Response from Outstation"
	} else if dir && !prm {
		return "Unsolicited Response"
	} else {
		return "Reserved"
	}
}

// categorizeFunctionCode categorizes function codes
func (d *DNP3Analyzer) categorizeFunctionCode(code uint8) string {
	switch {
	case code >= 0x00 && code <= 0x06:
		return "Control Functions"
	case code >= 0x07 && code <= 0x0C:
		return "Freeze Functions"
	case code >= 0x0D && code <= 0x12:
		return "Application Control"
	case code >= 0x13 && code <= 0x17:
		return "Configuration"
	case code >= 0x18 && code <= 0x1E:
		return "File Transfer"
	case code == 0x81:
		return "Response"
	case code == 0x82:
		return "Unsolicited Response"
	default:
		return "Other"
	}
}
