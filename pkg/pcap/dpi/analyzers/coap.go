package analyzers

import (
	"cipgram/pkg/pcap/core"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CoAPAnalyzer implements DPI for CoAP (Constrained Application Protocol)
type CoAPAnalyzer struct {
	messageCodes map[uint8]string
	optionNames  map[uint16]string
}

// NewCoAPAnalyzer creates a new CoAP analyzer
func NewCoAPAnalyzer() *CoAPAnalyzer {
	return &CoAPAnalyzer{
		messageCodes: map[uint8]string{
			0: "Empty",
			1: "GET",
			2: "POST",
			3: "PUT",
			4: "DELETE",
			// Response codes
			65:  "Created",
			66:  "Deleted",
			67:  "Valid",
			68:  "Changed",
			69:  "Content",
			128: "Bad Request",
			129: "Unauthorized",
			130: "Bad Option",
			131: "Forbidden",
			132: "Not Found",
			133: "Method Not Allowed",
			134: "Not Acceptable",
			140: "Precondition Failed",
			141: "Request Entity Too Large",
			143: "Unsupported Content-Format",
			160: "Internal Server Error",
			161: "Not Implemented",
			162: "Bad Gateway",
			163: "Service Unavailable",
			164: "Gateway Timeout",
			165: "Proxying Not Supported",
		},
		optionNames: map[uint16]string{
			1:  "If-Match",
			3:  "Uri-Host",
			4:  "ETag",
			5:  "If-None-Match",
			7:  "Uri-Port",
			8:  "Location-Path",
			11: "Uri-Path",
			12: "Content-Format",
			14: "Max-Age",
			15: "Uri-Query",
			17: "Accept",
			20: "Location-Query",
			35: "Proxy-Uri",
			39: "Proxy-Scheme",
			60: "Size1",
		},
	}
}

// CanAnalyze determines if this analyzer can process the packet
func (c *CoAPAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)

	// Check CoAP port (5683)
	if udp.SrcPort == 5683 || udp.DstPort == 5683 {
		payload := udp.Payload
		if len(payload) >= 4 {
			return c.looksLikeCoAP(payload)
		}
	}

	return false
}

// Analyze performs CoAP protocol analysis
func (c *CoAPAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}

	udp := udpLayer.(*layers.UDP)
	payload := udp.Payload

	if len(payload) < 4 {
		return nil
	}

	// Parse CoAP message
	coapMsg := c.parseCoAPMessage(payload)
	if coapMsg == nil {
		return nil
	}

	return &core.AnalysisResult{
		Protocol:    "CoAP",
		Subprotocol: coapMsg.MethodName,
		Confidence:  0.9,
		Details:     coapMsg.Details,
		Metadata:    coapMsg.Metadata,
	}
}

// GetProtocolName returns the protocol name
func (c *CoAPAnalyzer) GetProtocolName() string {
	return "CoAP"
}

// GetConfidenceThreshold returns the confidence threshold
func (c *CoAPAnalyzer) GetConfidenceThreshold() float32 {
	return 0.85
}

// CoAPMessage represents a parsed CoAP message
type CoAPMessage struct {
	Version    uint8
	Type       uint8
	TokenLen   uint8
	Code       uint8
	MessageID  uint16
	Token      []byte
	Options    []CoAPOption
	Payload    []byte
	MethodName string
	Details    map[string]interface{}
	Metadata   map[string]string
}

// CoAPOption represents a CoAP option
type CoAPOption struct {
	Number uint16
	Length uint16
	Value  []byte
}

// looksLikeCoAP performs heuristic check for CoAP content
func (c *CoAPAnalyzer) looksLikeCoAP(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}

	// Check version (should be 1)
	version := (payload[0] >> 6) & 0x03
	if version != 1 {
		return false
	}

	// Check message type (0-3)
	msgType := (payload[0] >> 4) & 0x03
	if msgType > 3 {
		return false
	}

	// Check token length (0-8)
	tokenLen := payload[0] & 0x0F
	if tokenLen > 8 {
		return false
	}

	// Check if we have enough bytes for the header + token
	if len(payload) < int(4+tokenLen) {
		return false
	}

	return true
}

// parseCoAPMessage parses a CoAP message
func (c *CoAPAnalyzer) parseCoAPMessage(payload []byte) *CoAPMessage {
	if len(payload) < 4 {
		return nil
	}

	msg := &CoAPMessage{
		Details:  make(map[string]interface{}),
		Metadata: make(map[string]string),
	}

	// Parse header
	msg.Version = (payload[0] >> 6) & 0x03
	msg.Type = (payload[0] >> 4) & 0x03
	msg.TokenLen = payload[0] & 0x0F
	msg.Code = payload[1]
	msg.MessageID = binary.BigEndian.Uint16(payload[2:4])

	// Validate header
	if msg.Version != 1 || msg.TokenLen > 8 {
		return nil
	}

	offset := 4

	// Parse token
	if msg.TokenLen > 0 {
		if len(payload) < offset+int(msg.TokenLen) {
			return nil
		}
		msg.Token = payload[offset : offset+int(msg.TokenLen)]
		offset += int(msg.TokenLen)
	}

	// Parse options
	msg.Options = c.parseOptions(payload[offset:])

	// Find payload marker (0xFF)
	for i := offset; i < len(payload); i++ {
		if payload[i] == 0xFF {
			if i+1 < len(payload) {
				msg.Payload = payload[i+1:]
			}
			break
		}
	}

	// Determine method name
	msg.MethodName = c.getMethodName(msg.Code)

	// Fill details
	msg.Details["version"] = msg.Version
	msg.Details["type"] = c.getTypeName(msg.Type)
	msg.Details["code"] = msg.Code
	msg.Details["message_id"] = msg.MessageID
	msg.Details["token_length"] = msg.TokenLen
	msg.Details["options_count"] = len(msg.Options)
	msg.Details["payload_length"] = len(msg.Payload)

	// Add metadata
	msg.Metadata["protocol_type"] = "iot"
	msg.Metadata["layer"] = "application"
	msg.Metadata["message_type"] = c.getTypeName(msg.Type)

	return msg
}

// parseOptions parses CoAP options
func (c *CoAPAnalyzer) parseOptions(payload []byte) []CoAPOption {
	var options []CoAPOption
	offset := 0
	optionNumber := uint16(0)

	for offset < len(payload) {
		if payload[offset] == 0xFF { // Payload marker
			break
		}

		if offset >= len(payload) {
			break
		}

		// Parse option header
		optionDelta := (payload[offset] >> 4) & 0x0F
		optionLength := payload[offset] & 0x0F
		offset++

		// Handle extended option delta
		var deltaValue uint16
		if optionDelta == 13 {
			if offset >= len(payload) {
				break
			}
			deltaValue = uint16(payload[offset]) + 13
			offset++
		} else if optionDelta == 14 {
			if offset+1 >= len(payload) {
				break
			}
			deltaValue = binary.BigEndian.Uint16(payload[offset:offset+2]) + 269
			offset += 2
		} else {
			deltaValue = uint16(optionDelta)
		}

		// Handle extended option length
		var lengthValue uint16
		if optionLength == 13 {
			if offset >= len(payload) {
				break
			}
			lengthValue = uint16(payload[offset]) + 13
			offset++
		} else if optionLength == 14 {
			if offset+1 >= len(payload) {
				break
			}
			lengthValue = binary.BigEndian.Uint16(payload[offset:offset+2]) + 269
			offset += 2
		} else {
			lengthValue = uint16(optionLength)
		}

		optionNumber += deltaValue

		// Parse option value
		var optionValue []byte
		if lengthValue > 0 {
			if offset+int(lengthValue) > len(payload) {
				break
			}
			optionValue = payload[offset : offset+int(lengthValue)]
			offset += int(lengthValue)
		}

		options = append(options, CoAPOption{
			Number: optionNumber,
			Length: lengthValue,
			Value:  optionValue,
		})
	}

	return options
}

// getMethodName returns the method name for a code
func (c *CoAPAnalyzer) getMethodName(code uint8) string {
	if name, exists := c.messageCodes[code]; exists {
		return name
	}
	return fmt.Sprintf("Unknown Code (%d)", code)
}

// getTypeName returns the type name for a message type
func (c *CoAPAnalyzer) getTypeName(msgType uint8) string {
	switch msgType {
	case 0:
		return "Confirmable"
	case 1:
		return "Non-confirmable"
	case 2:
		return "Acknowledgement"
	case 3:
		return "Reset"
	default:
		return "Unknown"
	}
}
