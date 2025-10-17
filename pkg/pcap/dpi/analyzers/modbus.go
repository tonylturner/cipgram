package analyzers

import (
	"cipgram/pkg/pcap/core"
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ModbusAnalyzer implements DPI for Modbus TCP protocol
type ModbusAnalyzer struct {
	functionCodes map[uint8]string
}

// NewModbusAnalyzer creates a new Modbus analyzer
func NewModbusAnalyzer() *ModbusAnalyzer {
	return &ModbusAnalyzer{
		functionCodes: map[uint8]string{
			0x01: "Read Coils",
			0x02: "Read Discrete Inputs",
			0x03: "Read Holding Registers",
			0x04: "Read Input Registers",
			0x05: "Write Single Coil",
			0x06: "Write Single Register",
			0x0F: "Write Multiple Coils",
			0x10: "Write Multiple Registers",
			0x16: "Mask Write Register",
			0x17: "Read/Write Multiple Registers",
			0x2B: "Encapsulated Interface Transport",
		},
	}
}

// CanAnalyze determines if this analyzer can process the packet
func (m *ModbusAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)

	// Check Modbus TCP port (502)
	if tcp.SrcPort == 502 || tcp.DstPort == 502 {
		return true
	}

	// Also check if payload looks like Modbus
	payload := tcp.Payload
	if len(payload) >= 7 {
		return m.looksLikeModbus(payload)
	}

	return false
}

// Analyze performs Modbus protocol analysis
func (m *ModbusAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) < 7 {
		return nil
	}

	// Parse Modbus TCP header
	modbus := m.parseModbusTCP(payload)
	if modbus == nil {
		return nil
	}

	return &core.AnalysisResult{
		Protocol:    "Modbus TCP",
		Subprotocol: modbus.FunctionName,
		Confidence:  modbus.Confidence,
		Details:     modbus.Details,
		Metadata:    modbus.Metadata,
	}
}

// GetProtocolName returns the protocol name
func (m *ModbusAnalyzer) GetProtocolName() string {
	return "Modbus TCP"
}

// GetConfidenceThreshold returns the minimum confidence threshold
func (m *ModbusAnalyzer) GetConfidenceThreshold() float32 {
	return 0.85
}

// ModbusTCPFrame represents a parsed Modbus TCP frame
type ModbusTCPFrame struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
	FunctionCode  uint8
	FunctionName  string
	Data          []byte
	Confidence    float32
	Details       map[string]interface{}
	Metadata      map[string]string
}

// parseModbusTCP parses a Modbus TCP frame
func (m *ModbusAnalyzer) parseModbusTCP(payload []byte) *ModbusTCPFrame {
	if len(payload) < 7 {
		return nil
	}

	// Parse MBAP header (7 bytes)
	transactionID := binary.BigEndian.Uint16(payload[0:2])
	protocolID := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])
	unitID := payload[6]

	// Protocol ID must be 0 for Modbus TCP
	if protocolID != 0 {
		return nil
	}

	// Length should be reasonable (1-252 bytes)
	if length < 1 || length > 252 {
		return nil
	}

	// Check if we have the function code
	if len(payload) < 8 {
		return nil
	}

	functionCode := payload[7]

	// Validate function code
	if !m.isValidFunctionCode(functionCode) {
		return nil
	}

	functionName, exists := m.functionCodes[functionCode]
	if !exists {
		functionName = fmt.Sprintf("Unknown Function (0x%02X)", functionCode)
	}

	// Extract data portion
	var data []byte
	if len(payload) > 8 {
		data = payload[8:]
	}

	frame := &ModbusTCPFrame{
		TransactionID: transactionID,
		ProtocolID:    protocolID,
		Length:        length,
		UnitID:        unitID,
		FunctionCode:  functionCode,
		FunctionName:  functionName,
		Data:          data,
		Confidence:    0.95,
		Details:       make(map[string]interface{}),
		Metadata:      make(map[string]string),
	}

	// Fill in details
	frame.Details["transaction_id"] = transactionID
	frame.Details["unit_id"] = unitID
	frame.Details["function_code"] = functionCode
	frame.Details["function_name"] = functionName
	frame.Details["data_length"] = len(data)

	// Add metadata
	frame.Metadata["protocol_version"] = "TCP"
	frame.Metadata["function_category"] = m.categorizeFunctionCode(functionCode)

	// Parse function-specific data
	m.parseFunctionData(frame)

	return frame
}

// looksLikeModbus performs heuristic check for Modbus-like content
func (m *ModbusAnalyzer) looksLikeModbus(payload []byte) bool {
	if len(payload) < 7 {
		return false
	}

	// Check protocol ID (should be 0x0000)
	protocolID := binary.BigEndian.Uint16(payload[2:4])
	if protocolID != 0 {
		return false
	}

	// Check length field
	length := binary.BigEndian.Uint16(payload[4:6])
	if length < 1 || length > 252 {
		return false
	}

	// Check function code if available
	if len(payload) >= 8 {
		functionCode := payload[7]
		return m.isValidFunctionCode(functionCode)
	}

	return true
}

// isValidFunctionCode checks if a function code is valid
func (m *ModbusAnalyzer) isValidFunctionCode(code uint8) bool {
	// Valid function codes are 1-127
	// Exception responses have bit 7 set (128-255)
	return code >= 1 && code <= 127 || (code >= 129 && code <= 255)
}

// categorizeFunctionCode categorizes function codes
func (m *ModbusAnalyzer) categorizeFunctionCode(code uint8) string {
	// Check if it's an exception response
	if code >= 128 {
		return "Exception Response"
	}

	switch {
	case code >= 1 && code <= 4:
		return "Read Function"
	case code >= 5 && code <= 6:
		return "Write Single"
	case code >= 15 && code <= 16:
		return "Write Multiple"
	case code == 23:
		return "Read/Write Multiple"
	case code >= 43 && code <= 44:
		return "Encapsulated Interface"
	default:
		return "Other"
	}
}

// parseFunctionData parses function-specific data
func (m *ModbusAnalyzer) parseFunctionData(frame *ModbusTCPFrame) {
	switch frame.FunctionCode {
	case 0x01, 0x02: // Read Coils/Discrete Inputs
		m.parseReadBitsRequest(frame)
	case 0x03, 0x04: // Read Holding/Input Registers
		m.parseReadRegistersRequest(frame)
	case 0x05: // Write Single Coil
		m.parseWriteSingleCoilRequest(frame)
	case 0x06: // Write Single Register
		m.parseWriteSingleRegisterRequest(frame)
	case 0x0F: // Write Multiple Coils
		m.parseWriteMultipleCoilsRequest(frame)
	case 0x10: // Write Multiple Registers
		m.parseWriteMultipleRegistersRequest(frame)
	}
}

// parseReadBitsRequest parses read coils/discrete inputs request
func (m *ModbusAnalyzer) parseReadBitsRequest(frame *ModbusTCPFrame) {
	if len(frame.Data) >= 4 {
		startAddress := binary.BigEndian.Uint16(frame.Data[0:2])
		quantity := binary.BigEndian.Uint16(frame.Data[2:4])

		frame.Details["start_address"] = startAddress
		frame.Details["quantity"] = quantity
		frame.Metadata["operation"] = "read_bits"
	}
}

// parseReadRegistersRequest parses read holding/input registers request
func (m *ModbusAnalyzer) parseReadRegistersRequest(frame *ModbusTCPFrame) {
	if len(frame.Data) >= 4 {
		startAddress := binary.BigEndian.Uint16(frame.Data[0:2])
		quantity := binary.BigEndian.Uint16(frame.Data[2:4])

		frame.Details["start_address"] = startAddress
		frame.Details["quantity"] = quantity
		frame.Metadata["operation"] = "read_registers"
	}
}

// parseWriteSingleCoilRequest parses write single coil request
func (m *ModbusAnalyzer) parseWriteSingleCoilRequest(frame *ModbusTCPFrame) {
	if len(frame.Data) >= 4 {
		address := binary.BigEndian.Uint16(frame.Data[0:2])
		value := binary.BigEndian.Uint16(frame.Data[2:4])

		frame.Details["address"] = address
		frame.Details["value"] = value
		frame.Metadata["operation"] = "write_single_coil"
	}
}

// parseWriteSingleRegisterRequest parses write single register request
func (m *ModbusAnalyzer) parseWriteSingleRegisterRequest(frame *ModbusTCPFrame) {
	if len(frame.Data) >= 4 {
		address := binary.BigEndian.Uint16(frame.Data[0:2])
		value := binary.BigEndian.Uint16(frame.Data[2:4])

		frame.Details["address"] = address
		frame.Details["value"] = value
		frame.Metadata["operation"] = "write_single_register"
	}
}

// parseWriteMultipleCoilsRequest parses write multiple coils request
func (m *ModbusAnalyzer) parseWriteMultipleCoilsRequest(frame *ModbusTCPFrame) {
	if len(frame.Data) >= 5 {
		startAddress := binary.BigEndian.Uint16(frame.Data[0:2])
		quantity := binary.BigEndian.Uint16(frame.Data[2:4])
		byteCount := frame.Data[4]

		frame.Details["start_address"] = startAddress
		frame.Details["quantity"] = quantity
		frame.Details["byte_count"] = byteCount
		frame.Metadata["operation"] = "write_multiple_coils"
	}
}

// parseWriteMultipleRegistersRequest parses write multiple registers request
func (m *ModbusAnalyzer) parseWriteMultipleRegistersRequest(frame *ModbusTCPFrame) {
	if len(frame.Data) >= 5 {
		startAddress := binary.BigEndian.Uint16(frame.Data[0:2])
		quantity := binary.BigEndian.Uint16(frame.Data[2:4])
		byteCount := frame.Data[4]

		frame.Details["start_address"] = startAddress
		frame.Details["quantity"] = quantity
		frame.Details["byte_count"] = byteCount
		frame.Metadata["operation"] = "write_multiple_registers"
	}
}
