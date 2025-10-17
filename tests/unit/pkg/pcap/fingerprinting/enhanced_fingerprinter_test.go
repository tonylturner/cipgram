package fingerprinting_test

import (
	"cipgram/pkg/pcap/core"
	"cipgram/pkg/pcap/fingerprinting"
	"cipgram/pkg/types"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewEnhancedDeviceFingerprinter(t *testing.T) {
	fingerprinter := fingerprinting.NewEnhancedDeviceFingerprinter()

	if fingerprinter == nil {
		t.Fatal("NewEnhancedDeviceFingerprinter() returned nil")
	}

	// Test that it implements the expected interface methods
	deviceTypes := fingerprinter.GetDeviceTypes()
	if len(deviceTypes) == 0 {
		t.Error("Expected non-empty device types list")
	}
}

func TestGetDeviceTypes(t *testing.T) {
	fingerprinter := fingerprinting.NewEnhancedDeviceFingerprinter()
	deviceTypes := fingerprinter.GetDeviceTypes()

	if len(deviceTypes) == 0 {
		t.Error("Expected non-empty device types list")
	}

	// Check for expected device types
	expectedTypes := []string{"PLC", "HMI", "RTU", "Workstation", "Network Switch"}
	for _, expectedType := range expectedTypes {
		found := false
		for _, deviceType := range deviceTypes {
			if deviceType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected device type %s not found in list", expectedType)
		}
	}
}

func TestFingerprintDevice(t *testing.T) {
	fingerprinter := fingerprinting.NewEnhancedDeviceFingerprinter()

	// Create test asset
	asset := &types.Asset{
		ID:        "192.168.1.100",
		IP:        "192.168.1.100",
		MAC:       "00:0c:29:12:34:56", // VMware MAC
		Protocols: []types.Protocol{types.ProtoModbus, types.ProtoHTTP},
	}

	// Create test packets
	packets := createMockTCPPackets()

	result := fingerprinter.FingerprintDevice(asset, packets)

	if result == nil {
		t.Fatal("FingerprintDevice() returned nil")
	}

	// Verify result structure
	if result.DeviceType == "" {
		t.Error("Expected non-empty device type")
	}

	if result.Confidence < 0 || result.Confidence > 1 {
		t.Errorf("Expected confidence between 0 and 1, got %f", result.Confidence)
	}

	if len(result.Indicators) == 0 {
		t.Error("Expected at least one indicator")
	}

	// For industrial protocols, should classify as industrial device
	if result.DeviceType == "Unknown" {
		t.Error("Expected device type classification for asset with industrial protocols")
	}
}

func TestUpdateSignatures(t *testing.T) {
	fingerprinter := fingerprinting.NewEnhancedDeviceFingerprinter()

	// Test signature update (should not error)
	signatures := make(map[string]*core.DeviceSignature)
	err := fingerprinter.UpdateSignatures(signatures)

	if err != nil {
		t.Errorf("UpdateSignatures() returned error: %v", err)
	}
}

// Helper functions for creating mock data

func createMockTCPPackets() []gopacket.Packet {
	packets := make([]gopacket.Packet, 3)

	for i := 0; i < 3; i++ {
		// Create TCP SYN packet
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x12, 0x34, 0x56},
			DstMAC:       []byte{0x00, 0x50, 0x56, 0x78, 0x9a, 0xbc},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    []byte{192, 168, 1, 100},
			DstIP:    []byte{192, 168, 1, 1},
		}

		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(12345 + i),
			DstPort: layers.TCPPort(502), // Modbus port
			SYN:     true,
			Window:  65535,
			Options: []layers.TCPOption{
				{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
				{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x07}},
			},
		}

		// Serialize packet
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp.SetNetworkLayerForChecksum(ip)
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)

		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		packets[i] = packet
	}

	return packets
}

// Benchmark tests

func BenchmarkFingerprintDevice(b *testing.B) {
	fingerprinter := fingerprinting.NewEnhancedDeviceFingerprinter()

	asset := &types.Asset{
		ID:        "192.168.1.100",
		IP:        "192.168.1.100",
		MAC:       "00:0c:29:12:34:56",
		Protocols: []types.Protocol{types.ProtoModbus, types.ProtoHTTP},
	}

	packets := createMockTCPPackets()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := fingerprinter.FingerprintDevice(asset, packets)
		_ = result
	}
}
