package integration_test

import (
	"cipgram/pkg/pcap/core"
	"cipgram/pkg/pcap/integration"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestModularDetectionAdapter_Integration(t *testing.T) {
	// Create temporary config for testing
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.json")

	adapter := integration.NewModularDetectionAdapter(configPath)

	// Test HTTP detection
	httpPacket := createHTTPPacket()
	protocol := adapter.DetectProtocol(httpPacket)

	if protocol == "Unknown" {
		t.Error("Should detect HTTP protocol")
	}

	// Test detailed detection
	details := adapter.DetectProtocolWithDetails(httpPacket)
	if details == nil {
		t.Fatal("Should return detection details")
	}

	if details.Confidence == 0.0 {
		t.Error("Should have non-zero confidence")
	}

	if details.Method == "none" {
		t.Error("Should have a detection method")
	}
}

func TestModularDetectionAdapter_SupportedProtocols(t *testing.T) {
	adapter := integration.NewModularDetectionAdapter("")

	protocols := adapter.GetSupportedProtocols()

	if len(protocols) == 0 {
		t.Error("Should support at least some protocols")
	}

	// Check for common protocols
	protocolMap := make(map[string]bool)
	for _, protocol := range protocols {
		protocolMap[protocol] = true
	}

	expectedProtocols := []string{"HTTP", "HTTPS", "SSH", "DNS"}
	for _, expected := range expectedProtocols {
		if !protocolMap[expected] {
			t.Errorf("Should support %s protocol", expected)
		}
	}
}

func TestModularDetectionAdapter_Statistics(t *testing.T) {
	adapter := integration.NewModularDetectionAdapter("")

	// Process some test packets
	packets := []gopacket.Packet{
		createHTTPPacket(),
		createSSHPacket(),
		createDNSPacket(),
	}

	for _, packet := range packets {
		adapter.DetectProtocol(packet)
	}

	// Check detection statistics
	stats := adapter.GetDetectionStats()

	if totalPackets, ok := stats["total_packets"].(int64); !ok || totalPackets != 3 {
		t.Errorf("Expected 3 total packets, got %v", stats["total_packets"])
	}

	if successRate, ok := stats["success_rate"].(float32); !ok || successRate == 0.0 {
		t.Error("Should have non-zero success rate")
	}

	// Check DPI statistics
	dpiStats := adapter.GetDPIStats()
	if dpiStats == nil {
		t.Error("Should return DPI statistics")
	}
}

func TestModularDetectionAdapter_Configuration(t *testing.T) {
	adapter := integration.NewModularDetectionAdapter("")

	// Test configuration update
	config := &core.Config{
		Detection: &core.DetectionConfig{
			EnablePortBased:     true,
			EnableDPI:           false,
			EnableHeuristic:     true,
			ConfidenceThreshold: 0.8,
		},
		DPI: &core.DPIConfig{
			EnableHTTP: false,
			EnableTLS:  true,
		},
	}

	adapter.UpdateConfiguration(config)

	// Test that configuration was applied
	// This would require access to internal state or observable behavior changes
	// For now, we just verify the method doesn't panic
}

func TestModularDetectionAdapter_CacheManagement(t *testing.T) {
	adapter := integration.NewModularDetectionAdapter("")

	// Process same packet multiple times
	packet := createHTTPPacket()

	for i := 0; i < 5; i++ {
		adapter.DetectProtocol(packet)
	}

	// Clear cache
	adapter.ClearCache()

	// Process packet again
	result := adapter.DetectProtocol(packet)
	if result == "" {
		t.Error("Should still detect protocol after cache clear")
	}
}

func TestModularDetectionAdapter_PerformanceReport(t *testing.T) {
	adapter := integration.NewModularDetectionAdapter("")

	// Process some packets
	packets := []gopacket.Packet{
		createHTTPPacket(),
		createSSHPacket(),
		createDNSPacket(),
	}

	for _, packet := range packets {
		adapter.DetectProtocol(packet)
	}

	report := adapter.GetPerformanceReport()

	// Check report structure
	if _, exists := report["detection"]; !exists {
		t.Error("Performance report should include detection section")
	}

	if _, exists := report["dpi"]; !exists {
		t.Error("Performance report should include DPI section")
	}

	if _, exists := report["configuration"]; !exists {
		t.Error("Performance report should include configuration section")
	}
}

func TestBackwardCompatibilityWrapper(t *testing.T) {
	wrapper := integration.NewBackwardCompatibilityWrapper("")

	// Test old-style detection interface
	packet := createHTTPPacket()
	protocol, subprotocol, details := wrapper.DetectProtocol(packet)

	if protocol == "" {
		t.Error("Should return protocol name")
	}

	// Subprotocol and details might be empty, but shouldn't cause errors
	_ = subprotocol
	_ = details

	// Test old-style statistics
	stats := wrapper.GetStats()
	if stats == nil {
		t.Error("Should return statistics map")
	}
}

func TestOptimizedDetector(t *testing.T) {
	detector := integration.NewOptimizedDetector("")

	// Test fast detection
	packet := createHTTPPacket()
	protocol := detector.FastDetect(packet)

	if protocol == "" {
		t.Error("Fast detect should return protocol")
	}

	// Test cache statistics
	cacheStats := detector.GetCacheStats()
	if cacheStats == nil {
		t.Error("Should return cache statistics")
	}
}

func TestConfigurableDetector(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.json")

	// Create a basic config file
	configContent := `{
		"detection": {
			"enable_port_based": true,
			"enable_dpi": true,
			"confidence_threshold": 0.8
		},
		"dpi": {
			"enable_http": true,
			"enable_tls": false
		}
	}`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	detector := integration.NewConfigurableDetector(configPath)

	// Test configuration loading
	if err := detector.UpdateFromFile(configPath); err != nil {
		t.Errorf("Failed to update from file: %v", err)
	}

	// Test DPI enable/disable
	if err := detector.SetDPIEnabled(false); err != nil {
		t.Errorf("Failed to disable DPI: %v", err)
	}

	if err := detector.SetHeuristicEnabled(true); err != nil {
		t.Errorf("Failed to enable heuristic: %v", err)
	}

	// Test getting current config
	config := detector.GetCurrentConfig()
	if config == nil {
		t.Error("Should return current configuration")
	}
}

// Helper functions for creating test packets

func createHTTPPacket() gopacket.Packet {
	return createTCPPacket(12345, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
}

func createSSHPacket() gopacket.Packet {
	return createTCPPacket(12345, 22, []byte("SSH-2.0-OpenSSH_7.4"))
}

func createDNSPacket() gopacket.Packet {
	return createUDPPacket(12345, 53, []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query: example.com A record
		0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	})
}

func createTCPPacket(srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		Ack:     2000,
		PSH:     true,
		ACK:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Create packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createUDPPacket(srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Create packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Benchmark tests

func BenchmarkModularDetectionAdapter_DetectProtocol(b *testing.B) {
	adapter := integration.NewModularDetectionAdapter("")
	packet := createHTTPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.DetectProtocol(packet)
	}
}

func BenchmarkOptimizedDetector_FastDetect(b *testing.B) {
	detector := integration.NewOptimizedDetector("")
	packet := createHTTPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.FastDetect(packet)
	}
}

func BenchmarkBackwardCompatibilityWrapper_DetectProtocol(b *testing.B) {
	wrapper := integration.NewBackwardCompatibilityWrapper("")
	packet := createHTTPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wrapper.DetectProtocol(packet)
	}
}
