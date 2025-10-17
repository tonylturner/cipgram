package detection

import (
	"cipgram/pkg/pcap/core"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MockDPIEngine for testing
type MockDPIEngine struct {
	protocols []string
	results   map[string]*core.AnalysisResult
}

func NewMockDPIEngine() *MockDPIEngine {
	return &MockDPIEngine{
		protocols: []string{"HTTP", "Modbus", "EtherNet/IP"},
		results:   make(map[string]*core.AnalysisResult),
	}
}

func (m *MockDPIEngine) AnalyzePacket(packet gopacket.Packet) *core.AnalysisResult {
	// Simple mock: return HTTP for packets with HTTP-like payload
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := string(appLayer.Payload())
		if len(payload) > 4 && payload[:4] == "GET " {
			return &core.AnalysisResult{
				Protocol:    "HTTP",
				Subprotocol: "GET Request",
				Confidence:  0.95,
				Details:     map[string]interface{}{"method": "GET"},
			}
		}
	}
	return nil
}

func (m *MockDPIEngine) GetSupportedProtocols() []string {
	return m.protocols
}

func TestUnifiedDetector_DetectProtocol(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           true,
		EnableHeuristic:     true,
		ConfidenceThreshold: 0.7,
	}

	dpiEngine := NewMockDPIEngine()
	detector := NewUnifiedDetector(config, dpiEngine)

	// Create a test packet (HTTP on port 80)
	packet := createTestHTTPPacket()

	result := detector.DetectProtocol(packet)

	if result == nil {
		t.Fatal("Expected detection result, got nil")
	}

	// Should detect HTTP via DPI (highest priority)
	if result.Protocol != "HTTP" {
		t.Errorf("Expected HTTP, got %s", result.Protocol)
	}

	if result.Method != core.MethodDPI {
		t.Errorf("Expected DPI method, got %v", result.Method)
	}

	if result.Confidence < 0.7 {
		t.Errorf("Expected confidence >= 0.7, got %f", result.Confidence)
	}
}

func TestUnifiedDetector_PortBasedDetection(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           false, // Disable DPI to test port-based
		EnableHeuristic:     false,
		ConfidenceThreshold: 0.5,
	}

	detector := NewUnifiedDetector(config, nil)

	// Create a test packet on port 80
	packet := createTestTCPPacket(12345, 80, []byte("some data"))

	result := detector.DetectProtocol(packet)

	if result == nil {
		t.Fatal("Expected detection result, got nil")
	}

	if result.Protocol != "HTTP" {
		t.Errorf("Expected HTTP, got %s", result.Protocol)
	}

	if result.Method != core.MethodPort {
		t.Errorf("Expected port method, got %v", result.Method)
	}
}

func TestUnifiedDetector_ConfidenceThreshold(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           false,
		EnableHeuristic:     false,
		ConfidenceThreshold: 0.95, // High threshold
	}

	detector := NewUnifiedDetector(config, nil)

	// Create a packet that would normally be detected with lower confidence
	packet := createTestTCPPacket(12345, 8080, []byte("some data"))

	result := detector.DetectProtocol(packet)

	// Should return Unknown due to high confidence threshold
	if result.Protocol != "Unknown" {
		t.Errorf("Expected Unknown due to high threshold, got %s", result.Protocol)
	}
}

func TestUnifiedDetector_Caching(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           false,
		EnableHeuristic:     false,
		ConfidenceThreshold: 0.5,
	}

	detector := NewUnifiedDetector(config, nil)

	// Create identical packets
	packet1 := createTestTCPPacket(12345, 80, []byte("test data"))
	packet2 := createTestTCPPacket(12345, 80, []byte("test data"))

	// First detection
	result1 := detector.DetectProtocol(packet1)
	if result1 == nil {
		t.Fatal("Expected detection result, got nil")
	}

	// Second detection should use cache
	result2 := detector.DetectProtocol(packet2)
	if result2 == nil {
		t.Fatal("Expected detection result, got nil")
	}

	if result1.Protocol != result2.Protocol {
		t.Errorf("Cached result should match: %s != %s", result1.Protocol, result2.Protocol)
	}

	// Check cache stats
	cacheStats := detector.GetCacheStats()
	if cacheSize, ok := cacheStats["cache_size"].(int); !ok || cacheSize == 0 {
		t.Error("Cache should contain entries")
	}
}

func TestUnifiedDetector_GetSupportedProtocols(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased: true,
		EnableDPI:       true,
		EnableHeuristic: true,
	}

	dpiEngine := NewMockDPIEngine()
	detector := NewUnifiedDetector(config, dpiEngine)

	protocols := detector.GetSupportedProtocols()

	if len(protocols) == 0 {
		t.Error("Should support at least some protocols")
	}

	// Should include protocols from all detection methods
	protocolMap := make(map[string]bool)
	for _, protocol := range protocols {
		protocolMap[protocol] = true
	}

	// Should include HTTP from both port-based and DPI
	if !protocolMap["HTTP"] {
		t.Error("Should support HTTP protocol")
	}
}

func TestUnifiedDetector_GetDetectionStats(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           true,
		EnableHeuristic:     true,
		ConfidenceThreshold: 0.5,
	}

	dpiEngine := NewMockDPIEngine()
	detector := NewUnifiedDetector(config, dpiEngine)

	// Process some packets
	packet1 := createTestHTTPPacket()
	packet2 := createTestTCPPacket(12345, 443, []byte("https data"))

	detector.DetectProtocol(packet1)
	detector.DetectProtocol(packet2)

	stats := detector.GetDetectionStats()

	if stats.TotalPackets != 2 {
		t.Errorf("Expected 2 total packets, got %d", stats.TotalPackets)
	}

	if stats.SuccessfulDetections == 0 {
		t.Error("Should have some successful detections")
	}

	if len(stats.MethodBreakdown) == 0 {
		t.Error("Should have method breakdown statistics")
	}

	if len(stats.ProtocolCounts) == 0 {
		t.Error("Should have protocol count statistics")
	}
}

func TestUnifiedDetector_ClearCache(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		ConfidenceThreshold: 0.5,
	}

	detector := NewUnifiedDetector(config, nil)

	// Add something to cache
	packet := createTestTCPPacket(12345, 80, []byte("test"))
	detector.DetectProtocol(packet)

	// Verify cache has content
	cacheStats := detector.GetCacheStats()
	if cacheSize, ok := cacheStats["cache_size"].(int); !ok || cacheSize == 0 {
		t.Error("Cache should contain entries before clear")
	}

	// Clear cache
	detector.ClearCache()

	// Verify cache is empty
	cacheStats = detector.GetCacheStats()
	if cacheSize, ok := cacheStats["cache_size"].(int); !ok || cacheSize != 0 {
		t.Error("Cache should be empty after clear")
	}
}

func TestUnifiedDetector_SetCacheSize(t *testing.T) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		ConfidenceThreshold: 0.5,
	}

	detector := NewUnifiedDetector(config, nil)

	// Set new cache size
	newSize := 500
	detector.SetCacheSize(newSize)

	cacheStats := detector.GetCacheStats()
	if maxSize, ok := cacheStats["max_cache_size"].(int); !ok || maxSize != newSize {
		t.Errorf("Expected max cache size %d, got %v", newSize, maxSize)
	}
}

// Helper functions for creating test packets

func createTestHTTPPacket() gopacket.Packet {
	return createTestTCPPacket(12345, 80, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
}

func createTestTCPPacket(srcPort, dstPort uint16, payload []byte) gopacket.Packet {
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

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return packet
}

// Benchmark tests

func BenchmarkUnifiedDetector_DetectProtocol(b *testing.B) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           true,
		EnableHeuristic:     true,
		ConfidenceThreshold: 0.7,
	}

	dpiEngine := NewMockDPIEngine()
	detector := NewUnifiedDetector(config, dpiEngine)

	packet := createTestHTTPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectProtocol(packet)
	}
}

func BenchmarkUnifiedDetector_PortBasedOnly(b *testing.B) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		EnableDPI:           false,
		EnableHeuristic:     false,
		ConfidenceThreshold: 0.5,
	}

	detector := NewUnifiedDetector(config, nil)
	packet := createTestTCPPacket(12345, 80, []byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectProtocol(packet)
	}
}

func BenchmarkUnifiedDetector_WithCaching(b *testing.B) {
	config := &core.DetectionConfig{
		EnablePortBased:     true,
		ConfidenceThreshold: 0.5,
	}

	detector := NewUnifiedDetector(config, nil)
	packet := createTestTCPPacket(12345, 80, []byte("test"))

	// Prime the cache
	detector.DetectProtocol(packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectProtocol(packet)
	}
}
