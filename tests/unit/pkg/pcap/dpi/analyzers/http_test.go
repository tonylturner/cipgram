package analyzers_test

import (
	"cipgram/pkg/pcap/dpi/analyzers"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewHTTPAnalyzer(t *testing.T) {
	analyzer := analyzers.NewHTTPAnalyzer()

	if analyzer == nil {
		t.Fatal("analyzers.NewHTTPAnalyzer() returned nil")
	}

	// Test that it implements the interface methods
	name := analyzer.GetProtocolName()
	if name != "HTTP" {
		t.Errorf("Expected protocol name 'HTTP', got '%s'", name)
	}

	threshold := analyzer.GetConfidenceThreshold()
	if threshold <= 0 || threshold > 1 {
		t.Errorf("Expected confidence threshold between 0 and 1, got %f", threshold)
	}
}

func TestHTTPAnalyzer_GetProtocolName(t *testing.T) {
	analyzer := analyzers.NewHTTPAnalyzer()
	name := analyzer.GetProtocolName()

	if name != "HTTP" {
		t.Errorf("Expected protocol name 'HTTP', got '%s'", name)
	}
}

func TestHTTPAnalyzer_GetConfidenceThreshold(t *testing.T) {
	analyzer := analyzers.NewHTTPAnalyzer()
	threshold := analyzer.GetConfidenceThreshold()

	if threshold <= 0 || threshold > 1 {
		t.Errorf("Expected confidence threshold between 0 and 1, got %f", threshold)
	}
}

func TestHTTPAnalyzer_CanAnalyze(t *testing.T) {
	analyzer := analyzers.NewHTTPAnalyzer()

	tests := []struct {
		name     string
		packet   gopacket.Packet
		expected bool
	}{
		{
			name:     "HTTP packet on port 80",
			packet:   createHTTPPacket(80, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP packet on port 8080",
			packet:   createHTTPPacket(8080, "POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Non-HTTP packet",
			packet:   createTCPPacket(22, "SSH-2.0-OpenSSH_7.4"),
			expected: false,
		},
		{
			name:     "UDP packet",
			packet:   createUDPPacket(53, "DNS query"),
			expected: false,
		},
		{
			name:     "Empty TCP payload",
			packet:   createTCPPacket(80, ""),
			expected: true, // Analyzer checks port first, then payload
		},
		{
			name:     "Non-HTTP content on HTTP port",
			packet:   createTCPPacket(80, "BINARY_DATA_\x00\x01\x02"),
			expected: true, // Analyzer checks port first, then payload
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.CanAnalyze(tt.packet)
			if result != tt.expected {
				t.Errorf("Expected CanAnalyze() = %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestHTTPAnalyzer_Analyze(t *testing.T) {
	analyzer := analyzers.NewHTTPAnalyzer()

	tests := []struct {
		name            string
		packet          gopacket.Packet
		expectNil       bool
		expectedMethod  string
		expectedVersion string
		expectedURI     string
	}{
		{
			name:            "GET request",
			packet:          createHTTPPacket(80, "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
			expectNil:       false,
			expectedMethod:  "GET",
			expectedVersion: "HTTP/1.1",
			expectedURI:     "/index.html",
		},
		{
			name:            "POST request",
			packet:          createHTTPPacket(80, "POST /api/users HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"name\":\"test\"}"),
			expectNil:       false,
			expectedMethod:  "POST",
			expectedVersion: "HTTP/1.1",
			expectedURI:     "/api/users",
		},
		{
			name:            "HTTP response",
			packet:          createHTTPPacket(80, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>"),
			expectNil:       false,
			expectedMethod:  "",
			expectedVersion: "1.1", // Analyzer extracts version without "HTTP/" prefix
			expectedURI:     "",
		},
		{
			name:      "Invalid HTTP",
			packet:    createTCPPacket(80, "INVALID HTTP DATA"),
			expectNil: true,
		},
		{
			name:      "Non-TCP packet",
			packet:    createUDPPacket(80, "GET / HTTP/1.1"),
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.Analyze(tt.packet)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.Protocol != "HTTP" {
				t.Errorf("Expected protocol 'HTTP', got '%s'", result.Protocol)
			}

			if result.Confidence <= 0 {
				t.Errorf("Expected positive confidence, got %f", result.Confidence)
			}

			// Check details
			if result.Details == nil {
				t.Fatal("Expected non-nil details")
			}

			if tt.expectedMethod != "" {
				if method, ok := result.Details["method"]; !ok || method != tt.expectedMethod {
					t.Errorf("Expected method '%s', got '%v'", tt.expectedMethod, method)
				}
			}

			if tt.expectedVersion != "" {
				if version, ok := result.Details["version"]; !ok || version != tt.expectedVersion {
					t.Errorf("Expected version '%s', got '%v'", tt.expectedVersion, version)
				}
			}

			if tt.expectedURI != "" {
				if uri, ok := result.Details["uri"]; !ok || uri != tt.expectedURI {
					t.Errorf("Expected URI '%s', got '%v'", tt.expectedURI, uri)
				}
			}
		})
	}
}

// Internal method tests removed - testing through public interface only

// Internal method tests removed - testing through public interface only

// Helper functions for creating test packets

func createHTTPPacket(port uint16, payload string) gopacket.Packet {
	return createTCPPacket(port, payload)
}

func createTCPPacket(port uint16, payload string) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x00, 0x06, 0x07, 0x08, 0x09, 0x0a},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
	}

	// Set payload
	tcp.Payload = []byte(payload)

	// Serialize packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, gopacket.Payload(payload))

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createUDPPacket(port uint16, payload string) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x00, 0x06, 0x07, 0x08, 0x09, 0x0a},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(port),
	}

	// Serialize packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(buffer, opts, eth, ip, udp, gopacket.Payload(payload))

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Benchmark tests

func BenchmarkHTTPAnalyzer_CanAnalyze(b *testing.B) {
	analyzer := analyzers.NewHTTPAnalyzer()
	packet := createHTTPPacket(80, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.CanAnalyze(packet)
	}
}

func BenchmarkHTTPAnalyzer_Analyze(b *testing.B) {
	analyzer := analyzers.NewHTTPAnalyzer()
	packet := createHTTPPacket(80, "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(packet)
	}
}

// Internal method benchmarks removed - benchmarking through public interface only
