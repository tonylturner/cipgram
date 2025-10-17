package performance_test

import (
	"cipgram/pkg/pcap/performance"
	"cipgram/pkg/types"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewPerformanceOptimizer(t *testing.T) {
	tests := []struct {
		name   string
		config *performance.OptimizationConfig
		want   bool
	}{
		{
			name:   "Default config",
			config: nil,
			want:   true,
		},
		{
			name: "Custom config",
			config: &performance.OptimizationConfig{
				EnableMemoryPooling:   true,
				EnablePacketBatching:  true,
				EnableZeroCopy:        true,
				BatchSize:             500,
				MaxBufferSize:         32768,
				PoolPreallocation:     1000,
				GCOptimization:        true,
				MemoryProfileInterval: 10 * time.Second,
			},
			want: true,
		},
		{
			name: "Disabled optimizations",
			config: &performance.OptimizationConfig{
				EnableMemoryPooling:  false,
				EnablePacketBatching: false,
				EnableZeroCopy:       false,
				BatchSize:            100,
				MaxBufferSize:        1024,
				PoolPreallocation:    0,
				GCOptimization:       false,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optimizer := performance.NewPerformanceOptimizer(tt.config)
			if (optimizer != nil) != tt.want {
				t.Errorf("NewPerformanceOptimizer() = %v, want %v", optimizer != nil, tt.want)
			}

			// Can't test internal config directly since it's unexported
			// The fact that NewPerformanceOptimizer didn't panic is sufficient
		})
	}
}

func TestGetDefaultConfig(t *testing.T) {
	config := performance.GetDefaultConfig()

	if config == nil {
		t.Fatal("performance.GetDefaultConfig() returned nil")
	}

	// Verify default values
	if !config.EnableMemoryPooling {
		t.Error("Expected EnableMemoryPooling to be true by default")
	}

	if !config.EnablePacketBatching {
		t.Error("Expected EnablePacketBatching to be true by default")
	}

	if !config.EnableZeroCopy {
		t.Error("Expected EnableZeroCopy to be true by default")
	}

	if config.BatchSize <= 0 {
		t.Errorf("Expected positive BatchSize, got %d", config.BatchSize)
	}

	if config.MaxBufferSize <= 0 {
		t.Errorf("Expected positive MaxBufferSize, got %d", config.MaxBufferSize)
	}

	if config.PoolPreallocation <= 0 {
		t.Errorf("Expected positive PoolPreallocation, got %d", config.PoolPreallocation)
	}
}

func TestMemoryPooling(t *testing.T) {
	config := &performance.OptimizationConfig{
		EnableMemoryPooling: true,
		MaxBufferSize:       1024,
		PoolPreallocation:   10,
	}

	optimizer := performance.NewPerformanceOptimizer(config)

	t.Run("Buffer pooling", func(t *testing.T) {
		// Get buffer from pool
		buffer1 := optimizer.GetBuffer()
		if len(buffer1) != 0 {
			t.Errorf("Expected empty buffer, got length %d", len(buffer1))
		}
		if cap(buffer1) != config.MaxBufferSize {
			t.Errorf("Expected buffer capacity %d, got %d", config.MaxBufferSize, cap(buffer1))
		}

		// Return buffer to pool
		optimizer.PutBuffer(buffer1)

		// Get another buffer (should be reused)
		buffer2 := optimizer.GetBuffer()
		if cap(buffer2) != config.MaxBufferSize {
			t.Errorf("Expected buffer capacity %d, got %d", config.MaxBufferSize, cap(buffer2))
		}

		// Check stats
		stats := optimizer.GetStats()
		if stats.PoolHits < 1 {
			t.Errorf("Expected at least 1 pool hit, got %d", stats.PoolHits)
		}
	})

	t.Run("Asset pooling", func(t *testing.T) {
		// Get asset from pool
		asset1 := optimizer.GetAsset()
		if asset1 == nil {
			t.Fatal("GetAsset() returned nil")
		}

		// Modify asset
		asset1.ID = "test-asset"
		asset1.IP = "192.168.1.1"
		asset1.Protocols = append(asset1.Protocols, types.ProtoHTTP)

		// Return asset to pool
		optimizer.PutAsset(asset1)

		// Get another asset (should be reset)
		asset2 := optimizer.GetAsset()
		if asset2.ID != "" {
			t.Errorf("Expected empty ID after reset, got %s", asset2.ID)
		}
		if asset2.IP != "" {
			t.Errorf("Expected empty IP after reset, got %s", asset2.IP)
		}
		if len(asset2.Protocols) != 0 {
			t.Errorf("Expected empty protocols after reset, got %d", len(asset2.Protocols))
		}
	})

	t.Run("Flow pooling", func(t *testing.T) {
		// Get flow from pool
		flow1 := optimizer.GetFlow()
		if flow1 == nil {
			t.Fatal("GetFlow() returned nil")
		}

		// Modify flow
		flow1.Source = "src"
		flow1.Destination = "dst"
		flow1.Packets = 100

		// Return flow to pool
		optimizer.PutFlow(flow1)

		// Get another flow (should be reset)
		flow2 := optimizer.GetFlow()
		if flow2.Source != "" {
			t.Errorf("Expected empty source after reset, got %s", flow2.Source)
		}
		if flow2.Packets != 0 {
			t.Errorf("Expected zero packets after reset, got %d", flow2.Packets)
		}
	})
}

func TestZeroCopyBuffers(t *testing.T) {
	config := &performance.OptimizationConfig{
		EnableZeroCopy:    true,
		MaxBufferSize:     1024,
		PoolPreallocation: 5,
	}

	optimizer := performance.NewPerformanceOptimizer(config)

	// Get multiple zero-copy buffers
	buffers := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		buffers[i] = optimizer.GetZeroCopyBuffer()
		if len(buffers[i]) != 0 {
			t.Errorf("Expected empty buffer, got length %d", len(buffers[i]))
		}
		if cap(buffers[i]) != config.MaxBufferSize {
			t.Errorf("Expected buffer capacity %d, got %d", config.MaxBufferSize, cap(buffers[i]))
		}
	}

	// Check stats
	stats := optimizer.GetStats()
	if stats.ZeroCopyOperations != 10 {
		t.Errorf("Expected 10 zero-copy operations, got %d", stats.ZeroCopyOperations)
	}
}

func TestPacketBatching(t *testing.T) {
	config := &performance.OptimizationConfig{
		EnablePacketBatching: true,
		BatchSize:            3,
	}

	optimizer := performance.NewPerformanceOptimizer(config)

	// Create mock packets
	packets := createMockPackets(5)

	// Add packets to batch
	for i, packet := range packets {
		batchReady := optimizer.AddPacketToBatch(packet)
		if i < 2 {
			// First 3 packets shouldn't trigger batch processing
			if batchReady {
				t.Errorf("Batch should not be ready at packet %d", i)
			}
		} else if i == 2 {
			// Third packet should trigger batch processing
			if !batchReady {
				t.Errorf("Batch should be ready at packet %d", i)
			}
		}
	}

	// Get batch
	batch := optimizer.GetBatch()
	if batch == nil {
		t.Fatal("Expected non-nil batch")
	}

	// The batch should contain all packets added so far
	expectedSize := len(packets)
	if len(batch) != expectedSize {
		t.Errorf("Expected batch size %d, got %d", expectedSize, len(batch))
	}

	// Get batch again (should be empty since we already got all packets)
	batch2 := optimizer.GetBatch()
	if batch2 != nil && len(batch2) != 0 {
		t.Errorf("Expected empty batch after getting all packets, got %d", len(batch2))
	}
}

func TestPerformanceTracking(t *testing.T) {
	optimizer := performance.NewPerformanceOptimizer(performance.GetDefaultConfig())

	// Record some packet processing times
	processingTimes := []time.Duration{
		10 * time.Microsecond,
		20 * time.Microsecond,
		15 * time.Microsecond,
	}

	for _, duration := range processingTimes {
		optimizer.RecordPacketProcessed(duration)
	}

	// Check stats
	stats := optimizer.GetStats()
	if stats.PacketsProcessed != int64(len(processingTimes)) {
		t.Errorf("Expected %d packets processed, got %d", len(processingTimes), stats.PacketsProcessed)
	}

	expectedTotal := time.Duration(0)
	for _, d := range processingTimes {
		expectedTotal += d
	}

	if stats.ProcessingTime != expectedTotal {
		t.Errorf("Expected total processing time %v, got %v", expectedTotal, stats.ProcessingTime)
	}

	expectedAvg := expectedTotal / time.Duration(len(processingTimes))
	if stats.AveragePacketTime != expectedAvg {
		t.Errorf("Expected average packet time %v, got %v", expectedAvg, stats.AveragePacketTime)
	}
}

func TestGCOptimization(t *testing.T) {
	config := &performance.OptimizationConfig{
		GCOptimization: true,
	}

	optimizer := performance.NewPerformanceOptimizer(config)

	initialStats := optimizer.GetStats()
	initialGC := initialStats.GCCollections

	// Trigger GC optimization
	optimizer.OptimizeGC()

	finalStats := optimizer.GetStats()
	if finalStats.GCCollections != initialGC+1 {
		t.Errorf("Expected GC collections to increase by 1, got %d -> %d", initialGC, finalStats.GCCollections)
	}
}

func TestDisabledOptimizations(t *testing.T) {
	config := &performance.OptimizationConfig{
		EnableMemoryPooling:  false,
		EnablePacketBatching: false,
		EnableZeroCopy:       false,
		GCOptimization:       false,
	}

	optimizer := performance.NewPerformanceOptimizer(config)

	t.Run("Memory pooling disabled", func(t *testing.T) {
		buffer := optimizer.GetBuffer()
		if cap(buffer) != config.MaxBufferSize {
			t.Errorf("Expected buffer capacity %d, got %d", config.MaxBufferSize, cap(buffer))
		}

		// PutBuffer should be no-op
		optimizer.PutBuffer(buffer)

		// Stats should show no pool activity
		stats := optimizer.GetStats()
		if stats.PoolHits > 0 {
			t.Errorf("Expected no pool hits with pooling disabled, got %d", stats.PoolHits)
		}
	})

	t.Run("Packet batching disabled", func(t *testing.T) {
		packet := createMockPackets(1)[0]
		batchReady := optimizer.AddPacketToBatch(packet)
		if batchReady {
			t.Error("Batch should never be ready with batching disabled")
		}
	})

	t.Run("Zero-copy disabled", func(t *testing.T) {
		buffer := optimizer.GetZeroCopyBuffer()
		if cap(buffer) != config.MaxBufferSize {
			t.Errorf("Expected buffer capacity %d, got %d", config.MaxBufferSize, cap(buffer))
		}

		stats := optimizer.GetStats()
		if stats.ZeroCopyOperations > 0 {
			t.Errorf("Expected no zero-copy operations with zero-copy disabled, got %d", stats.ZeroCopyOperations)
		}
	})

	t.Run("GC optimization disabled", func(t *testing.T) {
		initialStats := optimizer.GetStats()
		initialGC := initialStats.GCCollections

		optimizer.OptimizeGC()

		finalStats := optimizer.GetStats()
		if finalStats.GCCollections != initialGC {
			t.Errorf("Expected no change in GC collections with optimization disabled, got %d -> %d", initialGC, finalStats.GCCollections)
		}
	})
}

func TestStatsReporting(t *testing.T) {
	optimizer := performance.NewPerformanceOptimizer(performance.GetDefaultConfig())

	// Perform some operations
	buffer := optimizer.GetBuffer()
	optimizer.PutBuffer(buffer)
	optimizer.RecordPacketProcessed(10 * time.Microsecond)
	optimizer.OptimizeGC()

	// Get stats
	stats := optimizer.GetStats()

	// Verify stats structure
	if stats.StartTime.IsZero() {
		t.Error("Expected non-zero start time")
	}

	if stats.LastUpdate.IsZero() {
		t.Error("Expected non-zero last update time")
	}

	if stats.PoolHits == 0 {
		t.Error("Expected some pool hits")
	}

	if stats.PacketsProcessed == 0 {
		t.Error("Expected some packets processed")
	}

	if stats.GCCollections == 0 {
		t.Error("Expected some GC collections")
	}

	// Test performance report (should not panic)
	optimizer.PrintPerformanceReport()
}

// Helper function to create mock packets for testing
func createMockPackets(count int) []gopacket.Packet {
	packets := make([]gopacket.Packet, count)

	for i := 0; i < count; i++ {
		// Create a simple Ethernet + IP + TCP packet
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
			DstPort: layers.TCPPort(80),
		}

		// Serialize the packet
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)

		// Create packet from serialized data
		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		packets[i] = packet
	}

	return packets
}

func BenchmarkMemoryPooling(b *testing.B) {
	optimizer := performance.NewPerformanceOptimizer(performance.GetDefaultConfig())

	b.Run("Asset pooling", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			asset := optimizer.GetAsset()
			optimizer.PutAsset(asset)
		}
	})

	b.Run("Flow pooling", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			flow := optimizer.GetFlow()
			optimizer.PutFlow(flow)
		}
	})

	b.Run("Buffer pooling", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buffer := optimizer.GetBuffer()
			optimizer.PutBuffer(buffer)
		}
	})
}

func BenchmarkZeroCopyBuffers(b *testing.B) {
	optimizer := performance.NewPerformanceOptimizer(performance.GetDefaultConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buffer := optimizer.GetZeroCopyBuffer()
		_ = buffer
	}
}

func BenchmarkPerformanceTracking(b *testing.B) {
	optimizer := performance.NewPerformanceOptimizer(performance.GetDefaultConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		optimizer.RecordPacketProcessed(10 * time.Microsecond)
	}
}
