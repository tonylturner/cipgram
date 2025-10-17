package pcap

import (
	"testing"
	"time"

	"cipgram/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestWorkerPoolCreation(t *testing.T) {
	parser := &PCAPParser{
		pcapPath: "test.pcap",
		config:   &PCAPConfig{},
	}

	wp := NewWorkerPool(parser, 4)

	if wp.numWorkers != 4 {
		t.Errorf("Expected 4 workers, got %d", wp.numWorkers)
	}

	if wp.parser != parser {
		t.Error("Parser not set correctly")
	}

	wp.Close()
}

func TestWorkerPoolAutoWorkerCount(t *testing.T) {
	parser := &PCAPParser{
		pcapPath: "test.pcap",
		config:   &PCAPConfig{},
	}

	wp := NewWorkerPool(parser, 0) // Should use runtime.NumCPU()

	if wp.numWorkers <= 0 {
		t.Errorf("Expected positive number of workers, got %d", wp.numWorkers)
	}

	wp.Close()
}

func TestPacketResultMerging(t *testing.T) {
	parser := &PCAPParser{
		pcapPath: "test.pcap",
		config:   &PCAPConfig{},
	}

	wp := NewWorkerPool(parser, 2)

	// Create test assets
	asset1 := &types.Asset{
		ID:        "192.168.1.10",
		IP:        "192.168.1.10",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Protocols: []types.Protocol{types.ProtoModbus},
		Roles:     []string{"PLC"},
	}

	asset2 := &types.Asset{
		ID:        "192.168.1.10", // Same IP, should merge
		IP:        "192.168.1.10",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Protocols: []types.Protocol{types.ProtoENIP_Explicit},
		Roles:     []string{"Controller"},
		Hostname:  "plc-001",
	}

	// Create test results
	result1 := &PacketResult{
		Assets: map[string]*types.Asset{"192.168.1.10": asset1},
		Flows:  make(map[types.FlowKey]*types.Flow),
	}

	result2 := &PacketResult{
		Assets: map[string]*types.Asset{"192.168.1.10": asset2},
		Flows:  make(map[types.FlowKey]*types.Flow),
	}

	// Merge results
	wp.mergeResult(result1)
	wp.mergeResult(result2)

	// Check merged result
	merged := wp.model.Assets["192.168.1.10"]
	if merged == nil {
		t.Fatal("Asset not found after merge")
	}

	// Check protocols are merged
	if len(merged.Protocols) != 2 {
		t.Errorf("Expected 2 protocols after merge, got %d", len(merged.Protocols))
	}

	// Check roles are merged
	if len(merged.Roles) != 2 {
		t.Errorf("Expected 2 roles after merge, got %d", len(merged.Roles))
	}

	// Check hostname is preserved
	if merged.Hostname != "plc-001" {
		t.Errorf("Expected hostname 'plc-001', got '%s'", merged.Hostname)
	}

	wp.Close()
}

func TestFlowAggregation(t *testing.T) {
	parser := &PCAPParser{
		pcapPath: "test.pcap",
		config:   &PCAPConfig{},
	}

	wp := NewWorkerPool(parser, 2)

	flowKey := types.FlowKey{
		SrcIP: "192.168.1.10",
		DstIP: "192.168.1.20",
		Proto: types.ProtoModbus,
	}

	now := time.Now()

	// Create overlapping flows
	flow1 := &types.Flow{
		Source:      "192.168.1.10",
		Destination: "192.168.1.20",
		Protocol:    types.ProtoModbus,
		Packets:     100,
		Bytes:       5000,
		FirstSeen:   now,
		LastSeen:    now.Add(time.Minute),
	}

	flow2 := &types.Flow{
		Source:      "192.168.1.10",
		Destination: "192.168.1.20",
		Protocol:    types.ProtoModbus,
		Packets:     50,
		Bytes:       2500,
		FirstSeen:   now.Add(30 * time.Second),
		LastSeen:    now.Add(2 * time.Minute),
	}

	result1 := &PacketResult{
		Assets: make(map[string]*types.Asset),
		Flows:  map[types.FlowKey]*types.Flow{flowKey: flow1},
	}

	result2 := &PacketResult{
		Assets: make(map[string]*types.Asset),
		Flows:  map[types.FlowKey]*types.Flow{flowKey: flow2},
	}

	// Merge flows
	wp.mergeResult(result1)
	wp.mergeResult(result2)

	// Check aggregated flow
	aggregated := wp.model.Flows[flowKey]
	if aggregated == nil {
		t.Fatal("Flow not found after merge")
	}

	// Check packet and byte aggregation
	if aggregated.Packets != 150 {
		t.Errorf("Expected 150 packets, got %d", aggregated.Packets)
	}

	if aggregated.Bytes != 7500 {
		t.Errorf("Expected 7500 bytes, got %d", aggregated.Bytes)
	}

	// Check time range expansion
	if !aggregated.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen not preserved correctly")
	}

	if !aggregated.LastSeen.Equal(now.Add(2 * time.Minute)) {
		t.Errorf("LastSeen not extended correctly")
	}

	wp.Close()
}

func TestAssetMerging(t *testing.T) {
	parser := &PCAPParser{
		pcapPath: "test.pcap",
		config:   &PCAPConfig{},
	}

	wp := NewWorkerPool(parser, 1)

	existing := &types.Asset{
		ID:        "192.168.1.10",
		IP:        "192.168.1.10",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Protocols: []types.Protocol{types.ProtoModbus},
		Roles:     []string{"PLC"},
		Hostname:  "",
		Vendor:    "",
	}

	new := &types.Asset{
		ID:        "192.168.1.10",
		IP:        "192.168.1.10",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Protocols: []types.Protocol{types.ProtoENIP_Explicit, types.ProtoModbus}, // Duplicate Modbus
		Roles:     []string{"Controller", "PLC"},                                 // Duplicate PLC
		Hostname:  "plc-001",
		Vendor:    "Allen-Bradley",
	}

	wp.mergeAssets(existing, new)

	// Check protocol deduplication
	protocolCount := make(map[types.Protocol]int)
	for _, proto := range existing.Protocols {
		protocolCount[proto]++
	}

	if protocolCount[types.ProtoModbus] != 1 {
		t.Error("Modbus protocol was duplicated")
	}

	if len(existing.Protocols) != 2 {
		t.Errorf("Expected 2 unique protocols, got %d", len(existing.Protocols))
	}

	// Check role deduplication
	roleCount := make(map[string]int)
	for _, role := range existing.Roles {
		roleCount[role]++
	}

	if roleCount["PLC"] != 1 {
		t.Error("PLC role was duplicated")
	}

	if len(existing.Roles) != 2 {
		t.Errorf("Expected 2 unique roles, got %d", len(existing.Roles))
	}

	// Check field updates
	if existing.Hostname != "plc-001" {
		t.Errorf("Expected hostname 'plc-001', got '%s'", existing.Hostname)
	}

	if existing.Vendor != "Allen-Bradley" {
		t.Errorf("Expected vendor 'Allen-Bradley', got '%s'", existing.Vendor)
	}

	wp.Close()
}

// Mock packet for testing
func createMockPacket() gopacket.Packet {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{192, 168, 1, 20},
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: 502, // Modbus port
		DstPort: 12345,
	}

	gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Benchmark worker pool performance
func BenchmarkWorkerPool(b *testing.B) {
	parser := &PCAPParser{
		pcapPath: "test.pcap",
		config:   &PCAPConfig{},
	}

	packet := createMockPacket()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		wp := NewWorkerPool(parser, 4)
		wp.Start()

		for j := 0; j < 1000; j++ {
			wp.ProcessPacket(packet)
		}

		wp.Wait()
		wp.Close()
	}
}
