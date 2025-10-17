package pcap

import (
	"fmt"
	"testing"
	"time"

	"cipgram/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BenchmarkPCAPProcessing benchmarks PCAP processing with different packet counts
func BenchmarkPCAPProcessing(b *testing.B) {
	testCases := []struct {
		name        string
		packetCount int
	}{
		{"Small_100_packets", 100},
		{"Medium_1000_packets", 1000},
		{"Large_10000_packets", 10000},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			packets := createTestPackets(tc.packetCount)
			parser := &PCAPParser{
				pcapPath: "benchmark.pcap",
				config:   &PCAPConfig{EnableVendorLookup: false}, // Disable for pure processing speed
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				model := &types.NetworkModel{
					Assets:   make(map[string]*types.Asset),
					Networks: make(map[string]*types.NetworkSegment),
					Flows:    make(map[types.FlowKey]*types.Flow),
					Policies: []*types.SecurityPolicy{},
				}

				for _, packet := range packets {
					parser.processPacket(packet, model)
				}
			}
		})
	}
}

// BenchmarkPacketProcessing benchmarks individual packet processing
func BenchmarkPacketProcessing(b *testing.B) {
	parser := &PCAPParser{
		pcapPath: "benchmark.pcap",
		config:   &PCAPConfig{EnableVendorLookup: false},
	}

	model := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: []*types.SecurityPolicy{},
	}

	packet := createTestPackets(1)[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.processPacket(packet, model)
	}
}

// BenchmarkVendorLookup benchmarks vendor lookup performance
func BenchmarkVendorLookup(b *testing.B) {
	testCases := []struct {
		name         string
		enableVendor bool
		enableDNS    bool
	}{
		{"NoLookups", false, false},
		{"VendorOnly", true, false},
		{"DNSOnly", false, true},
		{"BothLookups", true, true},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			parser := &PCAPParser{
				pcapPath: "benchmark.pcap",
				config: &PCAPConfig{
					EnableVendorLookup: tc.enableVendor,
					EnableDNSLookup:    tc.enableDNS,
				},
			}

			model := &types.NetworkModel{
				Assets:   make(map[string]*types.Asset),
				Networks: make(map[string]*types.NetworkSegment),
				Flows:    make(map[types.FlowKey]*types.Flow),
				Policies: []*types.SecurityPolicy{},
			}

			packets := createDiverseTestPackets(100) // Different MAC addresses

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, packet := range packets {
					parser.processPacket(packet, model)
				}
			}
		})
	}
}

// BenchmarkModelEnhancement benchmarks post-processing enhancement
func BenchmarkModelEnhancement(b *testing.B) {
	parser := &PCAPParser{
		pcapPath: "benchmark.pcap",
		config:   &PCAPConfig{},
	}

	// Create a model with realistic data
	model := createRealisticModel(1000) // 1000 assets

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a copy for each iteration
		modelCopy := copyModel(model)
		parser.enhanceModel(modelCopy)
	}
}

// BenchmarkNetworkSegmentation benchmarks network segment inference
func BenchmarkNetworkSegmentation(b *testing.B) {
	parser := &PCAPParser{
		pcapPath: "benchmark.pcap",
		config:   &PCAPConfig{},
	}

	model := createRealisticModel(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		modelCopy := copyModel(model)
		parser.inferNetworkSegments(modelCopy)
	}
}

// Helper functions for benchmarking

func createTestPackets(count int) []gopacket.Packet {
	packets := make([]gopacket.Packet, count)

	for i := 0; i < count; i++ {
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{}

		eth := &layers.Ethernet{
			SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i % 256)},
			DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, byte((i + 1) % 256)},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			SrcIP:    []byte{192, 168, 1, byte(i%254 + 1)},
			DstIP:    []byte{192, 168, 1, byte((i+1)%254 + 1)},
			Protocol: layers.IPProtocolTCP,
		}

		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(502 + (i % 100)), // Vary ports
			DstPort: layers.TCPPort(12345),
		}

		gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
		packets[i] = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	}

	return packets
}

func createDiverseTestPackets(count int) []gopacket.Packet {
	packets := make([]gopacket.Packet, count)

	// Known vendor MAC prefixes for realistic testing
	vendorPrefixes := [][]byte{
		{0x00, 0x0c, 0x29}, // VMware
		{0x00, 0x50, 0x56}, // VMware
		{0x08, 0x00, 0x27}, // VirtualBox
		{0x00, 0x1c, 0x7f}, // Perle Systems
		{0x00, 0x80, 0xa3}, // Lantronix
	}

	for i := 0; i < count; i++ {
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{}

		// Use different vendor prefixes
		vendorPrefix := vendorPrefixes[i%len(vendorPrefixes)]
		srcMAC := append(vendorPrefix, byte(i%256), byte((i+1)%256), byte((i+2)%256))

		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, byte((i + 1) % 256)},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			SrcIP:    []byte{192, 168, byte((i / 254) + 1), byte(i%254 + 1)},
			DstIP:    []byte{192, 168, byte(((i + 1) / 254) + 1), byte((i+1)%254 + 1)},
			Protocol: layers.IPProtocolTCP,
		}

		// Vary protocols for realistic testing
		var port layers.TCPPort
		switch i % 4 {
		case 0:
			port = 502 // Modbus
		case 1:
			port = 44818 // EtherNet/IP
		case 2:
			port = 4840 // OPC-UA
		default:
			port = 80 // HTTP
		}

		tcp := &layers.TCP{
			SrcPort: port,
			DstPort: layers.TCPPort(12345),
		}

		gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
		packets[i] = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	}

	return packets
}

func createRealisticModel(assetCount int) *types.NetworkModel {
	model := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: []*types.SecurityPolicy{},
	}

	// Create realistic assets
	for i := 0; i < assetCount; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", (i/254)+1, (i%254)+1)
		asset := &types.Asset{
			ID:           ip,
			IP:           ip,
			MAC:          fmt.Sprintf("00:0c:29:%02x:%02x:%02x", i%256, (i+1)%256, (i+2)%256),
			Protocols:    []types.Protocol{types.ProtoModbus, types.ProtoENIP_Explicit},
			PurdueLevel:  types.L2,
			IEC62443Zone: types.IndustrialZone,
			Criticality:  types.MediumAsset,
			Exposure:     types.OTOnly,
		}
		model.Assets[ip] = asset

		// Create some flows
		if i > 0 {
			srcIP := fmt.Sprintf("192.168.%d.%d", ((i-1)/254)+1, ((i-1)%254)+1)
			flowKey := types.FlowKey{
				SrcIP: srcIP,
				DstIP: ip,
				Proto: types.ProtoModbus,
			}
			flow := &types.Flow{
				Source:      srcIP,
				Destination: ip,
				Protocol:    types.ProtoModbus,
				Packets:     int64(100 + i),
				Bytes:       int64(6400 + i*64),
				FirstSeen:   time.Now().Add(-time.Hour),
				LastSeen:    time.Now(),
				Allowed:     true,
			}
			model.Flows[flowKey] = flow
		}
	}

	return model
}

func copyModel(original *types.NetworkModel) *types.NetworkModel {
	modelCopy := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: make([]*types.SecurityPolicy, len(original.Policies)),
		Metadata: original.Metadata,
	}

	// Deep copy assets
	for id, asset := range original.Assets {
		assetCopy := *asset
		assetCopy.Protocols = make([]types.Protocol, len(asset.Protocols))
		for i, proto := range asset.Protocols {
			assetCopy.Protocols[i] = proto
		}
		assetCopy.Roles = make([]string, len(asset.Roles))
		for i, role := range asset.Roles {
			assetCopy.Roles[i] = role
		}
		modelCopy.Assets[id] = &assetCopy
	}

	// Deep copy flows
	for key, flow := range original.Flows {
		flowCopy := *flow
		modelCopy.Flows[key] = &flowCopy
	}

	// Copy policies
	for i, policy := range original.Policies {
		modelCopy.Policies[i] = policy
	}

	return modelCopy
}
