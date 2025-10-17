package pcap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"cipgram/pkg/logging"
	"cipgram/pkg/pcap/integration"
	"cipgram/pkg/types"
	"cipgram/pkg/vendor"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PCAPParser implements InputSource for PCAP file analysis
type PCAPParser struct {
	pcapPath         string
	config           *PCAPConfig
	detectionAdapter *integration.ModularDetectionAdapter
}

// PCAPConfig holds configuration for PCAP parsing
type PCAPConfig struct {
	ShowHostnames      bool
	EnableVendorLookup bool
	EnableDNSLookup    bool
	FastMode           bool
	HideUnknown        bool
	MaxNodes           int
	ConfigPath         string // Optional Purdue config
}

// NewPCAPParser creates a new PCAP parser with enhanced capabilities
func NewPCAPParser(pcapPath string, config *PCAPConfig) *PCAPParser {
	if config == nil {
		config = &PCAPConfig{
			ShowHostnames:      true,
			EnableVendorLookup: true,  // Default: enable vendor lookup
			EnableDNSLookup:    false, // Default: disable DNS lookup (requires network)
			FastMode:           false,
			HideUnknown:        false,
			MaxNodes:           0,
		}
	}

	return &PCAPParser{
		pcapPath:         pcapPath,
		config:           config,
		detectionAdapter: integration.NewModularDetectionAdapter(config.ConfigPath),
	}
}

// Parse implements InputSource.Parse for PCAP files using sequential processing
func (p *PCAPParser) Parse() (*types.NetworkModel, error) {
	// Check file size for logging
	info, err := os.Stat(p.pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat PCAP file: %v", err)
	}

	logger := logging.NewLogger("pcap-parser", logging.INFO, false)
	logger.Info("Processing PCAP file using optimized sequential processing", map[string]interface{}{
		"file_path":    p.pcapPath,
		"file_size_mb": info.Size() / (1024 * 1024),
	})
	return p.parseSequential()
}

// parseSequential processes packets sequentially with optimized performance
func (p *PCAPParser) parseSequential() (*types.NetworkModel, error) {
	logger := logging.NewLogger("pcap-parser", logging.INFO, false)
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		logger.Info("PCAP processing completed", map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
			"duration":    duration.String(),
		})
	}()

	// Open PCAP file
	handle, err := pcap.OpenOffline(p.pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open PCAP file %s: %w", p.pcapPath, err)
	}
	defer handle.Close()

	model := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: []*types.SecurityPolicy{}, // Empty for PCAP-only
		Metadata: p.GetMetadata(),
	}

	// Parse packets and build model
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	for packet := range src.Packets() {
		packetCount++
		if packetCount%10000 == 0 {
			logger.Debug("Processing progress", map[string]interface{}{
				"packets_processed": packetCount,
			})
		}

		if err := p.processPacket(packet, model); err != nil {
			// Log error but continue processing - packet errors shouldn't stop analysis
			logger.Warn("Failed to process packet", map[string]interface{}{
				"packet_number": packetCount,
				"timestamp":     packet.Metadata().Timestamp,
				"error":         err.Error(),
			})
			continue
		}
	}

	processingTime := time.Since(start)
	packetsPerSecond := float64(packetCount) / processingTime.Seconds()
	logger.Info("Packet processing completed", map[string]interface{}{
		"total_packets":      packetCount,
		"processing_time":    processingTime.String(),
		"packets_per_second": int(packetsPerSecond),
	})

	// Post-processing: deduplicate, classify, enhance
	enhanceStart := time.Now()
	p.enhanceModel(model)
	logger.Info("Model enhancement completed", map[string]interface{}{
		"enhancement_time": time.Since(enhanceStart).String(),
		"total_assets":     len(model.Assets),
		"total_flows":      len(model.Flows),
	})

	// Infer network segments from traffic patterns
	p.inferNetworkSegments(model)

	// Protocol analysis is now handled by the detection adapter

	// Print enhanced detection statistics
	p.printEnhancedStatistics()

	// Print detection statistics
	stats := p.detectionAdapter.GetDetectionStats()
	log.Printf("Detection Statistics: %+v", stats)

	// Analyze unknown protocols and provide recommendations
	unknownFlows := make(map[string]int)
	for _, flow := range model.Flows {
		protocol := string(flow.Protocol)
		if strings.HasPrefix(protocol, "Unknown-") || strings.HasPrefix(protocol, "TCP (ports") || strings.HasPrefix(protocol, "UDP (ports") {
			unknownFlows[protocol] = int(flow.Packets)
		}
	}

	if len(unknownFlows) > 0 {
		log.Printf("Found %d unknown protocol flows", len(unknownFlows))
		for protocol, count := range unknownFlows {
			log.Printf("  %s: %d packets", protocol, count)
		}
	}

	return model, nil
}

// GetMetadata implements InputSource.GetMetadata
func (p *PCAPParser) GetMetadata() types.InputMetadata {
	info, _ := os.Stat(p.pcapPath)
	size := int64(0)
	modTime := time.Now()

	if info != nil {
		size = info.Size()
		modTime = info.ModTime()
	}

	return types.InputMetadata{
		Source:    p.pcapPath,
		Type:      types.InputTypePCAP,
		Timestamp: modTime,
		Size:      size,
		Hash:      calculateFileHash(p.pcapPath),
	}
}

// GetType implements InputSource.GetType
func (p *PCAPParser) GetType() types.InputType {
	return types.InputTypePCAP
}

// processPacket processes a single packet and updates the model
func (p *PCAPParser) processPacket(packet gopacket.Packet, model *types.NetworkModel) error {
	// Extract network layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	arpLayer := packet.Layer(layers.LayerTypeARP)
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	var srcIP, dstIP net.IP
	var eth *layers.Ethernet

	if ethLayer != nil {
		eth = ethLayer.(*layers.Ethernet)
	}

	// Handle ARP packets (Layer 2)
	if arpLayer != nil {
		return p.processARPPacket(packet, model, eth, arpLayer.(*layers.ARP))
	}

	// Handle IPv4/IPv6
	if ip4Layer != nil {
		ip := ip4Layer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	} else if ip6Layer != nil {
		ip := ip6Layer.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	} else {
		// Handle L2-only protocols like Profinet
		if eth != nil && eth.EthernetType == layers.EthernetType(0x8892) {
			return p.processL2Protocol(packet, model, eth)
		}
		return nil // Skip non-IP packets for now
	}

	// Create or update assets
	srcAsset := p.getOrCreateAsset(model, srcIP.String(), eth.SrcMAC.String())
	dstAsset := p.getOrCreateAsset(model, dstIP.String(), eth.DstMAC.String())

	// Detect protocol using optimized detection
	protocol := p.detectionAdapter.DetectProtocol(packet)
	flowKey := types.FlowKey{
		SrcIP: srcAsset.ID,
		DstIP: dstAsset.ID,
		Proto: types.Protocol(protocol),
	}

	// Update or create flow
	flow := model.Flows[flowKey]
	if flow == nil {
		flow = &types.Flow{
			Source:      srcAsset.ID,
			Destination: dstAsset.ID,
			Protocol:    types.Protocol(protocol),
			Ports:       []types.Port{},
			FirstSeen:   packet.Metadata().Timestamp,
			Allowed:     true, // Assume allowed for PCAP traffic
		}
		model.Flows[flowKey] = flow
	}

	// Update flow statistics
	flow.Packets++
	flow.Bytes += int64(len(packet.Data()))
	flow.LastSeen = packet.Metadata().Timestamp

	// Update asset protocol information
	p.updateAssetProtocols(srcAsset, dstAsset, protocol, tcpLayer, udpLayer, icmpLayer, icmp6Layer)

	return nil
}

// processL2Protocol handles Layer 2 protocols like Profinet
func (p *PCAPParser) processL2Protocol(packet gopacket.Packet, model *types.NetworkModel, eth *layers.Ethernet) error {
	// Create assets based on MAC addresses
	srcAsset := p.getOrCreateAsset(model, eth.SrcMAC.String(), eth.SrcMAC.String())
	dstAsset := p.getOrCreateAsset(model, eth.DstMAC.String(), eth.DstMAC.String())

	// Detect L2 protocol
	protocol := "Profinet-DCP" // Could be enhanced with payload analysis

	flowKey := types.FlowKey{
		SrcIP: srcAsset.ID,
		DstIP: dstAsset.ID,
		Proto: types.Protocol(protocol),
	}

	// Create flow
	if model.Flows[flowKey] == nil {
		model.Flows[flowKey] = &types.Flow{
			Source:      srcAsset.ID,
			Destination: dstAsset.ID,
			Protocol:    types.Protocol(protocol),
			FirstSeen:   packet.Metadata().Timestamp,
			Allowed:     true,
		}
	}

	// Update flow
	flow := model.Flows[flowKey]
	flow.Packets++
	flow.Bytes += int64(len(packet.Data()))
	flow.LastSeen = packet.Metadata().Timestamp

	// Update asset protocols
	srcAsset.Protocols = p.addProtocolIfNotExists(srcAsset.Protocols, types.Protocol(protocol))
	dstAsset.Protocols = p.addProtocolIfNotExists(dstAsset.Protocols, types.Protocol(protocol))

	return nil
}

// processARPPacket handles ARP packets
func (p *PCAPParser) processARPPacket(packet gopacket.Packet, model *types.NetworkModel, eth *layers.Ethernet, arp *layers.ARP) error {
	// Extract IP addresses from ARP packet
	var srcIP, dstIP string

	if arp.Operation == layers.ARPRequest || arp.Operation == layers.ARPReply {
		srcIP = net.IP(arp.SourceProtAddress).String()
		dstIP = net.IP(arp.DstProtAddress).String()

		// Create assets for ARP participants
		srcAsset := p.getOrCreateAsset(model, srcIP, net.HardwareAddr(arp.SourceHwAddress).String())
		dstAsset := p.getOrCreateAsset(model, dstIP, net.HardwareAddr(arp.DstHwAddress).String())

		// Create ARP flow
		flowKey := types.FlowKey{
			SrcIP: srcAsset.ID,
			DstIP: dstAsset.ID,
			Proto: types.Protocol("ARP"),
		}

		flow := model.Flows[flowKey]
		if flow == nil {
			flow = &types.Flow{
				Source:      srcAsset.ID,
				Destination: dstAsset.ID,
				Protocol:    types.Protocol("ARP"),
				FirstSeen:   packet.Metadata().Timestamp,
				Allowed:     true,
			}
			model.Flows[flowKey] = flow
		}

		// Update flow statistics
		flow.Packets++
		flow.Bytes += int64(len(packet.Data()))
		flow.LastSeen = packet.Metadata().Timestamp

		// Update asset protocols
		srcAsset.Protocols = p.addProtocolIfNotExists(srcAsset.Protocols, types.Protocol("ARP"))
		dstAsset.Protocols = p.addProtocolIfNotExists(dstAsset.Protocols, types.Protocol("ARP"))
	}

	return nil
}

// getOrCreateAsset retrieves or creates an asset
func (p *PCAPParser) getOrCreateAsset(model *types.NetworkModel, ip, mac string) *types.Asset {
	// Use IP as primary key, but handle MAC-only cases
	id := ip
	if ip == mac { // MAC-only case
		id = "MAC-" + mac
	}

	asset := model.Assets[id]
	if asset == nil {
		// Get vendor information from MAC address if enabled
		var vendorName string
		if p.config.EnableVendorLookup && mac != "" && len(mac) >= 8 {
			vendorName = vendor.LookupOUI(mac)
		}

		// Get hostname if DNS lookup is enabled
		var hostname string
		if p.config.EnableDNSLookup && ip != "" && ip != mac {
			hostname = vendor.ResolveHostname(ip)
		}

		asset = &types.Asset{
			ID:           id,
			IP:           ip,
			MAC:          mac,
			Hostname:     hostname,
			Vendor:       vendorName,
			Protocols:    []types.Protocol{},
			PurdueLevel:  types.Unknown,
			IEC62443Zone: "", // Will be inferred later
			Criticality:  types.LowAsset,
			Exposure:     types.OTOnly,
		}
		model.Assets[id] = asset
	}

	return asset
}

// detectProtocol detects protocols from packet layers
func (p *PCAPParser) detectProtocol(tcpLayer, udpLayer, icmpLayer, icmp6Layer gopacket.Layer, eth *layers.Ethernet) string {
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return p.detectTCPProtocol(uint16(tcp.SrcPort), uint16(tcp.DstPort))
	}

	if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return p.detectUDPProtocol(uint16(udp.SrcPort), uint16(udp.DstPort))
	}

	if icmpLayer != nil {
		return "ICMP"
	}

	if icmp6Layer != nil {
		return "ICMPv6"
	}

	if eth != nil {
		return p.detectL2Protocol(eth.EthernetType)
	}

	return "Unknown"
}

// detectTCPProtocol maps TCP ports to protocols
func (p *PCAPParser) detectTCPProtocol(srcPort, dstPort uint16) string {
	protocolMap := map[uint16]string{
		// Industrial protocols (primary focus)
		44818: "EtherNet/IP",
		502:   "Modbus TCP",
		102:   "S7Comm",
		4840:  "OPC-UA",
		20000: "DNP3",
		9600:  "FINS",
		5007:  "SLMP",
		135:   "OPC Classic",
		8834:  "SINEC",
		1025:  "Melsec Q",
		20547: "Omron TCP",

		// Standard IT protocols
		80:    "HTTP",
		443:   "HTTPS",
		22:    "SSH",
		23:    "Telnet",
		21:    "FTP",
		25:    "SMTP",
		110:   "POP3",
		143:   "IMAP",
		993:   "IMAPS",
		995:   "POP3S",
		389:   "LDAP",
		636:   "LDAPS",
		3389:  "RDP",
		5900:  "VNC",
		1433:  "SQL Server",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	if proto, exists := protocolMap[srcPort]; exists {
		return proto
	}
	if proto, exists := protocolMap[dstPort]; exists {
		return proto
	}

	return "TCP"
}

// detectUDPProtocol maps UDP ports to protocols
func (p *PCAPParser) detectUDPProtocol(srcPort, dstPort uint16) string {
	protocolMap := map[uint16]string{
		// Industrial protocols
		2222:  "EtherNet/IP I/O",
		47808: "BACnet/IP",
		18246: "CC-Link",

		// Standard IT protocols
		53:   "DNS",
		67:   "DHCP Server",
		68:   "DHCP Client",
		69:   "TFTP",
		123:  "NTP",
		161:  "SNMP",
		162:  "SNMP Trap",
		514:  "Syslog",
		1812: "RADIUS Auth",
		1813: "RADIUS Acct",
		5353: "mDNS",
	}

	if proto, exists := protocolMap[srcPort]; exists {
		return proto
	}
	if proto, exists := protocolMap[dstPort]; exists {
		return proto
	}

	return "UDP"
}

// detectL2Protocol detects Layer 2 protocols
func (p *PCAPParser) detectL2Protocol(etherType layers.EthernetType) string {
	switch etherType {
	case layers.EthernetType(0x8892):
		return "Profinet"
	default:
		return "Ethernet"
	}
}

// updateAssetProtocols updates asset protocol information
func (p *PCAPParser) updateAssetProtocols(srcAsset, dstAsset *types.Asset, protocol string, tcpLayer, udpLayer, icmpLayer, icmp6Layer gopacket.Layer) {
	proto := types.Protocol(protocol)

	srcAsset.Protocols = p.addProtocolIfNotExists(srcAsset.Protocols, proto)
	dstAsset.Protocols = p.addProtocolIfNotExists(dstAsset.Protocols, proto)

	// Update ports for classification
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		// Could track ports for classification purposes
		_ = tcp
	}
	if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		// Could track ports for classification purposes
		_ = udp
	}
	if icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		// Could track ICMP types for classification
		_ = icmp
	}
	if icmp6Layer != nil {
		icmp6 := icmp6Layer.(*layers.ICMPv6)
		// Could track ICMPv6 types for classification
		_ = icmp6
	}
}

// addProtocolIfNotExists adds protocol to list if not already present
func (p *PCAPParser) addProtocolIfNotExists(protocols []types.Protocol, proto types.Protocol) []types.Protocol {
	for _, existing := range protocols {
		if existing == proto {
			return protocols
		}
	}
	return append(protocols, proto)
}

// enhanceModel performs post-processing enhancement
func (p *PCAPParser) enhanceModel(model *types.NetworkModel) error {
	// Perform device fingerprinting first
	p.performDeviceFingerprinting(model)

	// Classify assets using enhanced logic
	for _, asset := range model.Assets {
		asset.PurdueLevel = p.classifyAssetPurdueLevel(asset, model)
		asset.IEC62443Zone = p.classifyAssetZone(asset, model)
		asset.Criticality = p.assessAssetCriticality(asset, model)
		asset.Exposure = p.assessAssetExposure(asset, model)

		// Set device name based on protocols and patterns
		asset.DeviceName = p.inferDeviceName(asset)
	}

	return nil
}

// performDeviceFingerprinting performs basic device classification
func (p *PCAPParser) performDeviceFingerprinting(model *types.NetworkModel) {
	logger := logging.NewLogger("device-classifier", logging.INFO, false)

	for _, asset := range model.Assets {
		// Basic device classification based on protocols
		asset.DeviceName = p.classifyDeviceType(asset)

		// Update roles based on device type
		if asset.DeviceName == "PLC" {
			asset.Roles = append(asset.Roles, "Controller")
		} else if asset.DeviceName == "HMI" {
			asset.Roles = append(asset.Roles, "Operator Interface")
		} else if asset.DeviceName == "Network Infrastructure" {
			asset.Roles = append(asset.Roles, "Network Device")
		} else if asset.DeviceName == "Workstation" {
			asset.Roles = append(asset.Roles, "Engineering Station")
		}
	}

	logger.Info("Device classification completed", map[string]interface{}{
		"total_assets": len(model.Assets),
	})
}

// classifyDeviceType performs basic device type classification based on protocols
func (p *PCAPParser) classifyDeviceType(asset *types.Asset) string {
	// Check for industrial protocols
	for _, protocol := range asset.Protocols {
		protocolStr := string(protocol)
		switch {
		case strings.Contains(protocolStr, "Modbus"):
			return "PLC"
		case strings.Contains(protocolStr, "EtherNet/IP"):
			return "PLC"
		case strings.Contains(protocolStr, "S7Comm"):
			return "PLC"
		case strings.Contains(protocolStr, "DNP3"):
			return "RTU"
		case strings.Contains(protocolStr, "BACnet"):
			return "Building Controller"
		case strings.Contains(protocolStr, "OPC"):
			return "HMI"
		case strings.Contains(protocolStr, "HTTP") && strings.Contains(protocolStr, "HTTPS"):
			return "HMI"
		case strings.Contains(protocolStr, "RDP") || strings.Contains(protocolStr, "VNC"):
			return "Workstation"
		case strings.Contains(protocolStr, "SSH") || strings.Contains(protocolStr, "Telnet"):
			return "Network Infrastructure"
		}
	}

	// Default classification
	return "Unknown"
}

// printEnhancedStatistics prints enhanced protocol detection statistics
func (p *PCAPParser) printEnhancedStatistics() {
	log.Printf("\n=== Enhanced Protocol Detection Statistics ===")

	// Print performance statistics from the detection adapter
	stats := p.detectionAdapter.GetDetectionStats()
	log.Printf("Detection Performance:")
	if totalPackets, ok := stats["total_packets"].(int64); ok {
		log.Printf("  Total Packets: %d", totalPackets)
	}
	if successRate, ok := stats["success_rate"].(float32); ok {
		log.Printf("  Success Rate: %.2f%%", successRate*100)
	}

	if methodBreakdown, ok := stats["method_breakdown"].(map[string]int64); ok {
		log.Printf("Detection Methods:")
		for method, count := range methodBreakdown {
			log.Printf("  %s: %d", method, count)
		}
	}
}

// inferNetworkSegments creates network segments from traffic patterns
func (p *PCAPParser) inferNetworkSegments(model *types.NetworkModel) {
	// Group assets by network patterns (simplified)
	networks := make(map[string][]*types.Asset)

	for _, asset := range model.Assets {
		if asset.IP != "" && asset.IP != asset.MAC {
			// Group by /24 network (simplified)
			ip := net.ParseIP(asset.IP)
			if ip != nil && ip.To4() != nil {
				network := fmt.Sprintf("%d.%d.%d.0/24", ip[12], ip[13], ip[14])
				networks[network] = append(networks[network], asset)
			}
		}
	}

	// Create network segments
	for cidr, assets := range networks {
		if len(assets) < 2 { // Skip single-asset networks
			continue
		}

		segment := &types.NetworkSegment{
			ID:       fmt.Sprintf("network_%s", strings.ReplaceAll(cidr, "/", "_")),
			CIDR:     cidr,
			Name:     fmt.Sprintf("Inferred Network %s", cidr),
			Assets:   assets,
			Policies: []*types.SecurityPolicy{},
			Zone:     p.inferNetworkZone(assets),
			Risk:     p.assessNetworkRisk(assets),
			Purpose:  p.inferNetworkPurpose(assets),
		}

		model.Networks[segment.ID] = segment
	}
}

// Classification helper functions (simplified versions)
func (p *PCAPParser) classifyAssetPurdueLevel(asset *types.Asset, model *types.NetworkModel) types.PurdueLevel {
	// Simplified classification based on protocols and communication patterns
	for _, proto := range asset.Protocols {
		switch proto {
		case "EtherNet/IP I/O", "Profinet":
			return types.L1 // Field devices
		case "EtherNet/IP", "Modbus TCP", "S7Comm":
			// Check if more client or server behavior
			return types.L2 // Supervisory control
		case "OPC-UA":
			return types.L2 // Could be L2 or L3
		}
	}
	return types.Unknown
}

func (p *PCAPParser) classifyAssetZone(asset *types.Asset, model *types.NetworkModel) types.IEC62443Zone {
	switch asset.PurdueLevel {
	case types.L1:
		return types.IndustrialZone
	case types.L2:
		return types.IndustrialZone
	case types.L3:
		return types.EnterpriseZone
	default:
		return types.EnterpriseZone
	}
}

func (p *PCAPParser) assessAssetCriticality(asset *types.Asset, model *types.NetworkModel) types.CriticalityLevel {
	// Simple heuristic based on protocols and level
	if asset.PurdueLevel == types.L1 {
		return types.HighAsset // Field devices are critical
	}
	return types.MediumAsset
}

func (p *PCAPParser) assessAssetExposure(asset *types.Asset, model *types.NetworkModel) types.ExposureLevel {
	// For PCAP analysis, assume OT-only unless proven otherwise
	return types.OTOnly
}

func (p *PCAPParser) inferDeviceName(asset *types.Asset) string {
	if len(asset.Protocols) == 0 {
		return "Unknown Device"
	}

	// Generate name based on primary protocol
	primaryProto := asset.Protocols[0]
	switch primaryProto {
	case "EtherNet/IP":
		return "Allen-Bradley Device"
	case "S7Comm":
		return "Siemens Device"
	case "Modbus TCP":
		return "Modbus Device"
	case "Profinet":
		return "Profinet Device"
	default:
		return fmt.Sprintf("%s Device", primaryProto)
	}
}

func (p *PCAPParser) inferNetworkZone(assets []*types.Asset) types.IEC62443Zone {
	// Majority vote from assets
	zoneCount := make(map[types.IEC62443Zone]int)
	for _, asset := range assets {
		zoneCount[asset.IEC62443Zone]++
	}

	maxCount := 0
	var dominantZone types.IEC62443Zone
	for zone, count := range zoneCount {
		if count > maxCount {
			maxCount = count
			dominantZone = zone
		}
	}

	return dominantZone
}

func (p *PCAPParser) assessNetworkRisk(assets []*types.Asset) types.RiskLevel {
	highRiskCount := 0
	for _, asset := range assets {
		if asset.Criticality == types.HighAsset || asset.Criticality == types.CriticalAsset {
			highRiskCount++
		}
	}

	if highRiskCount > len(assets)/2 {
		return types.HighRisk
	} else if highRiskCount > 0 {
		return types.MediumRisk
	}

	return types.LowRisk
}

func (p *PCAPParser) inferNetworkPurpose(assets []*types.Asset) string {
	// Analyze asset types to infer purpose
	deviceTypes := make(map[string]int)
	for _, asset := range assets {
		for _, proto := range asset.Protocols {
			deviceTypes[string(proto)]++
		}
	}

	// Determine dominant purpose
	if deviceTypes["EtherNet/IP"] > 0 || deviceTypes["Modbus TCP"] > 0 {
		return "Industrial Control"
	} else if deviceTypes["OPC-UA"] > 0 {
		return "SCADA/HMI"
	}

	return "General Purpose"
}

// calculateFileHash computes SHA256 hash of a file for integrity checking
func calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Warning: Failed to calculate file hash for %s: %v", filePath, err)
		return ""
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		log.Printf("Warning: Failed to calculate file hash for %s: %v", filePath, err)
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
