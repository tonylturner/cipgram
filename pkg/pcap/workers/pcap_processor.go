// Package workers provides PCAP-specific packet processing for worker queues
package workers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cipgram/pkg/pcap/integration"
	"cipgram/pkg/pcap/optimization"
	"cipgram/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PCAPPacketProcessor implements PacketProcessor for PCAP analysis
type PCAPPacketProcessor struct {
	// Detection and optimization
	detectionAdapter *integration.ModularDetectionAdapter
	stringOptimizer  *optimization.StringOptimizer

	// Shared model (thread-safe access required)
	model      *types.NetworkModel
	modelMutex sync.RWMutex

	// Configuration
	config *PCAPProcessorConfig

	// Statistics
	stats      ProcessorStats
	statsMutex sync.RWMutex
}

// PCAPProcessorConfig holds configuration for PCAP processing
type PCAPProcessorConfig struct {
	EnableVendorLookup bool `json:"enable_vendor_lookup"`
	EnableDNSLookup    bool `json:"enable_dns_lookup"`
	MaxRetries         int  `json:"max_retries"`
}

// ProcessorStats tracks processing statistics
type ProcessorStats struct {
	PacketsProcessed int64         `json:"packets_processed"`
	AssetsCreated    int64         `json:"assets_created"`
	FlowsCreated     int64         `json:"flows_created"`
	Errors           int64         `json:"errors"`
	AvgProcessTime   time.Duration `json:"avg_process_time"`
	StartTime        time.Time     `json:"start_time"`
}

// PacketProcessingResult contains the result of processing a packet
type PacketProcessingResult struct {
	AssetUpdates []AssetUpdate `json:"asset_updates"`
	FlowUpdates  []FlowUpdate  `json:"flow_updates"`
	Protocol     string        `json:"protocol"`
	Errors       []string      `json:"errors,omitempty"`
}

// AssetUpdate represents an asset creation or update
type AssetUpdate struct {
	ID        string           `json:"id"`
	IP        string           `json:"ip"`
	MAC       string           `json:"mac"`
	Vendor    string           `json:"vendor,omitempty"`
	Hostname  string           `json:"hostname,omitempty"`
	Protocols []types.Protocol `json:"protocols"`
	IsNew     bool             `json:"is_new"`
}

// FlowUpdate represents a flow creation or update
type FlowUpdate struct {
	Key       types.FlowKey `json:"key"`
	Protocol  string        `json:"protocol"`
	Packets   int64         `json:"packets"`
	Bytes     int64         `json:"bytes"`
	FirstSeen time.Time     `json:"first_seen"`
	LastSeen  time.Time     `json:"last_seen"`
	IsNew     bool          `json:"is_new"`
}

// NewPCAPPacketProcessor creates a new PCAP packet processor
func NewPCAPPacketProcessor(model *types.NetworkModel, configPath string) *PCAPPacketProcessor {
	config := &PCAPProcessorConfig{
		EnableVendorLookup: true,
		EnableDNSLookup:    false,
		MaxRetries:         3,
	}

	return &PCAPPacketProcessor{
		detectionAdapter: integration.NewModularDetectionAdapter(configPath),
		stringOptimizer:  optimization.NewStringOptimizer(),
		model:            model,
		config:           config,
		stats: ProcessorStats{
			StartTime: time.Now(),
		},
	}
}

// ProcessPacket implements PacketProcessor.ProcessPacket
func (p *PCAPPacketProcessor) ProcessPacket(ctx context.Context, job *PacketJob) (*JobResult, error) {
	start := time.Now()

	// Update statistics
	p.statsMutex.Lock()
	p.stats.PacketsProcessed++
	p.statsMutex.Unlock()

	// Process the packet
	result, err := p.processPacketInternal(ctx, job.Packet)

	duration := time.Since(start)

	// Update average processing time
	p.statsMutex.Lock()
	if p.stats.PacketsProcessed == 1 {
		p.stats.AvgProcessTime = duration
	} else {
		// Exponential moving average
		alpha := 0.1
		p.stats.AvgProcessTime = time.Duration(
			float64(p.stats.AvgProcessTime)*(1-alpha) +
				float64(duration)*alpha,
		)
	}

	if err != nil {
		p.stats.Errors++
	}
	p.statsMutex.Unlock()

	return &JobResult{
		JobID:       job.ID,
		Success:     err == nil,
		Error:       err,
		Data:        result,
		Duration:    duration,
		ProcessedAt: time.Now(),
	}, nil
}

// processPacketInternal performs the actual packet processing
func (p *PCAPPacketProcessor) processPacketInternal(ctx context.Context, packet gopacket.Packet) (*PacketProcessingResult, error) {
	result := &PacketProcessingResult{
		AssetUpdates: []AssetUpdate{},
		FlowUpdates:  []FlowUpdate{},
		Errors:       []string{},
	}

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Extract network information
	var srcIP, dstIP, srcMAC, dstMAC string

	// Handle Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
		dstMAC = eth.DstMAC.String()
	}

	// Handle IP layers
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	}

	// Handle ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		srcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
		dstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])
		srcMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp.SourceHwAddress[0], arp.SourceHwAddress[1], arp.SourceHwAddress[2], arp.SourceHwAddress[3], arp.SourceHwAddress[4], arp.SourceHwAddress[5])
		dstMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp.DstHwAddress[0], arp.DstHwAddress[1], arp.DstHwAddress[2], arp.DstHwAddress[3], arp.DstHwAddress[4], arp.DstHwAddress[5])
	}

	// Fallback to MAC addresses if no IP
	if srcIP == "" && srcMAC != "" {
		srcIP = srcMAC
	}
	if dstIP == "" && dstMAC != "" {
		dstIP = dstMAC
	}

	if srcIP == "" || dstIP == "" {
		result.Errors = append(result.Errors, "Could not extract source or destination addresses")
		return result, nil
	}

	// Detect protocol
	protocol := p.detectionAdapter.DetectProtocol(packet)
	result.Protocol = protocol

	// Intern the protocol string for efficiency
	internedProtocol := p.stringOptimizer.InternString(protocol)

	// Process assets
	srcAssetUpdate, err := p.processAsset(srcIP, srcMAC)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Error processing source asset: %v", err))
	} else {
		result.AssetUpdates = append(result.AssetUpdates, srcAssetUpdate)
	}

	dstAssetUpdate, err := p.processAsset(dstIP, dstMAC)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Error processing destination asset: %v", err))
	} else {
		result.AssetUpdates = append(result.AssetUpdates, dstAssetUpdate)
	}

	// Process flow
	flowUpdate, err := p.processFlow(srcAssetUpdate.ID, dstAssetUpdate.ID, internedProtocol, packet)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Error processing flow: %v", err))
	} else {
		result.FlowUpdates = append(result.FlowUpdates, flowUpdate)
	}

	return result, nil
}

// processAsset processes an asset (creates or updates)
func (p *PCAPPacketProcessor) processAsset(ip, mac string) (AssetUpdate, error) {
	// Generate optimized asset ID
	var id string
	if ip == mac {
		id = p.stringOptimizer.BuildString("MAC-", mac)
	} else {
		id = p.stringOptimizer.InternString(ip)
	}

	p.modelMutex.Lock()
	defer p.modelMutex.Unlock()

	asset := p.model.Assets[id]
	isNew := asset == nil

	if isNew {
		asset = &types.Asset{
			ID:        id,
			IP:        ip,
			MAC:       mac,
			Protocols: []types.Protocol{},
		}

		// TODO: Add vendor lookup if enabled
		// TODO: Add DNS lookup if enabled

		p.model.Assets[id] = asset

		p.statsMutex.Lock()
		p.stats.AssetsCreated++
		p.statsMutex.Unlock()
	}

	return AssetUpdate{
		ID:        id,
		IP:        ip,
		MAC:       mac,
		Vendor:    asset.Vendor,
		Hostname:  asset.Hostname,
		Protocols: asset.Protocols,
		IsNew:     isNew,
	}, nil
}

// processFlow processes a flow (creates or updates)
func (p *PCAPPacketProcessor) processFlow(srcID, dstID, protocol string, packet gopacket.Packet) (FlowUpdate, error) {
	flowKey := types.FlowKey{
		SrcIP: srcID,
		DstIP: dstID,
		Proto: types.Protocol(protocol),
	}

	p.modelMutex.Lock()
	defer p.modelMutex.Unlock()

	flow := p.model.Flows[flowKey]
	isNew := flow == nil
	now := time.Now()

	if isNew {
		flow = &types.Flow{
			Source:      srcID,
			Destination: dstID,
			Protocol:    types.Protocol(protocol),
			Packets:     1,
			Bytes:       int64(len(packet.Data())),
			FirstSeen:   now,
			LastSeen:    now,
		}

		p.model.Flows[flowKey] = flow

		p.statsMutex.Lock()
		p.stats.FlowsCreated++
		p.statsMutex.Unlock()
	} else {
		flow.Packets++
		flow.Bytes += int64(len(packet.Data()))
		flow.LastSeen = now
	}

	return FlowUpdate{
		Key:       flowKey,
		Protocol:  protocol,
		Packets:   flow.Packets,
		Bytes:     flow.Bytes,
		FirstSeen: flow.FirstSeen,
		LastSeen:  flow.LastSeen,
		IsNew:     isNew,
	}, nil
}

// GetStats returns processor statistics
func (p *PCAPPacketProcessor) GetStats() ProcessorStats {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()
	return p.stats
}

// GetStringOptimizerStats returns string optimizer statistics
func (p *PCAPPacketProcessor) GetStringOptimizerStats() optimization.StringOptimizerStats {
	return p.stringOptimizer.GetStats()
}

// GetDetectionStats returns detection statistics
func (p *PCAPPacketProcessor) GetDetectionStats() map[string]interface{} {
	return p.detectionAdapter.GetDetectionStats()
}
