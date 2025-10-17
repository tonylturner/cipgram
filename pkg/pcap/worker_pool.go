package pcap

import (
	"context"
	"log"
	"runtime"
	"sync"
	"time"

	"cipgram/pkg/types"

	"github.com/google/gopacket"
)

// WorkerPool manages concurrent packet processing
type WorkerPool struct {
	numWorkers int
	packetChan chan gopacket.Packet
	resultChan chan *PacketResult
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	model      *types.NetworkModel
	parser     *PCAPParser
	mu         sync.Mutex // Protects model updates
	processed  int64
	errors     int64
}

// PacketResult represents the result of processing a packet
type PacketResult struct {
	Assets map[string]*types.Asset
	Flows  map[types.FlowKey]*types.Flow
	Error  error
}

// NewWorkerPool creates a new worker pool for packet processing
func NewWorkerPool(parser *PCAPParser, numWorkers int) *WorkerPool {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		numWorkers: numWorkers,
		packetChan: make(chan gopacket.Packet, numWorkers*10), // Buffer for better throughput
		resultChan: make(chan *PacketResult, numWorkers*10),
		ctx:        ctx,
		cancel:     cancel,
		parser:     parser,
		model: &types.NetworkModel{
			Assets:   make(map[string]*types.Asset),
			Networks: make(map[string]*types.NetworkSegment),
			Flows:    make(map[types.FlowKey]*types.Flow),
			Policies: []*types.SecurityPolicy{},
		},
	}
}

// Start initializes and starts the worker pool
func (wp *WorkerPool) Start() {
	log.Printf("🚀 Starting worker pool with %d workers for parallel processing", wp.numWorkers)

	// Start packet processing workers
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.packetWorker(i)
	}

	// Start result aggregator
	wp.wg.Add(1)
	go wp.resultAggregator()
}

// ProcessPacket sends a packet to the worker pool for processing
func (wp *WorkerPool) ProcessPacket(packet gopacket.Packet) {
	select {
	case wp.packetChan <- packet:
		// Packet queued successfully
	case <-wp.ctx.Done():
		// Processing cancelled
		return
	}
}

// Wait waits for all workers to complete and returns the aggregated model
func (wp *WorkerPool) Wait() *types.NetworkModel {
	close(wp.packetChan) // Signal no more packets
	wp.wg.Wait()         // Wait for all workers to complete
	wp.cancel()          // Cancel context

	log.Printf("✅ Parallel processing complete: %d packets processed, %d errors",
		wp.processed, wp.errors)

	return wp.model
}

// packetWorker processes packets from the packet channel
func (wp *WorkerPool) packetWorker(workerID int) {
	defer wp.wg.Done()

	processed := 0
	for packet := range wp.packetChan {
		select {
		case <-wp.ctx.Done():
			return
		default:
		}

		result := wp.processPacketLocal(packet)

		select {
		case wp.resultChan <- result:
			processed++
			if processed%1000 == 0 {
				log.Printf("Worker %d: processed %d packets", workerID, processed)
			}
		case <-wp.ctx.Done():
			return
		}
	}

	log.Printf("Worker %d completed: %d packets processed", workerID, processed)
}

// processPacketLocal processes a single packet and returns local results
func (wp *WorkerPool) processPacketLocal(packet gopacket.Packet) *PacketResult {
	// Create local model for this packet to avoid locking during processing
	localModel := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: []*types.SecurityPolicy{},
	}

	// Process the packet (this is the same logic as the original processPacket)
	if err := wp.parser.processPacket(packet, localModel); err != nil {
		return &PacketResult{
			Assets: make(map[string]*types.Asset),
			Flows:  make(map[types.FlowKey]*types.Flow),
			Error:  err,
		}
	}

	return &PacketResult{
		Assets: localModel.Assets,
		Flows:  localModel.Flows,
		Error:  nil,
	}
}

// resultAggregator collects results from workers and merges them into the main model
func (wp *WorkerPool) resultAggregator() {
	defer wp.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result, ok := <-wp.resultChan:
			if !ok {
				log.Printf("📊 Result aggregation complete")
				return
			}

			if result.Error != nil {
				wp.mu.Lock()
				wp.errors++
				wp.mu.Unlock()
				continue
			}

			wp.mergeResult(result)
			wp.mu.Lock()
			wp.processed++
			wp.mu.Unlock()

		case <-ticker.C:
			// Periodic progress update
			wp.mu.Lock()
			processed := wp.processed
			errors := wp.errors
			wp.mu.Unlock()

			if processed > 0 {
				log.Printf("📊 Progress: %d packets processed, %d errors", processed, errors)
			}

		case <-wp.ctx.Done():
			return
		}
	}
}

// mergeResult safely merges worker results into the main model
func (wp *WorkerPool) mergeResult(result *PacketResult) {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	// Merge assets
	for id, asset := range result.Assets {
		if existing, exists := wp.model.Assets[id]; exists {
			// Merge asset data (combine protocols, roles, etc.)
			wp.mergeAssets(existing, asset)
		} else {
			wp.model.Assets[id] = asset
		}
	}

	// Merge flows
	for key, flow := range result.Flows {
		if existing, exists := wp.model.Flows[key]; exists {
			// Aggregate flow statistics
			existing.Packets += flow.Packets
			existing.Bytes += flow.Bytes

			// Update time range
			if flow.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = flow.FirstSeen
			}
			if flow.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = flow.LastSeen
			}
		} else {
			wp.model.Flows[key] = flow
		}
	}
}

// mergeAssets merges two asset objects
func (wp *WorkerPool) mergeAssets(existing, new *types.Asset) {
	// Merge protocols (avoid duplicates)
	protocolSet := make(map[types.Protocol]bool)
	for _, proto := range existing.Protocols {
		protocolSet[proto] = true
	}
	for _, proto := range new.Protocols {
		if !protocolSet[proto] {
			existing.Protocols = append(existing.Protocols, proto)
			protocolSet[proto] = true
		}
	}

	// Merge roles (avoid duplicates)
	roleSet := make(map[string]bool)
	for _, role := range existing.Roles {
		roleSet[role] = true
	}
	for _, role := range new.Roles {
		if !roleSet[role] {
			existing.Roles = append(existing.Roles, role)
			roleSet[role] = true
		}
	}

	// Update fields if they're empty in existing but present in new
	if existing.Hostname == "" && new.Hostname != "" {
		existing.Hostname = new.Hostname
	}
	if existing.DeviceName == "" && new.DeviceName != "" {
		existing.DeviceName = new.DeviceName
	}
	if existing.Vendor == "" && new.Vendor != "" {
		existing.Vendor = new.Vendor
	}

	// Use higher Purdue level (more specific is better)
	if new.PurdueLevel != types.Unknown && existing.PurdueLevel == types.Unknown {
		existing.PurdueLevel = new.PurdueLevel
	}
}

// Close shuts down the worker pool gracefully
func (wp *WorkerPool) Close() {
	wp.cancel()
	close(wp.resultChan)
}
