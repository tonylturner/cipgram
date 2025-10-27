package performance

import (
	"cipgram/pkg/logging"
	"cipgram/pkg/pcap/profiling"
	"cipgram/pkg/types"
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// PerformanceOptimizer implements advanced performance optimizations
type PerformanceOptimizer struct {
	// Memory pools
	packetPool sync.Pool
	bufferPool sync.Pool
	assetPool  sync.Pool
	flowPool   sync.Pool

	// Batch processing
	batchSize   int
	packetBatch []gopacket.Packet
	batchMutex  sync.Mutex

	// Performance metrics
	stats      *PerformanceStats
	statsMutex sync.RWMutex

	// Configuration
	config *OptimizationConfig
	logger *logging.Logger

	// Zero-copy buffers
	reusableBuffers [][]byte
	bufferIndex     int
	bufferMutex     sync.Mutex

	// Memory profiling
	memoryProfiler  *profiling.MemoryProfiler
	profilingCtx    context.Context
	profilingCancel context.CancelFunc
}

// OptimizationConfig contains performance optimization settings
type OptimizationConfig struct {
	EnableMemoryPooling   bool
	EnablePacketBatching  bool
	EnableZeroCopy        bool
	BatchSize             int
	MaxBufferSize         int
	PoolPreallocation     int
	GCOptimization        bool
	MemoryProfileInterval time.Duration

	// Memory profiling
	EnableMemoryProfiling bool                      `json:"enable_memory_profiling"`
	ProfilerConfig        *profiling.ProfilerConfig `json:"profiler_config,omitempty"`
}

// PerformanceStats tracks performance metrics
type PerformanceStats struct {
	// Memory statistics
	TotalAllocations int64
	PoolHits         int64
	PoolMisses       int64
	MemoryReused     int64
	GCCollections    int64

	// Processing statistics
	PacketsProcessed  int64
	BatchesProcessed  int64
	ProcessingTime    time.Duration
	AveragePacketTime time.Duration

	// Buffer statistics
	BuffersAllocated   int64
	BuffersReused      int64
	ZeroCopyOperations int64

	// Timestamps
	StartTime  time.Time
	LastUpdate time.Time
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config *OptimizationConfig) *PerformanceOptimizer {
	if config == nil {
		config = GetDefaultConfig()
	}

	optimizer := &PerformanceOptimizer{
		batchSize:       config.BatchSize,
		packetBatch:     make([]gopacket.Packet, 0, config.BatchSize),
		config:          config,
		logger:          logging.NewLogger("performance-optimizer", logging.INFO, false),
		reusableBuffers: make([][]byte, config.PoolPreallocation),
		stats: &PerformanceStats{
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
		},
	}

	optimizer.initializePools()
	optimizer.initializeBuffers()

	// Initialize memory profiling if enabled
	if config.EnableMemoryProfiling {
		optimizer.initializeMemoryProfiling()
	}

	if config.MemoryProfileInterval > 0 {
		go optimizer.startMemoryProfiler()
	}

	return optimizer
}

// GetDefaultConfig returns default optimization configuration
func GetDefaultConfig() *OptimizationConfig {
	return &OptimizationConfig{
		EnableMemoryPooling:   true,
		EnablePacketBatching:  true,
		EnableZeroCopy:        true,
		BatchSize:             1000,
		MaxBufferSize:         65536,
		PoolPreallocation:     10000,
		GCOptimization:        true,
		MemoryProfileInterval: 30 * time.Second,
		EnableMemoryProfiling: false, // Disabled by default
		ProfilerConfig:        profiling.GetDefaultProfilerConfig(),
	}
}

// initializePools initializes memory pools
func (po *PerformanceOptimizer) initializePools() {
	// Packet pool for reusing packet structures
	po.packetPool = sync.Pool{
		New: func() interface{} {
			po.statsMutex.Lock()
			po.stats.TotalAllocations++
			po.statsMutex.Unlock()
			return make([]byte, po.config.MaxBufferSize)
		},
	}

	// Buffer pool for general purpose buffers
	po.bufferPool = sync.Pool{
		New: func() interface{} {
			po.statsMutex.Lock()
			po.stats.TotalAllocations++
			po.statsMutex.Unlock()
			return make([]byte, 0, 1024)
		},
	}

	// Asset pool for reusing asset structures
	po.assetPool = sync.Pool{
		New: func() interface{} {
			po.statsMutex.Lock()
			po.stats.TotalAllocations++
			po.statsMutex.Unlock()
			return &types.Asset{
				Protocols:             make([]types.Protocol, 0, 10),
				Roles:                 make([]string, 0, 5),
				FingerprintingDetails: make(map[string]interface{}),
			}
		},
	}

	// Flow pool for reusing flow structures
	po.flowPool = sync.Pool{
		New: func() interface{} {
			po.statsMutex.Lock()
			po.stats.TotalAllocations++
			po.statsMutex.Unlock()
			return &types.Flow{
				Ports: make([]types.Port, 0, 5),
			}
		},
	}

	// Pre-allocate pool objects if configured
	if po.config.PoolPreallocation > 0 {
		po.preallocatePoolObjects()
	}
}

// initializeBuffers initializes zero-copy buffers
func (po *PerformanceOptimizer) initializeBuffers() {
	if !po.config.EnableZeroCopy {
		return
	}

	for i := range po.reusableBuffers {
		po.reusableBuffers[i] = make([]byte, po.config.MaxBufferSize)
	}

	po.logger.Info("Zero-copy buffers initialized", map[string]interface{}{
		"buffer_count": len(po.reusableBuffers),
		"buffer_size":  po.config.MaxBufferSize,
	})
}

// initializeMemoryProfiling initializes memory profiling
func (po *PerformanceOptimizer) initializeMemoryProfiling() {
	if po.config.ProfilerConfig == nil {
		po.config.ProfilerConfig = profiling.GetDefaultProfilerConfig()
	}

	po.memoryProfiler = profiling.NewMemoryProfiler(po.config.ProfilerConfig)
	po.profilingCtx, po.profilingCancel = context.WithCancel(context.Background())

	// Start the profiler
	if err := po.memoryProfiler.Start(po.profilingCtx); err != nil {
		po.logger.Error("Failed to start memory profiler", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	po.logger.Info("Memory profiling initialized", map[string]interface{}{
		"http_enabled":     po.config.ProfilerConfig.EnableHTTPServer,
		"http_addr":        po.config.ProfilerConfig.HTTPAddr,
		"monitor_interval": po.config.ProfilerConfig.MonitorInterval,
	})
}

// preallocatePoolObjects pre-allocates objects in pools
func (po *PerformanceOptimizer) preallocatePoolObjects() {
	// Pre-allocate packet buffers
	for i := 0; i < po.config.PoolPreallocation/4; i++ {
		po.packetPool.Put(make([]byte, po.config.MaxBufferSize))
	}

	// Pre-allocate general buffers
	for i := 0; i < po.config.PoolPreallocation/4; i++ {
		po.bufferPool.Put(make([]byte, 0, 1024))
	}

	// Pre-allocate assets
	for i := 0; i < po.config.PoolPreallocation/4; i++ {
		asset := &types.Asset{
			Protocols:             make([]types.Protocol, 0, 10),
			Roles:                 make([]string, 0, 5),
			FingerprintingDetails: make(map[string]interface{}),
		}
		po.assetPool.Put(asset)
	}

	// Pre-allocate flows
	for i := 0; i < po.config.PoolPreallocation/4; i++ {
		flow := &types.Flow{
			Ports: make([]types.Port, 0, 5),
		}
		po.flowPool.Put(flow)
	}

	po.logger.Info("Memory pools pre-allocated", map[string]interface{}{
		"preallocation_count": po.config.PoolPreallocation,
	})
}

// GetBuffer retrieves a buffer from the pool
func (po *PerformanceOptimizer) GetBuffer() []byte {
	if !po.config.EnableMemoryPooling {
		return make([]byte, po.config.MaxBufferSize)
	}

	buffer := po.packetPool.Get().([]byte)

	po.statsMutex.Lock()
	po.stats.PoolHits++
	po.stats.MemoryReused++
	po.statsMutex.Unlock()

	return buffer[:0] // Reset length but keep capacity
}

// PutBuffer returns a buffer to the pool
func (po *PerformanceOptimizer) PutBuffer(buffer []byte) {
	if !po.config.EnableMemoryPooling {
		return
	}

	// Reset buffer but keep capacity
	buffer = buffer[:cap(buffer)]
	po.packetPool.Put(buffer)
}

// GetZeroCopyBuffer gets a zero-copy buffer
func (po *PerformanceOptimizer) GetZeroCopyBuffer() []byte {
	if !po.config.EnableZeroCopy {
		return make([]byte, po.config.MaxBufferSize)
	}

	po.bufferMutex.Lock()
	defer po.bufferMutex.Unlock()

	buffer := po.reusableBuffers[po.bufferIndex]
	po.bufferIndex = (po.bufferIndex + 1) % len(po.reusableBuffers)

	po.statsMutex.Lock()
	po.stats.ZeroCopyOperations++
	po.stats.BuffersReused++
	po.statsMutex.Unlock()

	return buffer[:0] // Reset length but keep capacity
}

// GetAsset retrieves an asset from the pool
func (po *PerformanceOptimizer) GetAsset() *types.Asset {
	if !po.config.EnableMemoryPooling {
		return &types.Asset{
			Protocols:             make([]types.Protocol, 0, 10),
			Roles:                 make([]string, 0, 5),
			FingerprintingDetails: make(map[string]interface{}),
		}
	}

	asset := po.assetPool.Get().(*types.Asset)

	// Reset asset fields
	asset.ID = ""
	asset.IP = ""
	asset.MAC = ""
	asset.Hostname = ""
	asset.DeviceName = ""
	asset.Vendor = ""
	asset.OS = ""
	asset.Model = ""
	asset.Version = ""
	asset.PurdueLevel = types.Unknown
	asset.IEC62443Zone = ""
	asset.Protocols = asset.Protocols[:0]
	asset.Roles = asset.Roles[:0]
	asset.Criticality = types.LowAsset
	asset.Exposure = types.OTOnly

	// Clear fingerprinting details map
	for k := range asset.FingerprintingDetails {
		delete(asset.FingerprintingDetails, k)
	}

	po.statsMutex.Lock()
	po.stats.PoolHits++
	po.stats.MemoryReused++
	po.statsMutex.Unlock()

	return asset
}

// PutAsset returns an asset to the pool
func (po *PerformanceOptimizer) PutAsset(asset *types.Asset) {
	if !po.config.EnableMemoryPooling {
		return
	}

	po.assetPool.Put(asset)
}

// GetFlow retrieves a flow from the pool
func (po *PerformanceOptimizer) GetFlow() *types.Flow {
	if !po.config.EnableMemoryPooling {
		return &types.Flow{
			Ports: make([]types.Port, 0, 5),
		}
	}

	flow := po.flowPool.Get().(*types.Flow)

	// Reset flow fields
	flow.Source = ""
	flow.Destination = ""
	flow.Protocol = ""
	flow.Ports = flow.Ports[:0]
	flow.Packets = 0
	flow.Bytes = 0
	flow.FirstSeen = time.Time{}
	flow.Allowed = true

	po.statsMutex.Lock()
	po.stats.PoolHits++
	po.stats.MemoryReused++
	po.statsMutex.Unlock()

	return flow
}

// PutFlow returns a flow to the pool
func (po *PerformanceOptimizer) PutFlow(flow *types.Flow) {
	if !po.config.EnableMemoryPooling {
		return
	}

	po.flowPool.Put(flow)
}

// AddPacketToBatch adds a packet to the processing batch
func (po *PerformanceOptimizer) AddPacketToBatch(packet gopacket.Packet) bool {
	if !po.config.EnablePacketBatching {
		return false // Indicate immediate processing needed
	}

	po.batchMutex.Lock()
	defer po.batchMutex.Unlock()

	po.packetBatch = append(po.packetBatch, packet)

	// Return true if batch is full and ready for processing
	return len(po.packetBatch) >= po.batchSize
}

// GetBatch retrieves the current packet batch for processing
func (po *PerformanceOptimizer) GetBatch() []gopacket.Packet {
	po.batchMutex.Lock()
	defer po.batchMutex.Unlock()

	if len(po.packetBatch) == 0 {
		return nil
	}

	// Return current batch and create new one
	batch := po.packetBatch
	po.packetBatch = make([]gopacket.Packet, 0, po.batchSize)

	po.statsMutex.Lock()
	po.stats.BatchesProcessed++
	po.statsMutex.Unlock()

	return batch
}

// FlushBatch forces processing of the current batch
func (po *PerformanceOptimizer) FlushBatch() []gopacket.Packet {
	return po.GetBatch()
}

// RecordPacketProcessed records that a packet was processed
func (po *PerformanceOptimizer) RecordPacketProcessed(processingTime time.Duration) {
	po.statsMutex.Lock()
	defer po.statsMutex.Unlock()

	po.stats.PacketsProcessed++
	po.stats.ProcessingTime += processingTime

	if po.stats.PacketsProcessed > 0 {
		po.stats.AveragePacketTime = po.stats.ProcessingTime / time.Duration(po.stats.PacketsProcessed)
	}

	po.stats.LastUpdate = time.Now()
}

// OptimizeGC performs garbage collection optimization
func (po *PerformanceOptimizer) OptimizeGC() {
	if !po.config.GCOptimization {
		return
	}

	// Force garbage collection at strategic points
	runtime.GC()

	po.statsMutex.Lock()
	po.stats.GCCollections++
	po.statsMutex.Unlock()

	po.logger.Debug("Garbage collection optimized", map[string]interface{}{
		"gc_collections": po.stats.GCCollections,
	})
}

// GetStats returns current performance statistics
func (po *PerformanceOptimizer) GetStats() *PerformanceStats {
	po.statsMutex.RLock()
	defer po.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	statsCopy := *po.stats
	return &statsCopy
}

// PrintPerformanceReport prints a detailed performance report
func (po *PerformanceOptimizer) PrintPerformanceReport() {
	stats := po.GetStats()

	po.logger.Info("Performance Optimization Report", map[string]interface{}{
		"total_runtime":      time.Since(stats.StartTime).String(),
		"packets_processed":  stats.PacketsProcessed,
		"batches_processed":  stats.BatchesProcessed,
		"avg_packet_time":    stats.AveragePacketTime.String(),
		"pool_hits":          stats.PoolHits,
		"pool_misses":        stats.PoolMisses,
		"memory_reused":      stats.MemoryReused,
		"zero_copy_ops":      stats.ZeroCopyOperations,
		"gc_collections":     stats.GCCollections,
		"packets_per_second": float64(stats.PacketsProcessed) / time.Since(stats.StartTime).Seconds(),
	})

	// Print memory profiling report if enabled
	if po.memoryProfiler != nil {
		po.memoryProfiler.PrintMemoryReport()
	}
}

// startMemoryProfiler starts the memory profiler goroutine
func (po *PerformanceOptimizer) startMemoryProfiler() {
	ticker := time.NewTicker(po.config.MemoryProfileInterval)
	defer ticker.Stop()

	for range ticker.C {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		po.logger.Debug("Memory Profile", map[string]interface{}{
			"alloc_mb":       memStats.Alloc / 1024 / 1024,
			"total_alloc_mb": memStats.TotalAlloc / 1024 / 1024,
			"sys_mb":         memStats.Sys / 1024 / 1024,
			"num_gc":         memStats.NumGC,
			"gc_pause_ns":    memStats.PauseNs[(memStats.NumGC+255)%256],
			"heap_objects":   memStats.HeapObjects,
		})

		// Trigger GC optimization if memory usage is high
		if memStats.Alloc > 512*1024*1024 { // 512MB threshold
			po.OptimizeGC()
		}
	}
}

// GetMemoryStats returns memory profiling statistics
func (po *PerformanceOptimizer) GetMemoryStats() *profiling.MemoryStats {
	if po.memoryProfiler == nil {
		return nil
	}

	stats := po.memoryProfiler.GetStats()
	return &stats
}

// TakeHeapProfile takes a heap profile and saves it to file
func (po *PerformanceOptimizer) TakeHeapProfile(filename string) error {
	if po.memoryProfiler == nil {
		return fmt.Errorf("memory profiler not enabled")
	}

	return po.memoryProfiler.TakeHeapProfile(filename)
}

// TakeCPUProfile takes a CPU profile for the specified duration
func (po *PerformanceOptimizer) TakeCPUProfile(filename string, duration time.Duration) error {
	if po.memoryProfiler == nil {
		return fmt.Errorf("memory profiler not enabled")
	}

	return po.memoryProfiler.TakeCPUProfile(filename, duration)
}

// EnableMemoryProfiling enables memory profiling at runtime
func (po *PerformanceOptimizer) EnableMemoryProfiling() error {
	if po.memoryProfiler != nil {
		return fmt.Errorf("memory profiler already enabled")
	}

	po.config.EnableMemoryProfiling = true
	po.initializeMemoryProfiling()
	return nil
}

// DisableMemoryProfiling disables memory profiling
func (po *PerformanceOptimizer) DisableMemoryProfiling() error {
	if po.memoryProfiler == nil {
		return fmt.Errorf("memory profiler not enabled")
	}

	if err := po.memoryProfiler.Stop(); err != nil {
		return fmt.Errorf("failed to stop memory profiler: %w", err)
	}

	if po.profilingCancel != nil {
		po.profilingCancel()
	}

	po.memoryProfiler = nil
	po.config.EnableMemoryProfiling = false

	po.logger.Info("Memory profiling disabled", nil)
	return nil
}

// Cleanup performs cleanup operations
func (po *PerformanceOptimizer) Cleanup() {
	po.logger.Info("Performance optimizer cleanup", map[string]interface{}{
		"final_stats": po.GetStats(),
	})

	// Final GC optimization
	po.OptimizeGC()
}
