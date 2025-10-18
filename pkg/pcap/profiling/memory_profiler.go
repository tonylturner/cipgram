// Package profiling provides memory profiling and optimization capabilities
package profiling

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Import pprof for HTTP endpoints
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	"cipgram/pkg/logging"
)

// MemoryProfiler provides comprehensive memory profiling and monitoring
type MemoryProfiler struct {
	// Configuration
	config *ProfilerConfig
	logger *logging.Logger

	// Profiling state
	running bool
	mutex   sync.RWMutex

	// Memory tracking
	allocTracker *AllocationTracker

	// Monitoring
	monitorTicker *time.Ticker
	stopChan      chan struct{}

	// Statistics
	stats      *MemoryStats
	statsMutex sync.RWMutex
}

// ProfilerConfig holds memory profiler configuration
type ProfilerConfig struct {
	// HTTP profiling server
	EnableHTTPServer bool   `json:"enable_http_server"`
	HTTPAddr         string `json:"http_addr"`

	// File-based profiling
	EnableFileProfiles bool   `json:"enable_file_profiles"`
	ProfileDir         string `json:"profile_dir"`

	// Memory monitoring
	MonitorInterval          time.Duration `json:"monitor_interval"`
	EnableAllocationTracking bool          `json:"enable_allocation_tracking"`

	// Optimization triggers
	GCThreshold          int64 `json:"gc_threshold_mb"`
	MemoryAlertThreshold int64 `json:"memory_alert_threshold_mb"`

	// Sampling
	MemProfileRate       int `json:"mem_profile_rate"`
	BlockProfileRate     int `json:"block_profile_rate"`
	MutexProfileFraction int `json:"mutex_profile_fraction"`
}

// MemoryStats tracks memory usage statistics
type MemoryStats struct {
	// Current memory usage
	AllocBytes      uint64 `json:"alloc_bytes"`
	TotalAllocBytes uint64 `json:"total_alloc_bytes"`
	SysBytes        uint64 `json:"sys_bytes"`
	HeapBytes       uint64 `json:"heap_bytes"`
	StackBytes      uint64 `json:"stack_bytes"`

	// GC statistics
	NumGC         uint32        `json:"num_gc"`
	GCCPUFraction float64       `json:"gc_cpu_fraction"`
	LastGCTime    time.Time     `json:"last_gc_time"`
	TotalGCPause  time.Duration `json:"total_gc_pause"`

	// Allocation tracking
	AllocationsPerSecond float64             `json:"allocations_per_second"`
	TopAllocators        []AllocationHotspot `json:"top_allocators"`

	// Trends
	MemoryGrowthRate float64   `json:"memory_growth_rate_mb_per_min"`
	LastUpdate       time.Time `json:"last_update"`
}

// AllocationHotspot represents a memory allocation hotspot
type AllocationHotspot struct {
	Function     string  `json:"function"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	AllocBytes   int64   `json:"alloc_bytes"`
	AllocCount   int64   `json:"alloc_count"`
	PercentTotal float64 `json:"percent_total"`
}

// AllocationTracker tracks memory allocations by location
type AllocationTracker struct {
	allocations map[string]*AllocationInfo
	mutex       sync.RWMutex
	enabled     bool
}

// AllocationInfo tracks allocation information for a specific location
type AllocationInfo struct {
	Function   string
	File       string
	Line       int
	Count      int64
	TotalBytes int64
	LastSeen   time.Time
}

// NewMemoryProfiler creates a new memory profiler
func NewMemoryProfiler(config *ProfilerConfig) *MemoryProfiler {
	if config == nil {
		config = GetDefaultProfilerConfig()
	}

	profiler := &MemoryProfiler{
		config:       config,
		logger:       logging.NewLogger("memory-profiler", logging.INFO, false),
		allocTracker: NewAllocationTracker(config.EnableAllocationTracking),
		stopChan:     make(chan struct{}),
		stats:        &MemoryStats{},
	}

	// Configure runtime profiling
	if config.MemProfileRate > 0 {
		runtime.MemProfileRate = config.MemProfileRate
	}
	if config.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(config.BlockProfileRate)
	}
	if config.MutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(config.MutexProfileFraction)
	}

	return profiler
}

// Start starts the memory profiler
func (mp *MemoryProfiler) Start(ctx context.Context) error {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()

	if mp.running {
		return fmt.Errorf("profiler is already running")
	}

	// Start HTTP server if enabled
	if mp.config.EnableHTTPServer {
		go mp.startHTTPServer()
	}

	// Start memory monitoring
	mp.monitorTicker = time.NewTicker(mp.config.MonitorInterval)
	go mp.monitorMemory(ctx)

	mp.running = true
	mp.logger.Info("Memory profiler started", map[string]interface{}{
		"http_enabled":     mp.config.EnableHTTPServer,
		"http_addr":        mp.config.HTTPAddr,
		"monitor_interval": mp.config.MonitorInterval,
	})

	return nil
}

// Stop stops the memory profiler
func (mp *MemoryProfiler) Stop() error {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()

	if !mp.running {
		return fmt.Errorf("profiler is not running")
	}

	// Stop monitoring
	if mp.monitorTicker != nil {
		mp.monitorTicker.Stop()
	}
	close(mp.stopChan)

	mp.running = false
	mp.logger.Info("Memory profiler stopped", nil)

	return nil
}

// startHTTPServer starts the pprof HTTP server
func (mp *MemoryProfiler) startHTTPServer() {
	mp.logger.Info("Starting pprof HTTP server", map[string]interface{}{
		"addr": mp.config.HTTPAddr,
	})

	if err := http.ListenAndServe(mp.config.HTTPAddr, nil); err != nil {
		mp.logger.Error("Failed to start pprof HTTP server", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

// monitorMemory continuously monitors memory usage
func (mp *MemoryProfiler) monitorMemory(ctx context.Context) {
	var lastStats runtime.MemStats
	runtime.ReadMemStats(&lastStats)
	lastTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-mp.stopChan:
			return
		case <-mp.monitorTicker.C:
			mp.updateMemoryStats(&lastStats, &lastTime)
		}
	}
}

// updateMemoryStats updates memory statistics
func (mp *MemoryProfiler) updateMemoryStats(lastStats *runtime.MemStats, lastTime *time.Time) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	now := time.Now()
	timeDelta := now.Sub(*lastTime).Seconds()

	mp.statsMutex.Lock()
	defer mp.statsMutex.Unlock()

	// Update current stats
	mp.stats.AllocBytes = memStats.Alloc
	mp.stats.TotalAllocBytes = memStats.TotalAlloc
	mp.stats.SysBytes = memStats.Sys
	mp.stats.HeapBytes = memStats.HeapAlloc
	mp.stats.StackBytes = memStats.StackSys
	mp.stats.NumGC = memStats.NumGC
	mp.stats.GCCPUFraction = memStats.GCCPUFraction
	mp.stats.LastUpdate = now

	// Calculate GC pause time
	if memStats.NumGC > 0 {
		mp.stats.TotalGCPause = time.Duration(memStats.PauseTotalNs)
		mp.stats.LastGCTime = time.Unix(0, int64(memStats.LastGC))
	}

	// Calculate allocation rate
	if timeDelta > 0 {
		allocDelta := memStats.TotalAlloc - lastStats.TotalAlloc
		mp.stats.AllocationsPerSecond = float64(allocDelta) / timeDelta

		// Calculate memory growth rate (MB per minute)
		memDelta := int64(memStats.Alloc) - int64(lastStats.Alloc)
		mp.stats.MemoryGrowthRate = (float64(memDelta) / (1024 * 1024)) / (timeDelta / 60)
	}

	// Update allocation tracker
	if mp.allocTracker.enabled {
		mp.stats.TopAllocators = mp.allocTracker.GetTopAllocators(10)
	}

	// Check thresholds
	mp.checkThresholds(&memStats)

	// Update last stats
	*lastStats = memStats
	*lastTime = now
}

// checkThresholds checks memory usage against configured thresholds
func (mp *MemoryProfiler) checkThresholds(memStats *runtime.MemStats) {
	allocMB := int64(memStats.Alloc / (1024 * 1024))

	// Check GC threshold
	if mp.config.GCThreshold > 0 && allocMB > mp.config.GCThreshold {
		mp.logger.Info("Memory usage above GC threshold, forcing GC", map[string]interface{}{
			"current_mb":   allocMB,
			"threshold_mb": mp.config.GCThreshold,
		})
		runtime.GC()
	}

	// Check alert threshold
	if mp.config.MemoryAlertThreshold > 0 && allocMB > mp.config.MemoryAlertThreshold {
		mp.logger.Warn("Memory usage above alert threshold", map[string]interface{}{
			"current_mb":   allocMB,
			"threshold_mb": mp.config.MemoryAlertThreshold,
		})
	}
}

// GetStats returns current memory statistics
func (mp *MemoryProfiler) GetStats() MemoryStats {
	mp.statsMutex.RLock()
	defer mp.statsMutex.RUnlock()
	return *mp.stats
}

// TakeHeapProfile takes a heap profile and saves it to file
func (mp *MemoryProfiler) TakeHeapProfile(filename string) error {
	if filename == "" {
		filename = fmt.Sprintf("%s/heap_%d.prof", mp.config.ProfileDir, time.Now().Unix())
	}

	// Ensure directory exists
	if err := os.MkdirAll(mp.config.ProfileDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create profile file: %w", err)
	}
	defer file.Close()

	runtime.GC() // Force GC before profiling
	if err := pprof.WriteHeapProfile(file); err != nil {
		return fmt.Errorf("failed to write heap profile: %w", err)
	}

	mp.logger.Info("Heap profile saved", map[string]interface{}{
		"filename": filename,
	})

	return nil
}

// TakeCPUProfile takes a CPU profile for the specified duration
func (mp *MemoryProfiler) TakeCPUProfile(filename string, duration time.Duration) error {
	if filename == "" {
		filename = fmt.Sprintf("%s/cpu_%d.prof", mp.config.ProfileDir, time.Now().Unix())
	}

	// Ensure directory exists
	if err := os.MkdirAll(mp.config.ProfileDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create profile file: %w", err)
	}
	defer file.Close()

	if err := pprof.StartCPUProfile(file); err != nil {
		return fmt.Errorf("failed to start CPU profile: %w", err)
	}

	time.Sleep(duration)
	pprof.StopCPUProfile()

	mp.logger.Info("CPU profile saved", map[string]interface{}{
		"filename": filename,
		"duration": duration,
	})

	return nil
}

// PrintMemoryReport prints a detailed memory report
func (mp *MemoryProfiler) PrintMemoryReport() {
	stats := mp.GetStats()

	mp.logger.Info("Memory Profile Report", map[string]interface{}{
		"alloc_mb":             float64(stats.AllocBytes) / (1024 * 1024),
		"total_alloc_mb":       float64(stats.TotalAllocBytes) / (1024 * 1024),
		"sys_mb":               float64(stats.SysBytes) / (1024 * 1024),
		"heap_mb":              float64(stats.HeapBytes) / (1024 * 1024),
		"stack_mb":             float64(stats.StackBytes) / (1024 * 1024),
		"num_gc":               stats.NumGC,
		"gc_cpu_fraction":      stats.GCCPUFraction,
		"total_gc_pause_ms":    stats.TotalGCPause.Milliseconds(),
		"alloc_per_second":     stats.AllocationsPerSecond,
		"memory_growth_mb_min": stats.MemoryGrowthRate,
		"top_allocators_count": len(stats.TopAllocators),
	})

	// Print top allocators if available
	if len(stats.TopAllocators) > 0 {
		mp.logger.Info("Top Memory Allocators", map[string]interface{}{
			"count": len(stats.TopAllocators),
		})

		for i, hotspot := range stats.TopAllocators {
			if i >= 5 { // Limit to top 5
				break
			}
			mp.logger.Info(fmt.Sprintf("Allocator #%d", i+1), map[string]interface{}{
				"function":      hotspot.Function,
				"file":          hotspot.File,
				"line":          hotspot.Line,
				"alloc_mb":      float64(hotspot.AllocBytes) / (1024 * 1024),
				"alloc_count":   hotspot.AllocCount,
				"percent_total": hotspot.PercentTotal,
			})
		}
	}
}

// NewAllocationTracker creates a new allocation tracker
func NewAllocationTracker(enabled bool) *AllocationTracker {
	return &AllocationTracker{
		allocations: make(map[string]*AllocationInfo),
		enabled:     enabled,
	}
}

// GetTopAllocators returns the top N allocation hotspots
func (at *AllocationTracker) GetTopAllocators(n int) []AllocationHotspot {
	if !at.enabled {
		return nil
	}

	at.mutex.RLock()
	defer at.mutex.RUnlock()

	// Convert to slice for sorting
	hotspots := make([]AllocationHotspot, 0, len(at.allocations))
	var totalBytes int64

	for _, info := range at.allocations {
		totalBytes += info.TotalBytes
		hotspots = append(hotspots, AllocationHotspot{
			Function:   info.Function,
			File:       info.File,
			Line:       info.Line,
			AllocBytes: info.TotalBytes,
			AllocCount: info.Count,
		})
	}

	// Calculate percentages
	for i := range hotspots {
		if totalBytes > 0 {
			hotspots[i].PercentTotal = float64(hotspots[i].AllocBytes) / float64(totalBytes) * 100
		}
	}

	// Sort by allocation bytes (descending)
	for i := 0; i < len(hotspots)-1; i++ {
		for j := i + 1; j < len(hotspots); j++ {
			if hotspots[i].AllocBytes < hotspots[j].AllocBytes {
				hotspots[i], hotspots[j] = hotspots[j], hotspots[i]
			}
		}
	}

	// Return top N
	if n > len(hotspots) {
		n = len(hotspots)
	}
	return hotspots[:n]
}

// GetDefaultProfilerConfig returns default profiler configuration
func GetDefaultProfilerConfig() *ProfilerConfig {
	return &ProfilerConfig{
		EnableHTTPServer:         true,
		HTTPAddr:                 "localhost:6060",
		EnableFileProfiles:       true,
		ProfileDir:               "./profiles",
		MonitorInterval:          30 * time.Second,
		EnableAllocationTracking: false,      // Disabled by default due to overhead
		GCThreshold:              100,        // 100MB
		MemoryAlertThreshold:     500,        // 500MB
		MemProfileRate:           512 * 1024, // Sample every 512KB
		BlockProfileRate:         1,
		MutexProfileFraction:     1,
	}
}
