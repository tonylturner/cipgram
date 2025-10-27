// Package performance provides adaptive memory optimization
package performance

import (
	"os"
	"runtime"

	"cipgram/pkg/logging"
)

// AdaptiveConfig provides intelligent configuration based on system resources and workload
type AdaptiveConfig struct {
	// System resources
	TotalMemoryMB     int64
	AvailableMemoryMB int64
	NumCPU            int

	// Workload characteristics
	EstimatedPackets int64
	FileSize         int64

	// Optimization strategy
	Strategy OptimizationStrategy
}

// OptimizationStrategy defines different optimization approaches
type OptimizationStrategy int

const (
	// StrategyMinimal uses minimal memory for small workloads
	StrategyMinimal OptimizationStrategy = iota

	// StrategyBalanced balances memory usage and performance
	StrategyBalanced

	// StrategyAggressive maximizes performance for large workloads
	StrategyAggressive

	// StrategyCustom allows manual configuration
	StrategyCustom
)

// GetAdaptiveConfig creates an optimized configuration based on system and workload characteristics
func GetAdaptiveConfig(filePath string) *OptimizationConfig {
	adaptive := analyzeSystem(filePath)
	logger := logging.NewLogger("adaptive-optimizer", logging.INFO, false)

	logger.Info("Adaptive optimization analysis", map[string]interface{}{
		"total_memory_mb":     adaptive.TotalMemoryMB,
		"available_memory_mb": adaptive.AvailableMemoryMB,
		"num_cpu":             adaptive.NumCPU,
		"file_size_mb":        adaptive.FileSize / (1024 * 1024),
		"estimated_packets":   adaptive.EstimatedPackets,
		"strategy":            getStrategyName(adaptive.Strategy),
	})

	return createOptimizedConfig(adaptive)
}

// analyzeSystem analyzes system resources and workload
func analyzeSystem(filePath string) *AdaptiveConfig {
	adaptive := &AdaptiveConfig{
		NumCPU: runtime.NumCPU(),
	}

	// Get system memory information
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	adaptive.TotalMemoryMB = int64(memStats.Sys / (1024 * 1024))
	adaptive.AvailableMemoryMB = adaptive.TotalMemoryMB - int64(memStats.Alloc/(1024*1024))

	// Analyze file size if provided
	if filePath != "" {
		if stat, err := os.Stat(filePath); err == nil {
			adaptive.FileSize = stat.Size()
			// Rough estimate: 1MB PCAP ≈ 1000-10000 packets
			adaptive.EstimatedPackets = adaptive.FileSize / 100 // Conservative estimate
		}
	}

	// Determine optimization strategy
	adaptive.Strategy = determineStrategy(adaptive)

	return adaptive
}

// determineStrategy selects the best optimization strategy
func determineStrategy(adaptive *AdaptiveConfig) OptimizationStrategy {
	fileSizeMB := adaptive.FileSize / (1024 * 1024)

	// Small files or limited memory - use minimal strategy
	if fileSizeMB < 10 || adaptive.AvailableMemoryMB < 500 {
		return StrategyMinimal
	}

	// Large files with plenty of memory - use aggressive strategy
	if fileSizeMB > 100 && adaptive.AvailableMemoryMB > 2000 {
		return StrategyAggressive
	}

	// Default to balanced
	return StrategyBalanced
}

// createOptimizedConfig creates an optimized configuration based on the adaptive analysis
func createOptimizedConfig(adaptive *AdaptiveConfig) *OptimizationConfig {
	config := &OptimizationConfig{
		EnableMemoryPooling:   true,
		EnablePacketBatching:  true,
		EnableZeroCopy:        true,
		GCOptimization:        true,
		EnableMemoryProfiling: false,
	}

	switch adaptive.Strategy {
	case StrategyMinimal:
		config.BatchSize = 100
		config.MaxBufferSize = 16384   // 16KB
		config.PoolPreallocation = 100 // Much smaller

	case StrategyBalanced:
		config.BatchSize = 500
		config.MaxBufferSize = 32768    // 32KB
		config.PoolPreallocation = 1000 // Reasonable size

	case StrategyAggressive:
		config.BatchSize = 2000
		config.MaxBufferSize = 65536    // 64KB
		config.PoolPreallocation = 5000 // Large but not excessive

	default:
		// Fallback to balanced
		config.BatchSize = 500
		config.MaxBufferSize = 32768
		config.PoolPreallocation = 1000
	}

	// Adjust based on available memory
	memoryBudgetMB := adaptive.AvailableMemoryMB / 4 // Use max 25% of available memory
	estimatedMemoryUsageMB := int64(config.PoolPreallocation) * int64(config.MaxBufferSize) / (1024 * 1024)

	if estimatedMemoryUsageMB > memoryBudgetMB {
		// Scale down to fit memory budget
		scaleFactor := float64(memoryBudgetMB) / float64(estimatedMemoryUsageMB)
		config.PoolPreallocation = int(float64(config.PoolPreallocation) * scaleFactor)

		// Ensure minimum viable configuration
		if config.PoolPreallocation < 10 {
			config.PoolPreallocation = 10
		}
	}

	return config
}

// getStrategyName returns a human-readable strategy name
func getStrategyName(strategy OptimizationStrategy) string {
	switch strategy {
	case StrategyMinimal:
		return "minimal"
	case StrategyBalanced:
		return "balanced"
	case StrategyAggressive:
		return "aggressive"
	case StrategyCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// MemoryUsageEstimate estimates memory usage for a configuration
type MemoryUsageEstimate struct {
	BufferPoolMB    float64 `json:"buffer_pool_mb"`
	ObjectPoolMB    float64 `json:"object_pool_mb"`
	TotalEstimateMB float64 `json:"total_estimate_mb"`
	PercentOfSystem float64 `json:"percent_of_system"`
}

// EstimateMemoryUsage calculates estimated memory usage for a configuration
func EstimateMemoryUsage(config *OptimizationConfig) MemoryUsageEstimate {
	// Buffer pool estimation
	bufferPoolMB := float64(config.PoolPreallocation) * float64(config.MaxBufferSize) / (1024 * 1024)

	// Object pool estimation (rough estimate)
	objectPoolMB := float64(config.PoolPreallocation) * 0.001 // ~1KB per object on average

	totalMB := bufferPoolMB + objectPoolMB

	// Get system memory for percentage calculation
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	systemMB := float64(memStats.Sys) / (1024 * 1024)

	return MemoryUsageEstimate{
		BufferPoolMB:    bufferPoolMB,
		ObjectPoolMB:    objectPoolMB,
		TotalEstimateMB: totalMB,
		PercentOfSystem: (totalMB / systemMB) * 100,
	}
}

// PrintMemoryEstimate prints a memory usage estimate
func PrintMemoryEstimate(config *OptimizationConfig) {
	estimate := EstimateMemoryUsage(config)
	logger := logging.NewLogger("memory-estimator", logging.INFO, false)

	logger.Info("Memory Usage Estimate", map[string]interface{}{
		"buffer_pool_mb":     estimate.BufferPoolMB,
		"object_pool_mb":     estimate.ObjectPoolMB,
		"total_estimate_mb":  estimate.TotalEstimateMB,
		"percent_of_system":  estimate.PercentOfSystem,
		"pool_preallocation": config.PoolPreallocation,
		"max_buffer_size":    config.MaxBufferSize,
		"batch_size":         config.BatchSize,
	})
}
