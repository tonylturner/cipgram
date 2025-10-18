package detection

import (
	"fmt"
	"sync"
	"time"

	"cipgram/pkg/pcap/cache"
	"cipgram/pkg/pcap/core"
	"cipgram/pkg/pcap/dpi"

	"github.com/google/gopacket"
)

// UnifiedDetector coordinates multiple detection methods
type UnifiedDetector struct {
	portDetector      *PortBasedDetector
	heuristicDetector *HeuristicDetector
	dpiEngine         *dpi.CachedDPIEngine

	// Configuration
	config *core.DetectionConfig

	// Statistics
	stats      *core.DetectionStats
	statsMutex sync.RWMutex

	// Performance optimization - LRU cache for detection results
	lruCache   *cache.LRUCache
	cacheMutex sync.RWMutex
}

// DPIEngine interface for deep packet inspection
type DPIEngine interface {
	AnalyzePacket(packet gopacket.Packet) *core.AnalysisResult
	GetSupportedProtocols() []string
}

// NewUnifiedDetector creates a new unified protocol detector
func NewUnifiedDetector(config *core.DetectionConfig, dpiEngine DPIEngine) *UnifiedDetector {
	// Create cached DPI engine if none provided
	var cachedEngine *dpi.CachedDPIEngine
	if dpiEngine != nil {
		// If a DPI engine is provided, we'll use it directly for now
		// In the future, we could wrap it with caching
		cachedEngine = dpi.NewCachedDPIEngine(&config.DPI)
	} else {
		cachedEngine = dpi.NewCachedDPIEngine(&config.DPI)
	}

	return &UnifiedDetector{
		portDetector:      NewPortBasedDetector(),
		heuristicDetector: NewHeuristicDetector(),
		dpiEngine:         cachedEngine,
		config:            config,
		stats: &core.DetectionStats{
			MethodBreakdown: make(map[core.DetectionMethod]int64),
			ProtocolCounts:  make(map[string]int64),
		},
		lruCache: cache.NewLRUCache(1000, 5*time.Minute), // 1000 entries, 5min TTL
	}
}

// DetectProtocol performs comprehensive protocol detection
func (ud *UnifiedDetector) DetectProtocol(packet gopacket.Packet) *core.DetectionResult {
	ud.statsMutex.Lock()
	ud.stats.TotalPackets++
	ud.statsMutex.Unlock()

	// Check cache first
	if result := ud.checkCache(packet); result != nil {
		return result
	}

	var bestResult *core.DetectionResult
	var results []*core.DetectionResult

	// 1. Try DPI first (highest confidence)
	if ud.config.EnableDPI && ud.dpiEngine != nil {
		if dpiResult := ud.dpiEngine.AnalyzePacket(packet); dpiResult != nil {
			result := &core.DetectionResult{
				Protocol:   dpiResult.Protocol,
				Confidence: dpiResult.Confidence,
				Method:     core.MethodDPI,
				Details: map[string]interface{}{
					"subprotocol": dpiResult.Subprotocol,
					"details":     dpiResult.Details,
				},
			}
			results = append(results, result)
		}
	}

	// 2. Try port-based detection
	if ud.config.EnablePortBased {
		if portResult := ud.portDetector.DetectByPort(packet); portResult != nil {
			results = append(results, portResult)
		}
	}

	// 3. Try heuristic detection
	if ud.config.EnableHeuristic {
		if heuristicResult := ud.heuristicDetector.DetectByHeuristics(packet); heuristicResult != nil {
			results = append(results, heuristicResult)
		}
	}

	// Select best result based on confidence and method priority
	bestResult = ud.selectBestResult(results)

	if bestResult != nil {
		// Only accept results above confidence threshold
		if bestResult.Confidence >= ud.config.ConfidenceThreshold {
			ud.updateStats(bestResult)
			ud.cacheResult(packet, bestResult)
			return bestResult
		}
	}

	// Return unknown result
	unknownResult := &core.DetectionResult{
		Protocol:   "Unknown",
		Confidence: 0.0,
		Method:     core.MethodUnknown,
		Details:    make(map[string]interface{}),
	}

	ud.cacheResult(packet, unknownResult)
	return unknownResult
}

// selectBestResult selects the best detection result from multiple candidates
func (ud *UnifiedDetector) selectBestResult(results []*core.DetectionResult) *core.DetectionResult {
	if len(results) == 0 {
		return nil
	}

	var best *core.DetectionResult
	bestScore := float32(-1)

	for _, result := range results {
		// Calculate weighted score based on method and confidence
		score := ud.calculateScore(result)
		if score > bestScore {
			bestScore = score
			best = result
		}
	}

	return best
}

// calculateScore calculates a weighted score for a detection result
func (ud *UnifiedDetector) calculateScore(result *core.DetectionResult) float32 {
	// Method weights (higher = better)
	methodWeights := map[core.DetectionMethod]float32{
		core.MethodDPI:       1.0, // Highest priority
		core.MethodSignature: 0.9,
		core.MethodPort:      0.7,
		core.MethodHeuristic: 0.5, // Lowest priority
	}

	weight, exists := methodWeights[result.Method]
	if !exists {
		weight = 0.1
	}

	return result.Confidence * weight
}

// checkCache checks if a result is cached for this packet
func (ud *UnifiedDetector) checkCache(packet gopacket.Packet) *core.DetectionResult {
	key := ud.generateCacheKey(packet)

	if cached, found := ud.lruCache.Get(key); found {
		if result, ok := cached.(*core.DetectionResult); ok {
			ud.statsMutex.Lock()
			ud.stats.CacheHits++
			ud.statsMutex.Unlock()
			return result
		}
	}

	ud.statsMutex.Lock()
	ud.stats.CacheMisses++
	ud.statsMutex.Unlock()
	return nil
}

// cacheResult caches a detection result
func (ud *UnifiedDetector) cacheResult(packet gopacket.Packet, result *core.DetectionResult) {
	key := ud.generateCacheKey(packet)
	ud.lruCache.Put(key, result)
}

// generateCacheKey generates a cache key for a packet
func (ud *UnifiedDetector) generateCacheKey(packet gopacket.Packet) string {
	// Use a combination of layer types and ports for caching
	key := ""

	for _, layer := range packet.Layers() {
		key += layer.LayerType().String() + ":"
	}

	// Add port information if available
	if tcpLayer := packet.TransportLayer(); tcpLayer != nil {
		key += fmt.Sprintf(":%d:%d", tcpLayer.TransportFlow().Src(), tcpLayer.TransportFlow().Dst())
	}

	return key
}

// evictCache removes old entries from cache
// evictCache is no longer needed - LRU cache handles eviction automatically

// updateStats updates detection statistics
func (ud *UnifiedDetector) updateStats(result *core.DetectionResult) {
	ud.statsMutex.Lock()
	defer ud.statsMutex.Unlock()

	if result.Protocol != "Unknown" {
		ud.stats.SuccessfulDetections++
	}

	ud.stats.MethodBreakdown[result.Method]++
	ud.stats.ProtocolCounts[result.Protocol]++
}

// GetSupportedProtocols returns all supported protocols
func (ud *UnifiedDetector) GetSupportedProtocols() []string {
	protocols := make(map[string]bool)

	// Add port-based protocols
	for _, proto := range ud.portDetector.GetSupportedProtocols() {
		protocols[proto] = true
	}

	// Add heuristic protocols
	for _, proto := range ud.heuristicDetector.GetSupportedProtocols() {
		protocols[proto] = true
	}

	// Add DPI protocols
	if ud.dpiEngine != nil {
		for _, proto := range ud.dpiEngine.GetSupportedProtocols() {
			protocols[proto] = true
		}
	}

	// Convert to slice
	var result []string
	for proto := range protocols {
		result = append(result, proto)
	}

	return result
}

// GetDetectionStats returns current detection statistics
func (ud *UnifiedDetector) GetDetectionStats() *core.DetectionStats {
	ud.statsMutex.RLock()
	defer ud.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := &core.DetectionStats{
		TotalPackets:         ud.stats.TotalPackets,
		SuccessfulDetections: ud.stats.SuccessfulDetections,
		MethodBreakdown:      make(map[core.DetectionMethod]int64),
		ProtocolCounts:       make(map[string]int64),
	}

	for method, count := range ud.stats.MethodBreakdown {
		stats.MethodBreakdown[method] = count
	}

	for protocol, count := range ud.stats.ProtocolCounts {
		stats.ProtocolCounts[protocol] = count
	}

	return stats
}

// GetCacheStats returns cache performance statistics
func (ud *UnifiedDetector) GetCacheStats() map[string]interface{} {
	cacheStats := ud.lruCache.Stats()
	dpiStats := ud.dpiEngine.GetCacheStats()

	return map[string]interface{}{
		"detection_cache": map[string]interface{}{
			"hits":     cacheStats.Hits,
			"misses":   cacheStats.Misses,
			"evicts":   cacheStats.Evicts,
			"hit_rate": cacheStats.HitRate,
			"size":     cacheStats.Size,
			"capacity": cacheStats.Capacity,
		},
		"dpi_cache": map[string]interface{}{
			"hits":     dpiStats.Hits,
			"misses":   dpiStats.Misses,
			"evicts":   dpiStats.Evicts,
			"hit_rate": dpiStats.HitRate,
			"size":     dpiStats.Size,
			"capacity": dpiStats.Capacity,
		},
	}
}

// ClearCache clears the detection cache
func (ud *UnifiedDetector) ClearCache() {
	ud.lruCache.Clear()
	ud.dpiEngine.ClearCache()
}

// SetCacheSize updates the cache size
func (ud *UnifiedDetector) SetCacheSize(size int) {
	ud.dpiEngine.SetCacheSize(size)
	// Note: LRU cache doesn't support dynamic resize in current implementation
	// Would need to create new cache and migrate entries
}

// UpdateConfig updates the detector configuration
func (ud *UnifiedDetector) UpdateConfig(config *core.DetectionConfig) {
	ud.config = config
}

// GetDetectionReport generates a comprehensive detection report
func (ud *UnifiedDetector) GetDetectionReport() map[string]interface{} {
	stats := ud.GetDetectionStats()
	cacheStats := ud.GetCacheStats()

	successRate := float32(0)
	if stats.TotalPackets > 0 {
		successRate = float32(stats.SuccessfulDetections) / float32(stats.TotalPackets)
	}

	return map[string]interface{}{
		"summary": map[string]interface{}{
			"total_packets":         stats.TotalPackets,
			"successful_detections": stats.SuccessfulDetections,
			"success_rate":          successRate,
			"supported_protocols":   len(ud.GetSupportedProtocols()),
		},
		"method_breakdown": stats.MethodBreakdown,
		"protocol_counts":  stats.ProtocolCounts,
		"cache_stats":      cacheStats,
		"configuration": map[string]interface{}{
			"port_based_enabled":   ud.config.EnablePortBased,
			"dpi_enabled":          ud.config.EnableDPI,
			"heuristic_enabled":    ud.config.EnableHeuristic,
			"confidence_threshold": ud.config.ConfidenceThreshold,
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}
}
