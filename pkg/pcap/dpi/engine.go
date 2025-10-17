package dpi

import (
	"cipgram/pkg/pcap/core"
	"sync"

	"github.com/google/gopacket"
)

// ModularDPIEngine coordinates multiple protocol analyzers
type ModularDPIEngine struct {
	analyzers      map[string]core.DPIAnalyzer
	analyzersMutex sync.RWMutex

	// Configuration
	config *core.DPIConfig

	// Statistics
	stats      *DPIStats
	statsMutex sync.RWMutex

	// Performance optimization
	cache      map[string]*core.AnalysisResult
	cacheSize  int
	cacheMutex sync.RWMutex
}

// DPIStats tracks DPI performance statistics
type DPIStats struct {
	TotalAnalyses      int64
	SuccessfulAnalyses int64
	AnalyzerStats      map[string]*AnalyzerStats
	CacheHits          int64
	CacheMisses        int64
}

// AnalyzerStats tracks statistics for individual analyzers
type AnalyzerStats struct {
	Analyses   int64
	Successes  int64
	Failures   int64
	AvgTime    float64
	Confidence float32
}

// NewModularDPIEngine creates a new modular DPI engine
func NewModularDPIEngine(config *core.DPIConfig) *ModularDPIEngine {
	engine := &ModularDPIEngine{
		analyzers: make(map[string]core.DPIAnalyzer),
		config:    config,
		stats: &DPIStats{
			AnalyzerStats: make(map[string]*AnalyzerStats),
		},
		cache:     make(map[string]*core.AnalysisResult),
		cacheSize: 5000,
	}

	engine.initializeAnalyzers()
	return engine
}

// AnalyzePacket performs comprehensive DPI analysis
func (engine *ModularDPIEngine) AnalyzePacket(packet gopacket.Packet) *core.AnalysisResult {
	engine.statsMutex.Lock()
	engine.stats.TotalAnalyses++
	engine.statsMutex.Unlock()

	// Check cache first
	if result := engine.checkCache(packet); result != nil {
		engine.statsMutex.Lock()
		engine.stats.CacheHits++
		engine.statsMutex.Unlock()
		return result
	}

	engine.statsMutex.Lock()
	engine.stats.CacheMisses++
	engine.statsMutex.Unlock()

	var bestResult *core.AnalysisResult
	bestConfidence := float32(0.0)

	// Try each analyzer
	engine.analyzersMutex.RLock()
	for name, analyzer := range engine.analyzers {
		if analyzer.CanAnalyze(packet) {
			if result := analyzer.Analyze(packet); result != nil {
				engine.updateAnalyzerStats(name, true, result.Confidence)

				// Keep the result with highest confidence
				if result.Confidence > bestConfidence {
					bestConfidence = result.Confidence
					bestResult = result
				}
			} else {
				engine.updateAnalyzerStats(name, false, 0.0)
			}
		}
	}
	engine.analyzersMutex.RUnlock()

	// Cache and return best result
	if bestResult != nil {
		engine.cacheResult(packet, bestResult)
		engine.statsMutex.Lock()
		engine.stats.SuccessfulAnalyses++
		engine.statsMutex.Unlock()
	}

	return bestResult
}

// RegisterAnalyzer registers a new DPI analyzer
func (engine *ModularDPIEngine) RegisterAnalyzer(name string, analyzer core.DPIAnalyzer) {
	engine.analyzersMutex.Lock()
	defer engine.analyzersMutex.Unlock()

	engine.analyzers[name] = analyzer

	engine.statsMutex.Lock()
	engine.stats.AnalyzerStats[name] = &AnalyzerStats{}
	engine.statsMutex.Unlock()
}

// UnregisterAnalyzer removes a DPI analyzer
func (engine *ModularDPIEngine) UnregisterAnalyzer(name string) {
	engine.analyzersMutex.Lock()
	defer engine.analyzersMutex.Unlock()

	delete(engine.analyzers, name)

	engine.statsMutex.Lock()
	delete(engine.stats.AnalyzerStats, name)
	engine.statsMutex.Unlock()
}

// GetSupportedProtocols returns all supported protocols
func (engine *ModularDPIEngine) GetSupportedProtocols() []string {
	engine.analyzersMutex.RLock()
	defer engine.analyzersMutex.RUnlock()

	var protocols []string
	for _, analyzer := range engine.analyzers {
		protocols = append(protocols, analyzer.GetProtocolName())
	}

	return protocols
}

// GetAnalyzerNames returns names of all registered analyzers
func (engine *ModularDPIEngine) GetAnalyzerNames() []string {
	engine.analyzersMutex.RLock()
	defer engine.analyzersMutex.RUnlock()

	var names []string
	for name := range engine.analyzers {
		names = append(names, name)
	}

	return names
}

// initializeAnalyzers initializes built-in analyzers based on configuration
func (engine *ModularDPIEngine) initializeAnalyzers() {
	if engine.config.EnableHTTP {
		engine.RegisterAnalyzer("HTTP", NewHTTPAnalyzer())
	}

	if engine.config.EnableTLS {
		engine.RegisterAnalyzer("TLS", NewTLSAnalyzer())
	}

	if engine.config.EnableDNS {
		engine.RegisterAnalyzer("DNS", NewDNSAnalyzer())
	}

	if engine.config.EnableIndustrial {
		engine.RegisterAnalyzer("Modbus", NewModbusAnalyzer())
		engine.RegisterAnalyzer("EtherNetIP", NewEtherNetIPAnalyzer())
		engine.RegisterAnalyzer("DNP3", NewDNP3Analyzer())
		engine.RegisterAnalyzer("BACnet", NewBACnetAnalyzer())
	}
}

// checkCache checks if analysis result is cached
func (engine *ModularDPIEngine) checkCache(packet gopacket.Packet) *core.AnalysisResult {
	key := engine.generateCacheKey(packet)

	engine.cacheMutex.RLock()
	result, exists := engine.cache[key]
	engine.cacheMutex.RUnlock()

	if exists {
		return result
	}

	return nil
}

// cacheResult caches an analysis result
func (engine *ModularDPIEngine) cacheResult(packet gopacket.Packet, result *core.AnalysisResult) {
	if len(engine.cache) >= engine.cacheSize {
		engine.evictCache()
	}

	key := engine.generateCacheKey(packet)

	engine.cacheMutex.Lock()
	engine.cache[key] = result
	engine.cacheMutex.Unlock()
}

// generateCacheKey generates a cache key for a packet
func (engine *ModularDPIEngine) generateCacheKey(packet gopacket.Packet) string {
	// Use application layer payload hash for caching
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			// Simple hash based on first few bytes and length
			hash := uint32(len(payload))
			for i := 0; i < min(len(payload), 16); i++ {
				hash = hash*31 + uint32(payload[i])
			}
			return string(rune(hash))
		}
	}

	// Fallback to layer types
	key := ""
	for _, layer := range packet.Layers() {
		key += layer.LayerType().String() + ":"
	}

	return key
}

// evictCache removes old entries from cache
func (engine *ModularDPIEngine) evictCache() {
	engine.cacheMutex.Lock()
	defer engine.cacheMutex.Unlock()

	// Simple eviction: remove half the cache
	if len(engine.cache) > engine.cacheSize/2 {
		newCache := make(map[string]*core.AnalysisResult)
		count := 0
		target := engine.cacheSize / 2

		for key, value := range engine.cache {
			if count >= target {
				break
			}
			newCache[key] = value
			count++
		}

		engine.cache = newCache
	}
}

// updateAnalyzerStats updates statistics for an analyzer
func (engine *ModularDPIEngine) updateAnalyzerStats(name string, success bool, confidence float32) {
	engine.statsMutex.Lock()
	defer engine.statsMutex.Unlock()

	stats, exists := engine.stats.AnalyzerStats[name]
	if !exists {
		stats = &AnalyzerStats{}
		engine.stats.AnalyzerStats[name] = stats
	}

	stats.Analyses++
	if success {
		stats.Successes++
		// Update running average confidence
		stats.Confidence = (stats.Confidence*float32(stats.Successes-1) + confidence) / float32(stats.Successes)
	} else {
		stats.Failures++
	}
}

// GetDPIStats returns current DPI statistics
func (engine *ModularDPIEngine) GetDPIStats() *DPIStats {
	engine.statsMutex.RLock()
	defer engine.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := &DPIStats{
		TotalAnalyses:      engine.stats.TotalAnalyses,
		SuccessfulAnalyses: engine.stats.SuccessfulAnalyses,
		CacheHits:          engine.stats.CacheHits,
		CacheMisses:        engine.stats.CacheMisses,
		AnalyzerStats:      make(map[string]*AnalyzerStats),
	}

	for name, analyzerStats := range engine.stats.AnalyzerStats {
		stats.AnalyzerStats[name] = &AnalyzerStats{
			Analyses:   analyzerStats.Analyses,
			Successes:  analyzerStats.Successes,
			Failures:   analyzerStats.Failures,
			AvgTime:    analyzerStats.AvgTime,
			Confidence: analyzerStats.Confidence,
		}
	}

	return stats
}

// GetCacheStats returns cache performance statistics
func (engine *ModularDPIEngine) GetCacheStats() map[string]interface{} {
	engine.cacheMutex.RLock()
	defer engine.cacheMutex.RUnlock()

	engine.statsMutex.RLock()
	defer engine.statsMutex.RUnlock()

	totalRequests := engine.stats.CacheHits + engine.stats.CacheMisses
	hitRate := float32(0)
	if totalRequests > 0 {
		hitRate = float32(engine.stats.CacheHits) / float32(totalRequests)
	}

	return map[string]interface{}{
		"cache_size":     len(engine.cache),
		"max_cache_size": engine.cacheSize,
		"cache_usage":    float32(len(engine.cache)) / float32(engine.cacheSize),
		"hit_rate":       hitRate,
		"total_hits":     engine.stats.CacheHits,
		"total_misses":   engine.stats.CacheMisses,
	}
}

// ClearCache clears the DPI cache
func (engine *ModularDPIEngine) ClearCache() {
	engine.cacheMutex.Lock()
	defer engine.cacheMutex.Unlock()

	engine.cache = make(map[string]*core.AnalysisResult)
}

// SetCacheSize updates the cache size
func (engine *ModularDPIEngine) SetCacheSize(size int) {
	engine.cacheMutex.Lock()
	defer engine.cacheMutex.Unlock()

	engine.cacheSize = size

	// Evict if current cache is larger than new size
	if len(engine.cache) > size {
		engine.evictCache()
	}
}

// UpdateConfig updates the DPI engine configuration
func (engine *ModularDPIEngine) UpdateConfig(config *core.DPIConfig) {
	engine.config = config

	// Reinitialize analyzers based on new config
	engine.analyzersMutex.Lock()
	engine.analyzers = make(map[string]core.DPIAnalyzer)
	engine.analyzersMutex.Unlock()

	engine.initializeAnalyzers()
}

// GetDPIReport generates a comprehensive DPI report
func (engine *ModularDPIEngine) GetDPIReport() map[string]interface{} {
	stats := engine.GetDPIStats()
	cacheStats := engine.GetCacheStats()

	successRate := float32(0)
	if stats.TotalAnalyses > 0 {
		successRate = float32(stats.SuccessfulAnalyses) / float32(stats.TotalAnalyses)
	}

	analyzerPerformance := make(map[string]interface{})
	for name, analyzerStats := range stats.AnalyzerStats {
		analyzerSuccessRate := float32(0)
		if analyzerStats.Analyses > 0 {
			analyzerSuccessRate = float32(analyzerStats.Successes) / float32(analyzerStats.Analyses)
		}

		analyzerPerformance[name] = map[string]interface{}{
			"analyses":       analyzerStats.Analyses,
			"success_rate":   analyzerSuccessRate,
			"avg_confidence": analyzerStats.Confidence,
		}
	}

	return map[string]interface{}{
		"summary": map[string]interface{}{
			"total_analyses":       stats.TotalAnalyses,
			"successful_analyses":  stats.SuccessfulAnalyses,
			"success_rate":         successRate,
			"registered_analyzers": len(engine.analyzers),
		},
		"analyzer_performance": analyzerPerformance,
		"cache_stats":          cacheStats,
		"configuration": map[string]interface{}{
			"http_enabled":       engine.config.EnableHTTP,
			"tls_enabled":        engine.config.EnableTLS,
			"dns_enabled":        engine.config.EnableDNS,
			"industrial_enabled": engine.config.EnableIndustrial,
			"max_payload_size":   engine.config.MaxPayloadSize,
		},
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
