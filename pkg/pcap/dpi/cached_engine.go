// Package dpi provides cached Deep Packet Inspection capabilities
package dpi

import (
	"crypto/md5"
	"fmt"
	"time"

	"cipgram/pkg/pcap/cache"
	"cipgram/pkg/pcap/core"

	"github.com/google/gopacket"
)

// CachedDPIEngine wraps the modular DPI engine with LRU caching
type CachedDPIEngine struct {
	engine *ModularDPIEngine
	cache  *cache.LRUCache
	config *CachedEngineConfig
}

// CachedEngineConfig holds configuration for the cached DPI engine
type CachedEngineConfig struct {
	CacheSize     int           `json:"cache_size"`
	CacheTTL      time.Duration `json:"cache_ttl"`
	EnableCaching bool          `json:"enable_caching"`

	// Cache key strategy
	UsePayloadHash   bool `json:"use_payload_hash"`
	MaxPayloadLength int  `json:"max_payload_length"`
}

// NewCachedDPIEngine creates a new cached DPI engine
func NewCachedDPIEngine(config *core.DPIConfig) *CachedDPIEngine {
	cacheConfig := &CachedEngineConfig{
		CacheSize:        1000, // Default cache size
		CacheTTL:         5 * time.Minute,
		EnableCaching:    true,
		UsePayloadHash:   true,
		MaxPayloadLength: 1024, // Only hash first 1KB for performance
	}

	return &CachedDPIEngine{
		engine: NewModularDPIEngine(config),
		cache:  cache.NewLRUCache(cacheConfig.CacheSize, cacheConfig.CacheTTL),
		config: cacheConfig,
	}
}

// AnalyzePacket performs DPI analysis with caching
func (c *CachedDPIEngine) AnalyzePacket(packet gopacket.Packet) *core.AnalysisResult {
	if !c.config.EnableCaching {
		return c.engine.AnalyzePacket(packet)
	}

	// Generate cache key
	cacheKey := c.generateCacheKey(packet)

	// Try cache first
	if cached, found := c.cache.Get(cacheKey); found {
		if result, ok := cached.(*core.AnalysisResult); ok {
			// Create a copy to avoid mutation issues
			return &core.AnalysisResult{
				Protocol:   result.Protocol,
				Confidence: result.Confidence,
				Details:    copyInterfaceMap(result.Details),
				Metadata:   copyStringMap(result.Metadata),
			}
		}
	}

	// Cache miss - perform analysis
	result := c.engine.AnalyzePacket(packet)

	// Cache the result if it's confident enough
	if result != nil && result.Confidence >= 0.7 {
		// Create a copy for caching to avoid mutation issues
		cachedResult := &core.AnalysisResult{
			Protocol:   result.Protocol,
			Confidence: result.Confidence,
			Details:    copyInterfaceMap(result.Details),
			Metadata:   copyStringMap(result.Metadata),
		}
		c.cache.Put(cacheKey, cachedResult)
	}

	return result
}

// RegisterAnalyzer adds a new DPI analyzer to the engine
func (c *CachedDPIEngine) RegisterAnalyzer(name string, analyzer core.DPIAnalyzer) {
	c.engine.RegisterAnalyzer(name, analyzer)
}

// GetSupportedProtocols returns all supported protocols
func (c *CachedDPIEngine) GetSupportedProtocols() []string {
	return c.engine.GetSupportedProtocols()
}

// GetCacheStats returns cache performance statistics
func (c *CachedDPIEngine) GetCacheStats() cache.CacheStats {
	return c.cache.Stats()
}

// ClearCache clears all cached entries
func (c *CachedDPIEngine) ClearCache() {
	c.cache.Clear()
}

// SetCacheSize updates the cache capacity
func (c *CachedDPIEngine) SetCacheSize(size int) {
	c.config.CacheSize = size
	// Note: Current implementation doesn't support dynamic resize
	// Would need to create a new cache and migrate entries
}

// EnableCaching enables or disables caching
func (c *CachedDPIEngine) EnableCaching(enabled bool) {
	c.config.EnableCaching = enabled
}

// CleanupExpiredEntries removes expired cache entries
func (c *CachedDPIEngine) CleanupExpiredEntries() int {
	return c.cache.CleanupExpired()
}

// generateCacheKey creates a cache key for the packet
func (c *CachedDPIEngine) generateCacheKey(packet gopacket.Packet) string {
	if !c.config.UsePayloadHash {
		// Simple key based on packet metadata
		return fmt.Sprintf("pkt_%d_%s",
			len(packet.Data()),
			packet.NetworkLayer().LayerType().String())
	}

	// Generate hash-based key for better accuracy
	var data []byte
	var layerType string

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		data = appLayer.LayerContents()
		layerType = appLayer.LayerType().String()
	} else if transport := packet.TransportLayer(); transport != nil {
		data = transport.LayerContents()
		layerType = transport.LayerType().String()
	} else if network := packet.NetworkLayer(); network != nil {
		data = network.LayerContents()
		layerType = network.LayerType().String()
	} else {
		return "empty_packet"
	}

	if len(data) > c.config.MaxPayloadLength {
		data = data[:c.config.MaxPayloadLength]
	}

	hash := md5.Sum(data)
	return fmt.Sprintf("hash_%x_%s", hash, layerType)
}

// copyInterfaceMap creates a deep copy of an interface map
func copyInterfaceMap(original map[string]interface{}) map[string]interface{} {
	if original == nil {
		return nil
	}

	copy := make(map[string]interface{})
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

// copyStringMap creates a deep copy of a string map
func copyStringMap(original map[string]string) map[string]string {
	if original == nil {
		return nil
	}

	copy := make(map[string]string)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

// PerformanceReport provides detailed performance metrics
type PerformanceReport struct {
	CacheStats    cache.CacheStats   `json:"cache_stats"`
	Configuration CachedEngineConfig `json:"configuration"`
	Timestamp     time.Time          `json:"timestamp"`
}

// GetPerformanceReport returns comprehensive performance metrics
func (c *CachedDPIEngine) GetPerformanceReport() PerformanceReport {
	return PerformanceReport{
		CacheStats:    c.cache.Stats(),
		Configuration: *c.config,
		Timestamp:     time.Now(),
	}
}
