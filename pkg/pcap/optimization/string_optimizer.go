// Package optimization provides string operation optimizations for PCAP processing
package optimization

import (
	"strings"
	"sync"
)

// StringOptimizer provides optimized string operations for hot paths
type StringOptimizer struct {
	// String builders pool for reuse
	builderPool sync.Pool

	// Common string cache for frequently used strings
	commonStrings map[string]string
	stringsMutex  sync.RWMutex

	// Statistics
	builderHits   int64
	builderMisses int64
	cacheHits     int64
	cacheMisses   int64
}

// NewStringOptimizer creates a new string optimizer
func NewStringOptimizer() *StringOptimizer {
	optimizer := &StringOptimizer{
		commonStrings: make(map[string]string),
		builderPool: sync.Pool{
			New: func() interface{} {
				return &strings.Builder{}
			},
		},
	}

	// Pre-populate with common protocol strings
	optimizer.prePopulateCommonStrings()

	return optimizer
}

// GetBuilder gets a string builder from the pool
func (so *StringOptimizer) GetBuilder() *strings.Builder {
	builder := so.builderPool.Get().(*strings.Builder)
	builder.Reset() // Ensure it's clean
	so.builderHits++
	return builder
}

// PutBuilder returns a string builder to the pool
func (so *StringOptimizer) PutBuilder(builder *strings.Builder) {
	if builder.Cap() > 1024*1024 { // 1MB limit to prevent memory bloat
		// Don't return very large builders to the pool
		return
	}
	so.builderPool.Put(builder)
}

// BuildString efficiently builds a string using pooled builders
func (so *StringOptimizer) BuildString(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}

	builder := so.GetBuilder()
	defer so.PutBuilder(builder)

	for _, part := range parts {
		builder.WriteString(part)
	}

	return builder.String()
}

// InternString interns frequently used strings to reduce memory allocation
func (so *StringOptimizer) InternString(s string) string {
	if s == "" {
		return ""
	}

	// Check cache first
	so.stringsMutex.RLock()
	if cached, exists := so.commonStrings[s]; exists {
		so.stringsMutex.RUnlock()
		so.cacheHits++
		return cached
	}
	so.stringsMutex.RUnlock()

	// Add to cache if it's a reasonable size
	if len(s) <= 256 && len(so.commonStrings) < 10000 {
		so.stringsMutex.Lock()
		// Double-check after acquiring write lock
		if cached, exists := so.commonStrings[s]; exists {
			so.stringsMutex.Unlock()
			so.cacheHits++
			return cached
		}
		so.commonStrings[s] = s
		so.stringsMutex.Unlock()
	}

	so.cacheMisses++
	return s
}

// OptimizedJoin efficiently joins strings with a separator
func (so *StringOptimizer) OptimizedJoin(parts []string, separator string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}

	builder := so.GetBuilder()
	defer so.PutBuilder(builder)

	for i, part := range parts {
		if i > 0 {
			builder.WriteString(separator)
		}
		builder.WriteString(part)
	}

	return builder.String()
}

// OptimizedConcat efficiently concatenates multiple strings
func (so *StringOptimizer) OptimizedConcat(parts ...string) string {
	return so.BuildString(parts...)
}

// FormatProtocolKey creates an optimized protocol key string
func (so *StringOptimizer) FormatProtocolKey(protocol, srcIP, dstIP string, srcPort, dstPort int) string {
	builder := so.GetBuilder()
	defer so.PutBuilder(builder)

	builder.WriteString(protocol)
	builder.WriteString(":")
	builder.WriteString(srcIP)
	builder.WriteString(":")
	builder.WriteString(dstIP)
	builder.WriteString(":")

	// Optimized integer to string conversion for ports
	so.writeInt(builder, srcPort)
	builder.WriteString(":")
	so.writeInt(builder, dstPort)

	return so.InternString(builder.String())
}

// FormatAssetKey creates an optimized asset key string
func (so *StringOptimizer) FormatAssetKey(ip, mac string) string {
	if mac == "" {
		return so.InternString(ip)
	}

	builder := so.GetBuilder()
	defer so.PutBuilder(builder)

	builder.WriteString(ip)
	builder.WriteString(":")
	builder.WriteString(mac)

	return so.InternString(builder.String())
}

// writeInt efficiently writes an integer to a string builder
func (so *StringOptimizer) writeInt(builder *strings.Builder, value int) {
	if value == 0 {
		builder.WriteByte('0')
		return
	}

	// Handle negative numbers
	if value < 0 {
		builder.WriteByte('-')
		value = -value
	}

	// Convert to string without allocation for small numbers
	if value < 10 {
		builder.WriteByte(byte('0' + value))
		return
	}

	// For larger numbers, use a small buffer
	var buf [20]byte // Enough for 64-bit integers
	i := len(buf)

	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}

	builder.Write(buf[i:])
}

// prePopulateCommonStrings adds frequently used strings to the cache
func (so *StringOptimizer) prePopulateCommonStrings() {
	commonProtocols := []string{
		"TCP", "UDP", "ICMP", "ARP", "HTTP", "HTTPS", "DNS", "DHCP",
		"EtherNet/IP", "Modbus", "DNP3", "BACnet", "OPC-UA", "S7Comm",
		"NetBIOS", "SMB", "SSH", "FTP", "SMTP", "POP3", "IMAP",
		"Unknown", "Industrial", "IT", "OT",
	}

	for _, protocol := range commonProtocols {
		so.commonStrings[protocol] = protocol
	}

	// Common network patterns
	commonPatterns := []string{
		"192.168.", "10.", "172.", "127.0.0.1", "0.0.0.0",
		"255.255.255.255", "broadcast", "multicast",
		":80", ":443", ":53", ":22", ":21", ":25", ":110", ":143",
		":502", ":44818", ":20000", ":102",
	}

	for _, pattern := range commonPatterns {
		so.commonStrings[pattern] = pattern
	}
}

// GetStats returns string optimization statistics
func (so *StringOptimizer) GetStats() StringOptimizerStats {
	so.stringsMutex.RLock()
	defer so.stringsMutex.RUnlock()

	cacheTotal := so.cacheHits + so.cacheMisses
	builderTotal := so.builderHits + so.builderMisses

	var cacheHitRate, builderHitRate float64
	if cacheTotal > 0 {
		cacheHitRate = float64(so.cacheHits) / float64(cacheTotal)
	}
	if builderTotal > 0 {
		builderHitRate = float64(so.builderHits) / float64(builderTotal)
	}

	return StringOptimizerStats{
		CacheHits:      so.cacheHits,
		CacheMisses:    so.cacheMisses,
		CacheHitRate:   cacheHitRate,
		CacheSize:      len(so.commonStrings),
		BuilderHits:    so.builderHits,
		BuilderMisses:  so.builderMisses,
		BuilderHitRate: builderHitRate,
	}
}

// ClearCache clears the string cache
func (so *StringOptimizer) ClearCache() {
	so.stringsMutex.Lock()
	defer so.stringsMutex.Unlock()

	so.commonStrings = make(map[string]string)
	so.prePopulateCommonStrings()
}

// StringOptimizerStats contains performance statistics
type StringOptimizerStats struct {
	CacheHits      int64   `json:"cache_hits"`
	CacheMisses    int64   `json:"cache_misses"`
	CacheHitRate   float64 `json:"cache_hit_rate"`
	CacheSize      int     `json:"cache_size"`
	BuilderHits    int64   `json:"builder_hits"`
	BuilderMisses  int64   `json:"builder_misses"`
	BuilderHitRate float64 `json:"builder_hit_rate"`
}
