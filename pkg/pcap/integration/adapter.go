package integration

import (
	"cipgram/pkg/pcap/core"
	"cipgram/pkg/pcap/detection"
	"cipgram/pkg/pcap/dpi"

	"github.com/google/gopacket"
)

// ModularDetectionAdapter adapts the new modular detection system to work with existing code
type ModularDetectionAdapter struct {
	detector  *detection.UnifiedDetector
	dpiEngine *dpi.ModularDPIEngine
	config    *core.Config
}

// NewModularDetectionAdapter creates a new adapter
func NewModularDetectionAdapter(configPath string) *ModularDetectionAdapter {
	// Initialize configuration
	configManager := core.NewConfigManager(configPath)
	config := configManager.GetConfig()

	// Initialize DPI engine
	dpiEngine := dpi.NewModularDPIEngine(config.DPI)

	// Initialize unified detector
	detector := detection.NewUnifiedDetector(config.Detection, dpiEngine)

	return &ModularDetectionAdapter{
		detector:  detector,
		dpiEngine: dpiEngine,
		config:    config,
	}
}

// DetectProtocol provides a simple interface for protocol detection
func (adapter *ModularDetectionAdapter) DetectProtocol(packet gopacket.Packet) string {
	result := adapter.detector.DetectProtocol(packet)
	if result != nil {
		return result.Protocol
	}
	return "Unknown"
}

// DetectProtocolWithDetails provides detailed protocol detection results
func (adapter *ModularDetectionAdapter) DetectProtocolWithDetails(packet gopacket.Packet) *DetectionDetails {
	result := adapter.detector.DetectProtocol(packet)
	if result == nil {
		return &DetectionDetails{
			Protocol:   "Unknown",
			Confidence: 0.0,
			Method:     "none",
			Details:    make(map[string]interface{}),
		}
	}

	return &DetectionDetails{
		Protocol:   result.Protocol,
		Confidence: result.Confidence,
		Method:     methodToString(result.Method),
		Details:    result.Details,
	}
}

// DetectionDetails contains detailed detection information
type DetectionDetails struct {
	Protocol   string
	Confidence float32
	Method     string
	Details    map[string]interface{}
}

// GetSupportedProtocols returns all supported protocols
func (adapter *ModularDetectionAdapter) GetSupportedProtocols() []string {
	return adapter.detector.GetSupportedProtocols()
}

// GetDetectionStats returns detection statistics
func (adapter *ModularDetectionAdapter) GetDetectionStats() map[string]interface{} {
	stats := adapter.detector.GetDetectionStats()

	methodStats := make(map[string]int64)
	for method, count := range stats.MethodBreakdown {
		methodStats[methodToString(method)] = count
	}

	return map[string]interface{}{
		"total_packets":         stats.TotalPackets,
		"successful_detections": stats.SuccessfulDetections,
		"success_rate":          float32(stats.SuccessfulDetections) / float32(stats.TotalPackets),
		"method_breakdown":      methodStats,
		"protocol_counts":       stats.ProtocolCounts,
	}
}

// GetDPIStats returns DPI-specific statistics
func (adapter *ModularDetectionAdapter) GetDPIStats() map[string]interface{} {
	return adapter.dpiEngine.GetDPIReport()
}

// UpdateConfiguration updates the detection configuration
func (adapter *ModularDetectionAdapter) UpdateConfiguration(config *core.Config) {
	adapter.config = config
	adapter.detector.UpdateConfig(config.Detection)
	adapter.dpiEngine.UpdateConfig(config.DPI)
}

// EnableProtocol enables detection for a specific protocol
func (adapter *ModularDetectionAdapter) EnableProtocol(protocol string) {
	// This would update the configuration to enable the protocol
	// Implementation depends on how protocols are managed in config
}

// DisableProtocol disables detection for a specific protocol
func (adapter *ModularDetectionAdapter) DisableProtocol(protocol string) {
	// This would update the configuration to disable the protocol
	// Implementation depends on how protocols are managed in config
}

// SetConfidenceThreshold updates the confidence threshold
func (adapter *ModularDetectionAdapter) SetConfidenceThreshold(threshold float32) {
	adapter.config.Detection.ConfidenceThreshold = threshold
	adapter.detector.UpdateConfig(adapter.config.Detection)
}

// ClearCache clears all detection caches
func (adapter *ModularDetectionAdapter) ClearCache() {
	adapter.detector.ClearCache()
	adapter.dpiEngine.ClearCache()
}

// GetPerformanceReport generates a comprehensive performance report
func (adapter *ModularDetectionAdapter) GetPerformanceReport() map[string]interface{} {
	detectionReport := adapter.detector.GetDetectionReport()
	dpiReport := adapter.dpiEngine.GetDPIReport()

	return map[string]interface{}{
		"detection": detectionReport,
		"dpi":       dpiReport,
		"configuration": map[string]interface{}{
			"detection_enabled":  adapter.config.Detection.EnablePortBased || adapter.config.Detection.EnableDPI || adapter.config.Detection.EnableHeuristic,
			"dpi_enabled":        adapter.config.Detection.EnableDPI,
			"heuristic_enabled":  adapter.config.Detection.EnableHeuristic,
			"port_based_enabled": adapter.config.Detection.EnablePortBased,
		},
	}
}

// methodToString converts detection method enum to string
func methodToString(method core.DetectionMethod) string {
	switch method {
	case core.MethodPort:
		return "port"
	case core.MethodDPI:
		return "dpi"
	case core.MethodHeuristic:
		return "heuristic"
	case core.MethodSignature:
		return "signature"
	default:
		return "unknown"
	}
}

// BackwardCompatibilityWrapper provides backward compatibility with existing detection functions
type BackwardCompatibilityWrapper struct {
	adapter *ModularDetectionAdapter
}

// NewBackwardCompatibilityWrapper creates a wrapper for backward compatibility
func NewBackwardCompatibilityWrapper(configPath string) *BackwardCompatibilityWrapper {
	return &BackwardCompatibilityWrapper{
		adapter: NewModularDetectionAdapter(configPath),
	}
}

// DetectProtocol provides the same interface as the old detection system
func (wrapper *BackwardCompatibilityWrapper) DetectProtocol(packet gopacket.Packet) (protocol, subprotocol, details string) {
	result := wrapper.adapter.DetectProtocolWithDetails(packet)

	protocol = result.Protocol
	subprotocol = ""
	details = ""

	// Extract subprotocol and details from the result
	if result.Details != nil {
		if sub, exists := result.Details["subprotocol"]; exists {
			if subStr, ok := sub.(string); ok {
				subprotocol = subStr
			}
		}

		if det, exists := result.Details["details"]; exists {
			if detStr, ok := det.(string); ok {
				details = detStr
			}
		}
	}

	return protocol, subprotocol, details
}

// GetStats provides backward compatible statistics
func (wrapper *BackwardCompatibilityWrapper) GetStats() map[string]int {
	stats := wrapper.adapter.GetDetectionStats()

	// Convert to the old format
	result := make(map[string]int)

	if protocolCounts, exists := stats["protocol_counts"]; exists {
		if counts, ok := protocolCounts.(map[string]int64); ok {
			for protocol, count := range counts {
				result[protocol] = int(count)
			}
		}
	}

	return result
}

// OptimizedDetector provides a high-performance interface for the existing parser
type OptimizedDetector struct {
	adapter *ModularDetectionAdapter
	cache   map[string]string // Simple protocol cache for frequently seen patterns
}

// NewOptimizedDetector creates an optimized detector for high-throughput scenarios
func NewOptimizedDetector(configPath string) *OptimizedDetector {
	return &OptimizedDetector{
		adapter: NewModularDetectionAdapter(configPath),
		cache:   make(map[string]string),
	}
}

// FastDetect provides fast protocol detection with minimal overhead
func (od *OptimizedDetector) FastDetect(packet gopacket.Packet) string {
	// For high-throughput scenarios, we might want to use a simpler cache key
	// and skip detailed analysis for better performance

	result := od.adapter.detector.DetectProtocol(packet)
	if result != nil {
		return result.Protocol
	}

	return "Unknown"
}

// GetCacheStats returns cache performance statistics
func (od *OptimizedDetector) GetCacheStats() map[string]interface{} {
	return od.adapter.detector.GetCacheStats()
}

// ConfigurableDetector allows runtime configuration changes
type ConfigurableDetector struct {
	adapter       *ModularDetectionAdapter
	configManager *core.DefaultConfigManager
}

// NewConfigurableDetector creates a detector with runtime configuration support
func NewConfigurableDetector(configPath string) *ConfigurableDetector {
	configManager := core.NewConfigManager(configPath)
	adapter := NewModularDetectionAdapter(configPath)

	return &ConfigurableDetector{
		adapter:       adapter,
		configManager: configManager,
	}
}

// UpdateFromFile updates configuration from a file
func (cd *ConfigurableDetector) UpdateFromFile(configPath string) error {
	if err := cd.configManager.LoadFromFile(configPath); err != nil {
		return err
	}

	config := cd.configManager.GetConfig()
	cd.adapter.UpdateConfiguration(config)

	return nil
}

// SetDPIEnabled enables or disables DPI analysis
func (cd *ConfigurableDetector) SetDPIEnabled(enabled bool) error {
	config := cd.configManager.GetConfig()
	config.Detection.EnableDPI = enabled

	if err := cd.configManager.UpdateConfig(config); err != nil {
		return err
	}

	cd.adapter.UpdateConfiguration(config)
	return nil
}

// SetHeuristicEnabled enables or disables heuristic analysis
func (cd *ConfigurableDetector) SetHeuristicEnabled(enabled bool) error {
	config := cd.configManager.GetConfig()
	config.Detection.EnableHeuristic = enabled

	if err := cd.configManager.UpdateConfig(config); err != nil {
		return err
	}

	cd.adapter.UpdateConfiguration(config)
	return nil
}

// GetCurrentConfig returns the current configuration
func (cd *ConfigurableDetector) GetCurrentConfig() *core.Config {
	return cd.configManager.GetConfig()
}
