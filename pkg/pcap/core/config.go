package core

import (
	"encoding/json"
	"fmt"
	"os"
)

// DefaultConfigManager implements the ConfigManager interface
type DefaultConfigManager struct {
	config     *Config
	configPath string
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configPath string) *DefaultConfigManager {
	return &DefaultConfigManager{
		configPath: configPath,
		config:     nil,
	}
}

// GetConfig returns the current configuration
func (cm *DefaultConfigManager) GetConfig() *Config {
	if cm.config == nil {
		cm.config = cm.GetDefaultConfig()
	}
	return cm.config
}

// UpdateConfig updates the configuration
func (cm *DefaultConfigManager) UpdateConfig(config *Config) error {
	if err := cm.ValidateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	cm.config = config

	// Save to file if path is specified
	if cm.configPath != "" {
		return cm.saveToFile(config)
	}

	return nil
}

// ValidateConfig validates the configuration
func (cm *DefaultConfigManager) ValidateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate detection config
	if config.Detection != nil {
		if config.Detection.ConfidenceThreshold < 0 || config.Detection.ConfidenceThreshold > 1 {
			return fmt.Errorf("detection confidence threshold must be between 0 and 1")
		}
	}

	// Validate DPI config
	if config.DPI != nil {
		if config.DPI.MaxPayloadSize < 0 {
			return fmt.Errorf("DPI max payload size cannot be negative")
		}
		if config.DPI.Timeout < 0 {
			return fmt.Errorf("DPI timeout cannot be negative")
		}
	}

	// Validate fingerprinting config
	if config.Fingerprinting != nil {
		if config.Fingerprinting.ConfidenceThreshold < 0 || config.Fingerprinting.ConfidenceThreshold > 1 {
			return fmt.Errorf("fingerprinting confidence threshold must be between 0 and 1")
		}
		if config.Fingerprinting.MaxSignatures < 0 {
			return fmt.Errorf("max signatures cannot be negative")
		}
	}

	// Validate performance config
	if config.Performance != nil {
		if config.Performance.CacheSize < 0 {
			return fmt.Errorf("cache size cannot be negative")
		}
		if config.Performance.MaxMemoryMB < 0 {
			return fmt.Errorf("max memory cannot be negative")
		}
		// Worker count validation removed - no longer using worker pools
	}

	return nil
}

// GetDefaultConfig returns the default configuration
func (cm *DefaultConfigManager) GetDefaultConfig() *Config {
	return &Config{
		Detection: &DetectionConfig{
			EnablePortBased:     true,
			EnableDPI:           true,
			EnableHeuristic:     true,
			ConfidenceThreshold: 0.7,
			EnabledProtocols: []string{
				"HTTP", "HTTPS", "SSH", "DNS", "DHCP",
				"Modbus", "EtherNet/IP", "OPC-UA", "DNP3",
				"BACnet", "Profinet", "S7Comm",
			},
		},
		DPI: &DPIConfig{
			EnableHTTP:       true,
			EnableTLS:        true,
			EnableDNS:        true,
			EnableIndustrial: true,
			MaxPayloadSize:   1500,
			Timeout:          1000, // 1 second
		},
		Fingerprinting: &FingerprintingConfig{
			EnableOSDetection:     true,
			EnableDeviceDetection: true,
			ConfidenceThreshold:   0.6,
			MaxSignatures:         1000,
		},
		Performance: &PerformanceConfig{
			EnableCaching:   true,
			CacheSize:       10000,
			EnableProfiling: false,
			MaxMemoryMB:     512,
		},
		Analysis: &AnalysisConfig{
			EnableFlowAnalysis:     true,
			EnableAnomalyDetection: false,
			EnableReporting:        true,
			ReportFormat:           "json",
		},
	}
}

// LoadFromFile loads configuration from a file
func (cm *DefaultConfigManager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return cm.UpdateConfig(&config)
}

// saveToFile saves configuration to a file
func (cm *DefaultConfigManager) saveToFile(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetDetectionConfig returns detection configuration with defaults
func (cm *DefaultConfigManager) GetDetectionConfig() *DetectionConfig {
	config := cm.GetConfig()
	if config.Detection == nil {
		return cm.GetDefaultConfig().Detection
	}
	return config.Detection
}

// GetDPIConfig returns DPI configuration with defaults
func (cm *DefaultConfigManager) GetDPIConfig() *DPIConfig {
	config := cm.GetConfig()
	if config.DPI == nil {
		return cm.GetDefaultConfig().DPI
	}
	return config.DPI
}

// GetFingerprintingConfig returns fingerprinting configuration with defaults
func (cm *DefaultConfigManager) GetFingerprintingConfig() *FingerprintingConfig {
	config := cm.GetConfig()
	if config.Fingerprinting == nil {
		return cm.GetDefaultConfig().Fingerprinting
	}
	return config.Fingerprinting
}

// GetPerformanceConfig returns performance configuration with defaults
func (cm *DefaultConfigManager) GetPerformanceConfig() *PerformanceConfig {
	config := cm.GetConfig()
	if config.Performance == nil {
		return cm.GetDefaultConfig().Performance
	}
	return config.Performance
}

// GetAnalysisConfig returns analysis configuration with defaults
func (cm *DefaultConfigManager) GetAnalysisConfig() *AnalysisConfig {
	config := cm.GetConfig()
	if config.Analysis == nil {
		return cm.GetDefaultConfig().Analysis
	}
	return config.Analysis
}

// IsProtocolEnabled checks if a protocol is enabled
func (cm *DefaultConfigManager) IsProtocolEnabled(protocol string) bool {
	detectionConfig := cm.GetDetectionConfig()

	// If no specific protocols are configured, assume all are enabled
	if len(detectionConfig.EnabledProtocols) == 0 {
		return true
	}

	for _, enabled := range detectionConfig.EnabledProtocols {
		if enabled == protocol {
			return true
		}
	}

	return false
}

// GetEnabledAnalyzers returns the list of enabled DPI analyzers
func (cm *DefaultConfigManager) GetEnabledAnalyzers() []string {
	dpiConfig := cm.GetDPIConfig()
	var enabled []string

	if dpiConfig.EnableHTTP {
		enabled = append(enabled, "HTTP")
	}
	if dpiConfig.EnableTLS {
		enabled = append(enabled, "TLS")
	}
	if dpiConfig.EnableDNS {
		enabled = append(enabled, "DNS")
	}
	if dpiConfig.EnableIndustrial {
		enabled = append(enabled, "Modbus", "EtherNet/IP", "DNP3", "BACnet")
	}

	return enabled
}

// UpdateDetectionThreshold updates the detection confidence threshold
func (cm *DefaultConfigManager) UpdateDetectionThreshold(threshold float32) error {
	if threshold < 0 || threshold > 1 {
		return fmt.Errorf("threshold must be between 0 and 1")
	}

	config := cm.GetConfig()
	if config.Detection == nil {
		config.Detection = cm.GetDefaultConfig().Detection
	}

	config.Detection.ConfidenceThreshold = threshold
	return cm.UpdateConfig(config)
}

// EnableProtocol enables a specific protocol
func (cm *DefaultConfigManager) EnableProtocol(protocol string) error {
	config := cm.GetConfig()
	if config.Detection == nil {
		config.Detection = cm.GetDefaultConfig().Detection
	}

	// Check if already enabled
	for _, enabled := range config.Detection.EnabledProtocols {
		if enabled == protocol {
			return nil // Already enabled
		}
	}

	config.Detection.EnabledProtocols = append(config.Detection.EnabledProtocols, protocol)
	return cm.UpdateConfig(config)
}

// DisableProtocol disables a specific protocol
func (cm *DefaultConfigManager) DisableProtocol(protocol string) error {
	config := cm.GetConfig()
	if config.Detection == nil {
		return nil // Nothing to disable
	}

	var filtered []string
	for _, enabled := range config.Detection.EnabledProtocols {
		if enabled != protocol {
			filtered = append(filtered, enabled)
		}
	}

	config.Detection.EnabledProtocols = filtered
	return cm.UpdateConfig(config)
}

// SetCacheSize updates the cache size
func (cm *DefaultConfigManager) SetCacheSize(size int) error {
	if size < 0 {
		return fmt.Errorf("cache size cannot be negative")
	}

	config := cm.GetConfig()
	if config.Performance == nil {
		config.Performance = cm.GetDefaultConfig().Performance
	}

	config.Performance.CacheSize = size
	return cm.UpdateConfig(config)
}

// EnableCaching enables or disables caching
func (cm *DefaultConfigManager) EnableCaching(enabled bool) error {
	config := cm.GetConfig()
	if config.Performance == nil {
		config.Performance = cm.GetDefaultConfig().Performance
	}

	config.Performance.EnableCaching = enabled
	return cm.UpdateConfig(config)
}

// GetConfigSummary returns a summary of the current configuration
func (cm *DefaultConfigManager) GetConfigSummary() map[string]interface{} {
	config := cm.GetConfig()

	return map[string]interface{}{
		"detection": map[string]interface{}{
			"port_based_enabled":   config.Detection.EnablePortBased,
			"dpi_enabled":          config.Detection.EnableDPI,
			"heuristic_enabled":    config.Detection.EnableHeuristic,
			"confidence_threshold": config.Detection.ConfidenceThreshold,
			"enabled_protocols":    len(config.Detection.EnabledProtocols),
		},
		"dpi": map[string]interface{}{
			"http_enabled":       config.DPI.EnableHTTP,
			"tls_enabled":        config.DPI.EnableTLS,
			"dns_enabled":        config.DPI.EnableDNS,
			"industrial_enabled": config.DPI.EnableIndustrial,
			"max_payload_size":   config.DPI.MaxPayloadSize,
		},
		"fingerprinting": map[string]interface{}{
			"os_detection_enabled":     config.Fingerprinting.EnableOSDetection,
			"device_detection_enabled": config.Fingerprinting.EnableDeviceDetection,
			"confidence_threshold":     config.Fingerprinting.ConfidenceThreshold,
		},
		"performance": map[string]interface{}{
			"caching_enabled": config.Performance.EnableCaching,
			"cache_size":      config.Performance.CacheSize,
			"max_memory_mb":   config.Performance.MaxMemoryMB,
			// Worker count removed - no longer using worker pools
		},
		"analysis": map[string]interface{}{
			"flow_analysis_enabled":     config.Analysis.EnableFlowAnalysis,
			"anomaly_detection_enabled": config.Analysis.EnableAnomalyDetection,
			"reporting_enabled":         config.Analysis.EnableReporting,
		},
	}
}
