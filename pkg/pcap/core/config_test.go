package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigManager_GetDefaultConfig(t *testing.T) {
	cm := NewConfigManager("")
	config := cm.GetDefaultConfig()

	// Test detection config defaults
	if config.Detection == nil {
		t.Fatal("Detection config should not be nil")
	}
	if !config.Detection.EnablePortBased {
		t.Error("Port-based detection should be enabled by default")
	}
	if !config.Detection.EnableDPI {
		t.Error("DPI should be enabled by default")
	}
	if config.Detection.ConfidenceThreshold != 0.7 {
		t.Errorf("Expected confidence threshold 0.7, got %f", config.Detection.ConfidenceThreshold)
	}

	// Test DPI config defaults
	if config.DPI == nil {
		t.Fatal("DPI config should not be nil")
	}
	if !config.DPI.EnableHTTP {
		t.Error("HTTP DPI should be enabled by default")
	}
	if config.DPI.MaxPayloadSize != 1500 {
		t.Errorf("Expected max payload size 1500, got %d", config.DPI.MaxPayloadSize)
	}

	// Test performance config defaults
	if config.Performance == nil {
		t.Fatal("Performance config should not be nil")
	}
	if !config.Performance.EnableCaching {
		t.Error("Caching should be enabled by default")
	}
	if config.Performance.CacheSize != 10000 {
		t.Errorf("Expected cache size 10000, got %d", config.Performance.CacheSize)
	}
}

func TestDefaultConfigManager_ValidateConfig(t *testing.T) {
	cm := NewConfigManager("")

	// Test valid config
	validConfig := cm.GetDefaultConfig()
	if err := cm.ValidateConfig(validConfig); err != nil {
		t.Errorf("Valid config should pass validation: %v", err)
	}

	// Test nil config
	if err := cm.ValidateConfig(nil); err == nil {
		t.Error("Nil config should fail validation")
	}

	// Test invalid confidence threshold
	invalidConfig := cm.GetDefaultConfig()
	invalidConfig.Detection.ConfidenceThreshold = 1.5
	if err := cm.ValidateConfig(invalidConfig); err == nil {
		t.Error("Config with invalid confidence threshold should fail validation")
	}

	// Test negative cache size
	invalidConfig2 := cm.GetDefaultConfig()
	invalidConfig2.Performance.CacheSize = -1
	if err := cm.ValidateConfig(invalidConfig2); err == nil {
		t.Error("Config with negative cache size should fail validation")
	}
}

func TestDefaultConfigManager_LoadFromFile(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.json")

	testConfig := &Config{
		Detection: &DetectionConfig{
			EnablePortBased:     true,
			EnableDPI:           false,
			ConfidenceThreshold: 0.8,
		},
		Performance: &PerformanceConfig{
			EnableCaching: true,
			CacheSize:     5000,
		},
	}

	// Write test config to file
	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Test loading config
	cm := NewConfigManager("")
	if err := cm.LoadFromFile(configPath); err != nil {
		t.Fatalf("Failed to load config from file: %v", err)
	}

	config := cm.GetConfig()
	if config.Detection.ConfidenceThreshold != 0.8 {
		t.Errorf("Expected confidence threshold 0.8, got %f", config.Detection.ConfidenceThreshold)
	}
	if config.Detection.EnableDPI {
		t.Error("DPI should be disabled based on loaded config")
	}
	if config.Performance.CacheSize != 5000 {
		t.Errorf("Expected cache size 5000, got %d", config.Performance.CacheSize)
	}
}

func TestDefaultConfigManager_UpdateConfig(t *testing.T) {
	cm := NewConfigManager("")

	// Get default config and modify it
	config := cm.GetDefaultConfig()
	config.Detection.ConfidenceThreshold = 0.9
	config.Performance.CacheSize = 15000

	// Update config
	if err := cm.UpdateConfig(config); err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	// Verify changes
	updatedConfig := cm.GetConfig()
	if updatedConfig.Detection.ConfidenceThreshold != 0.9 {
		t.Errorf("Expected confidence threshold 0.9, got %f", updatedConfig.Detection.ConfidenceThreshold)
	}
	if updatedConfig.Performance.CacheSize != 15000 {
		t.Errorf("Expected cache size 15000, got %d", updatedConfig.Performance.CacheSize)
	}
}

func TestDefaultConfigManager_ProtocolManagement(t *testing.T) {
	cm := NewConfigManager("")

	// Test enabling a protocol
	if err := cm.EnableProtocol("TestProtocol"); err != nil {
		t.Fatalf("Failed to enable protocol: %v", err)
	}

	if !cm.IsProtocolEnabled("TestProtocol") {
		t.Error("TestProtocol should be enabled")
	}

	// Test disabling a protocol
	if err := cm.DisableProtocol("TestProtocol"); err != nil {
		t.Fatalf("Failed to disable protocol: %v", err)
	}

	if cm.IsProtocolEnabled("TestProtocol") {
		t.Error("TestProtocol should be disabled")
	}
}

func TestDefaultConfigManager_CacheManagement(t *testing.T) {
	cm := NewConfigManager("")

	// Test setting cache size
	if err := cm.SetCacheSize(20000); err != nil {
		t.Fatalf("Failed to set cache size: %v", err)
	}

	config := cm.GetConfig()
	if config.Performance.CacheSize != 20000 {
		t.Errorf("Expected cache size 20000, got %d", config.Performance.CacheSize)
	}

	// Test enabling/disabling caching
	if err := cm.EnableCaching(false); err != nil {
		t.Fatalf("Failed to disable caching: %v", err)
	}

	config = cm.GetConfig()
	if config.Performance.EnableCaching {
		t.Error("Caching should be disabled")
	}
}

func TestDefaultConfigManager_GetEnabledAnalyzers(t *testing.T) {
	cm := NewConfigManager("")

	analyzers := cm.GetEnabledAnalyzers()

	// Should include HTTP, TLS, DNS by default
	expectedAnalyzers := []string{"HTTP", "TLS", "DNS", "Modbus", "EtherNet/IP", "DNP3", "BACnet"}

	if len(analyzers) != len(expectedAnalyzers) {
		t.Errorf("Expected %d analyzers, got %d", len(expectedAnalyzers), len(analyzers))
	}

	// Check that all expected analyzers are present
	analyzerMap := make(map[string]bool)
	for _, analyzer := range analyzers {
		analyzerMap[analyzer] = true
	}

	for _, expected := range expectedAnalyzers {
		if !analyzerMap[expected] {
			t.Errorf("Expected analyzer %s not found", expected)
		}
	}
}

func TestDefaultConfigManager_GetConfigSummary(t *testing.T) {
	cm := NewConfigManager("")

	summary := cm.GetConfigSummary()

	// Check that summary contains expected sections
	expectedSections := []string{"detection", "dpi", "fingerprinting", "performance", "analysis"}

	for _, section := range expectedSections {
		if _, exists := summary[section]; !exists {
			t.Errorf("Expected section %s not found in summary", section)
		}
	}

	// Check detection section
	if detection, ok := summary["detection"].(map[string]interface{}); ok {
		if !detection["port_based_enabled"].(bool) {
			t.Error("Port-based detection should be enabled in summary")
		}
		if detection["confidence_threshold"].(float32) != 0.7 {
			t.Error("Confidence threshold should be 0.7 in summary")
		}
	} else {
		t.Error("Detection section should be a map")
	}
}

func BenchmarkDefaultConfigManager_GetConfig(b *testing.B) {
	cm := NewConfigManager("")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cm.GetConfig()
	}
}

func BenchmarkDefaultConfigManager_ValidateConfig(b *testing.B) {
	cm := NewConfigManager("")
	config := cm.GetDefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cm.ValidateConfig(config)
	}
}

func BenchmarkDefaultConfigManager_IsProtocolEnabled(b *testing.B) {
	cm := NewConfigManager("")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cm.IsProtocolEnabled("HTTP")
	}
}
