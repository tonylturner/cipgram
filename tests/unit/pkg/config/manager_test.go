package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cipgram/pkg/config"
)

func TestNewManager(t *testing.T) {
	manager := config.NewManager()
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}
}

func TestGetDefaultConfig(t *testing.T) {
	cfg := config.GetDefaultConfig()
	if cfg == nil {
		t.Fatal("Expected default config to be created")
	}

	// Validate default values
	if cfg.App.Name != "cipgram" {
		t.Errorf("Expected app name 'cipgram', got %s", cfg.App.Name)
	}

	if cfg.Performance.BatchSize <= 0 {
		t.Errorf("Expected positive batch size, got %d", cfg.Performance.BatchSize)
	}

	if cfg.Performance.MaxBufferSize <= 0 {
		t.Errorf("Expected positive buffer size, got %d", cfg.Performance.MaxBufferSize)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.yaml")

	configContent := `
app:
  name: "test-cipgram"
  version: "1.0.0"
  environment: "test"
  debug: true

pcap:
  show_hostnames: false
  enable_vendor_lookup: true
  fast_mode: true

performance:
  batch_size: 500
  max_buffer_size: 32768
  optimization_strategy: "balanced"

profiling:
  enabled: true
  http_server:
    enabled: true
    port: 6061

logging:
  level: "debug"
  format: "json"

observability:
  metrics:
    enabled: true
    port: 9091
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load configuration
	manager := config.NewManager()
	cfg, err := manager.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Validate loaded values
	if cfg.App.Name != "test-cipgram" {
		t.Errorf("Expected app name 'test-cipgram', got %s", cfg.App.Name)
	}

	if cfg.App.Debug != true {
		t.Errorf("Expected debug mode true, got %v", cfg.App.Debug)
	}

	if cfg.Performance.BatchSize != 500 {
		t.Errorf("Expected batch size 500, got %d", cfg.Performance.BatchSize)
	}

	if cfg.Profiling.HTTPServer.Port != 6061 {
		t.Errorf("Expected profiling port 6061, got %d", cfg.Profiling.HTTPServer.Port)
	}

	if cfg.Observability.Metrics.Port != 9091 {
		t.Errorf("Expected metrics port 9091, got %d", cfg.Observability.Metrics.Port)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Set environment variables
	envVars := map[string]string{
		"CIPGRAM_APP_NAME":               "env-cipgram",
		"CIPGRAM_APP_DEBUG":              "true",
		"CIPGRAM_PERFORMANCE_BATCH_SIZE": "2000",
		"CIPGRAM_PROFILING_ENABLED":      "true",
		"CIPGRAM_LOGGING_LEVEL":          "error",
	}

	// Set environment variables
	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Load configuration
	manager := config.NewManager()
	cfg, err := manager.LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load config from env: %v", err)
	}

	// Validate environment overrides
	if cfg.App.Name != "env-cipgram" {
		t.Errorf("Expected app name 'env-cipgram', got %s", cfg.App.Name)
	}

	if cfg.App.Debug != true {
		t.Errorf("Expected debug mode true, got %v", cfg.App.Debug)
	}

	if cfg.Performance.BatchSize != 2000 {
		t.Errorf("Expected batch size 2000, got %d", cfg.Performance.BatchSize)
	}
}

func TestConfigValidation(t *testing.T) {
	manager := config.NewManager()

	// Test valid configuration
	_, err := manager.LoadConfig("")
	if err != nil {
		t.Errorf("Valid config should not fail validation: %v", err)
	}

	// Test invalid batch size
	invalidConfig := config.GetDefaultConfig()
	invalidConfig.Performance.BatchSize = -1

	err = manager.UpdateConfig(invalidConfig)
	if err == nil {
		t.Error("Expected validation error for negative batch size")
	}

	// Test invalid buffer size
	invalidConfig = config.GetDefaultConfig()
	invalidConfig.Performance.MaxBufferSize = 0

	err = manager.UpdateConfig(invalidConfig)
	if err == nil {
		t.Error("Expected validation error for zero buffer size")
	}
}

func TestConfigWatcher(t *testing.T) {
	manager := config.NewManager()

	// Create a mock watcher
	watcher := &MockConfigWatcher{
		changes: make(chan bool, 1),
	}

	manager.AddWatcher(watcher)

	// Update configuration
	newConfig := config.GetDefaultConfig()
	newConfig.App.Debug = true

	err := manager.UpdateConfig(newConfig)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	// Check if watcher was notified
	select {
	case <-watcher.changes:
		// Success - watcher was notified
	case <-time.After(100 * time.Millisecond):
		t.Error("Watcher was not notified of config change")
	}

	// Remove watcher
	manager.RemoveWatcher(watcher)

	// Update again - watcher should not be notified
	newConfig.App.Version = "2.0.0"
	err = manager.UpdateConfig(newConfig)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	select {
	case <-watcher.changes:
		t.Error("Watcher should not be notified after removal")
	case <-time.After(50 * time.Millisecond):
		// Success - watcher was not notified
	}
}

func TestSaveConfig(t *testing.T) {
	manager := config.NewManager()

	// Load default config
	_, err := manager.LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	// Save to temporary file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "saved_config.yaml")

	err = manager.SaveConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Load saved config and verify
	newManager := config.NewManager()
	loadedConfig, err := newManager.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if loadedConfig.App.Name != "cipgram" {
		t.Errorf("Expected app name 'cipgram', got %s", loadedConfig.App.Name)
	}
}

func TestGetConfig(t *testing.T) {
	manager := config.NewManager()

	// Get config before loading (should return default)
	cfg1 := manager.GetConfig()
	if cfg1 == nil {
		t.Fatal("Expected default config")
	}

	// Load specific config
	_, err := manager.LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Get config after loading
	cfg2 := manager.GetConfig()
	if cfg2 == nil {
		t.Fatal("Expected loaded config")
	}

	// Verify configs are independent copies
	cfg1.App.Name = "modified"
	cfg3 := manager.GetConfig()
	if cfg3.App.Name == "modified" {
		t.Error("Config should be independent copy")
	}
}

// MockConfigWatcher implements ConfigWatcher for testing
type MockConfigWatcher struct {
	changes chan bool
}

func (m *MockConfigWatcher) OnConfigChanged(oldConfig, newConfig *config.Config) error {
	select {
	case m.changes <- true:
	default:
	}
	return nil
}

func TestConfigPrecedence(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "precedence_config.yaml")

	configContent := `
app:
  name: "file-cipgram"
  debug: false

performance:
  batch_size: 1500
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Set environment variable that should override file
	os.Setenv("CIPGRAM_APP_NAME", "env-cipgram")
	defer os.Unsetenv("CIPGRAM_APP_NAME")

	os.Setenv("CIPGRAM_APP_DEBUG", "true")
	defer os.Unsetenv("CIPGRAM_APP_DEBUG")

	// Load configuration
	manager := config.NewManager()
	cfg, err := manager.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Environment should override file
	if cfg.App.Name != "env-cipgram" {
		t.Errorf("Expected env override 'env-cipgram', got %s", cfg.App.Name)
	}

	if cfg.App.Debug != true {
		t.Errorf("Expected env override debug=true, got %v", cfg.App.Debug)
	}

	// File should override defaults
	if cfg.Performance.BatchSize != 1500 {
		t.Errorf("Expected file override batch_size=1500, got %d", cfg.Performance.BatchSize)
	}
}
