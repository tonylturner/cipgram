// Package config provides centralized configuration management for CIPgram
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"cipgram/pkg/errors"
	"cipgram/pkg/logging"

	"gopkg.in/yaml.v3"
)

// Manager handles centralized configuration for the entire application
type Manager struct {
	config     *Config
	configPath string
	logger     *logging.Logger
	mutex      sync.RWMutex

	// Hot-reloading
	watchers   []ConfigWatcher
	stopWatch  chan struct{}
	watchMutex sync.RWMutex
}

// ConfigWatcher defines the interface for configuration change notifications
type ConfigWatcher interface {
	OnConfigChanged(oldConfig, newConfig *Config) error
}

// Config represents the unified application configuration
type Config struct {
	// Application metadata
	App AppConfig `yaml:"app" json:"app"`

	// PCAP processing configuration
	PCAP PCAPConfig `yaml:"pcap" json:"pcap"`

	// Performance optimization configuration
	Performance PerformanceConfig `yaml:"performance" json:"performance"`

	// Memory profiling configuration
	Profiling ProfilingConfig `yaml:"profiling" json:"profiling"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging" json:"logging"`

	// Observability configuration
	Observability ObservabilityConfig `yaml:"observability" json:"observability"`
}

// AppConfig contains application-level settings
type AppConfig struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Environment string `yaml:"environment" json:"environment"` // dev, staging, prod
	Debug       bool   `yaml:"debug" json:"debug"`
}

// PCAPConfig contains PCAP processing settings
type PCAPConfig struct {
	// Processing options
	ShowHostnames      bool `yaml:"show_hostnames" json:"show_hostnames"`
	EnableVendorLookup bool `yaml:"enable_vendor_lookup" json:"enable_vendor_lookup"`
	EnableDNSLookup    bool `yaml:"enable_dns_lookup" json:"enable_dns_lookup"`
	FastMode           bool `yaml:"fast_mode" json:"fast_mode"`
	HideUnknown        bool `yaml:"hide_unknown" json:"hide_unknown"`
	MaxNodes           int  `yaml:"max_nodes" json:"max_nodes"`

	// Detection configuration
	Detection DetectionConfig `yaml:"detection" json:"detection"`

	// Output configuration
	Output OutputConfig `yaml:"output" json:"output"`
}

// DetectionConfig contains protocol detection settings
type DetectionConfig struct {
	EnablePortBased     bool     `yaml:"enable_port_based" json:"enable_port_based"`
	EnableDPI           bool     `yaml:"enable_dpi" json:"enable_dpi"`
	EnableHeuristic     bool     `yaml:"enable_heuristic" json:"enable_heuristic"`
	ConfidenceThreshold float32  `yaml:"confidence_threshold" json:"confidence_threshold"`
	EnabledProtocols    []string `yaml:"enabled_protocols" json:"enabled_protocols"`

	// DPI-specific settings
	DPI DPIConfig `yaml:"dpi" json:"dpi"`
}

// DPIConfig contains Deep Packet Inspection settings
type DPIConfig struct {
	EnableHTTP       bool `yaml:"enable_http" json:"enable_http"`
	EnableTLS        bool `yaml:"enable_tls" json:"enable_tls"`
	EnableDNS        bool `yaml:"enable_dns" json:"enable_dns"`
	EnableIndustrial bool `yaml:"enable_industrial" json:"enable_industrial"`
	EnableModern     bool `yaml:"enable_modern" json:"enable_modern"`
}

// OutputConfig contains output generation settings
type OutputConfig struct {
	GenerateDiagrams bool     `yaml:"generate_diagrams" json:"generate_diagrams"`
	OutputFormats    []string `yaml:"output_formats" json:"output_formats"` // dot, svg, png, json
	DiagramThemes    []string `yaml:"diagram_themes" json:"diagram_themes"`
	FastModeEnabled  bool     `yaml:"fast_mode_enabled" json:"fast_mode_enabled"`
}

// PerformanceConfig contains performance optimization settings
type PerformanceConfig struct {
	// Memory management
	EnableMemoryPooling  bool `yaml:"enable_memory_pooling" json:"enable_memory_pooling"`
	EnablePacketBatching bool `yaml:"enable_packet_batching" json:"enable_packet_batching"`
	EnableZeroCopy       bool `yaml:"enable_zero_copy" json:"enable_zero_copy"`
	BatchSize            int  `yaml:"batch_size" json:"batch_size"`
	MaxBufferSize        int  `yaml:"max_buffer_size" json:"max_buffer_size"`
	PoolPreallocation    int  `yaml:"pool_preallocation" json:"pool_preallocation"`

	// Optimization strategy
	OptimizationStrategy  string        `yaml:"optimization_strategy" json:"optimization_strategy"` // minimal, balanced, aggressive, custom
	GCOptimization        bool          `yaml:"gc_optimization" json:"gc_optimization"`
	MemoryProfileInterval time.Duration `yaml:"memory_profile_interval" json:"memory_profile_interval"`

	// Adaptive optimization
	EnableAdaptiveOptimization bool `yaml:"enable_adaptive_optimization" json:"enable_adaptive_optimization"`
}

// ProfilingConfig contains memory profiling settings
type ProfilingConfig struct {
	Enabled      bool               `yaml:"enabled" json:"enabled"`
	HTTPServer   HTTPServerConfig   `yaml:"http_server" json:"http_server"`
	FileProfiles FileProfilesConfig `yaml:"file_profiles" json:"file_profiles"`
	Monitoring   MonitoringConfig   `yaml:"monitoring" json:"monitoring"`
	Thresholds   ThresholdsConfig   `yaml:"thresholds" json:"thresholds"`
	Sampling     SamplingConfig     `yaml:"sampling" json:"sampling"`
}

// HTTPServerConfig contains HTTP profiling server settings
type HTTPServerConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
}

// FileProfilesConfig contains file-based profiling settings
type FileProfilesConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Directory string `yaml:"directory" json:"directory"`
	AutoSave  bool   `yaml:"auto_save" json:"auto_save"`
	MaxFiles  int    `yaml:"max_files" json:"max_files"`
}

// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	Interval                 time.Duration `yaml:"interval" json:"interval"`
	EnableAllocationTracking bool          `yaml:"enable_allocation_tracking" json:"enable_allocation_tracking"`
}

// ThresholdsConfig contains memory threshold settings
type ThresholdsConfig struct {
	GCThresholdMB    int64 `yaml:"gc_threshold_mb" json:"gc_threshold_mb"`
	AlertThresholdMB int64 `yaml:"alert_threshold_mb" json:"alert_threshold_mb"`
}

// SamplingConfig contains profiling sampling settings
type SamplingConfig struct {
	MemProfileRate       int `yaml:"mem_profile_rate" json:"mem_profile_rate"`
	BlockProfileRate     int `yaml:"block_profile_rate" json:"block_profile_rate"`
	MutexProfileFraction int `yaml:"mutex_profile_fraction" json:"mutex_profile_fraction"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `yaml:"level" json:"level"`       // debug, info, warn, error
	Format     string `yaml:"format" json:"format"`     // json, text
	Output     string `yaml:"output" json:"output"`     // stdout, stderr, file
	File       string `yaml:"file" json:"file"`         // log file path
	MaxSize    int    `yaml:"max_size" json:"max_size"` // MB
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	MaxAge     int    `yaml:"max_age" json:"max_age"` // days
	Compress   bool   `yaml:"compress" json:"compress"`
}

// ObservabilityConfig contains monitoring and metrics settings
type ObservabilityConfig struct {
	Metrics     MetricsConfig     `yaml:"metrics" json:"metrics"`
	HealthCheck HealthCheckConfig `yaml:"health_check" json:"health_check"`
	Tracing     TracingConfig     `yaml:"tracing" json:"tracing"`
}

// MetricsConfig contains Prometheus metrics settings
type MetricsConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Address   string `yaml:"address" json:"address"`
	Port      int    `yaml:"port" json:"port"`
	Path      string `yaml:"path" json:"path"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

// HealthCheckConfig contains health check settings
type HealthCheckConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Address  string        `yaml:"address" json:"address"`
	Port     int           `yaml:"port" json:"port"`
	Path     string        `yaml:"path" json:"path"`
	Interval time.Duration `yaml:"interval" json:"interval"`
}

// TracingConfig contains distributed tracing settings
type TracingConfig struct {
	Enabled     bool    `yaml:"enabled" json:"enabled"`
	ServiceName string  `yaml:"service_name" json:"service_name"`
	Endpoint    string  `yaml:"endpoint" json:"endpoint"`
	SampleRate  float64 `yaml:"sample_rate" json:"sample_rate"`
}

// NewManager creates a new configuration manager
func NewManager() *Manager {
	return &Manager{
		logger:    logging.NewLogger("config-manager", logging.INFO, false),
		stopWatch: make(chan struct{}),
		watchers:  make([]ConfigWatcher, 0),
	}
}

// LoadConfig loads configuration from multiple sources with precedence:
// 1. CLI flags (highest priority)
// 2. Environment variables
// 3. Configuration file
// 4. Default values (lowest priority)
func (m *Manager) LoadConfig(configPath string) (*Config, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.configPath = configPath

	// Start with default configuration
	config := GetDefaultConfig()

	// Load from file if provided
	if configPath != "" {
		if err := m.loadFromFile(config, configPath); err != nil {
			return nil, errors.WrapSystem(err, errors.CodeFileNotFound, "failed to load config file").WithContext("config_path", configPath)
		}
	}

	// Override with environment variables
	if err := m.loadFromEnv(config); err != nil {
		return nil, errors.WrapSystem(err, errors.CodeInvalidConfig, "failed to load environment variables")
	}

	// Validate configuration
	if err := m.validateConfig(config); err != nil {
		return nil, errors.WrapValidation(err, errors.CodeInvalidConfig, "configuration validation failed")
	}

	m.config = config

	m.logger.Info("Configuration loaded successfully", map[string]interface{}{
		"config_path": configPath,
		"environment": config.App.Environment,
		"debug_mode":  config.App.Debug,
		"profiling":   config.Profiling.Enabled,
		"metrics":     config.Observability.Metrics.Enabled,
	})

	return config, nil
}

// GetConfig returns the current configuration (thread-safe)
func (m *Manager) GetConfig() *Config {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.config == nil {
		return GetDefaultConfig()
	}

	// Return a deep copy to prevent external modifications
	return m.copyConfig(m.config)
}

// UpdateConfig updates the configuration and notifies watchers
func (m *Manager) UpdateConfig(newConfig *Config) error {
	m.mutex.Lock()
	oldConfig := m.copyConfig(m.config)
	m.mutex.Unlock()

	// Validate new configuration
	if err := m.validateConfig(newConfig); err != nil {
		return errors.WrapValidation(err, errors.CodeInvalidConfig, "new configuration validation failed")
	}

	m.mutex.Lock()
	m.config = newConfig
	m.mutex.Unlock()

	// Notify watchers
	m.notifyWatchers(oldConfig, newConfig)

	m.logger.Info("Configuration updated", map[string]interface{}{
		"watchers_notified": len(m.watchers),
	})

	return nil
}

// SaveConfig saves the current configuration to file
func (m *Manager) SaveConfig(configPath string) error {
	m.mutex.RLock()
	config := m.copyConfig(m.config)
	m.mutex.RUnlock()

	if config == nil {
		return errors.NewValidationError(errors.CodeMissingConfig, "no configuration to save")
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.WrapSystem(err, errors.CodePermissionDenied, "failed to create config directory").WithContext("directory", dir)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return errors.WrapSystem(err, errors.CodeUnexpected, "failed to marshal configuration")
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return errors.WrapSystem(err, errors.CodeFileNotFound, "failed to write config file").WithContext("config_path", configPath)
	}

	m.logger.Info("Configuration saved", map[string]interface{}{
		"config_path": configPath,
	})

	return nil
}

// AddWatcher adds a configuration change watcher
func (m *Manager) AddWatcher(watcher ConfigWatcher) {
	m.watchMutex.Lock()
	defer m.watchMutex.Unlock()

	m.watchers = append(m.watchers, watcher)
}

// RemoveWatcher removes a configuration change watcher
func (m *Manager) RemoveWatcher(watcher ConfigWatcher) {
	m.watchMutex.Lock()
	defer m.watchMutex.Unlock()

	for i, w := range m.watchers {
		if w == watcher {
			m.watchers = append(m.watchers[:i], m.watchers[i+1:]...)
			break
		}
	}
}

// loadFromFile loads configuration from a YAML file
func (m *Manager) loadFromFile(config *Config, configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			m.logger.Info("Config file not found, using defaults", map[string]interface{}{
				"config_path": configPath,
			})
			return nil
		}
		return err
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func (m *Manager) loadFromEnv(config *Config) error {
	// Use reflection to set fields from environment variables
	return m.setFromEnv(reflect.ValueOf(config).Elem(), "CIPGRAM")
}

// setFromEnv recursively sets configuration fields from environment variables
func (m *Manager) setFromEnv(v reflect.Value, prefix string) error {
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Get YAML tag for field name
		yamlTag := fieldType.Tag.Get("yaml")
		if yamlTag == "" || yamlTag == "-" {
			continue
		}

		fieldName := strings.ToUpper(strings.ReplaceAll(yamlTag, "_", "_"))
		envKey := prefix + "_" + fieldName

		if field.Kind() == reflect.Struct {
			// Recursively handle nested structs
			if err := m.setFromEnv(field, envKey); err != nil {
				return err
			}
		} else {
			// Set field from environment variable
			if envValue := os.Getenv(envKey); envValue != "" {
				if err := m.setFieldFromString(field, envValue); err != nil {
					return fmt.Errorf("failed to set field %s from env %s: %w", fieldType.Name, envKey, err)
				}
			}
		}
	}

	return nil
}

// setFieldFromString sets a field value from a string representation
func (m *Manager) setFieldFromString(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Bool:
		if strings.ToLower(value) == "true" || value == "1" {
			field.SetBool(true)
		} else {
			field.SetBool(false)
		}
	case reflect.Int, reflect.Int32, reflect.Int64:
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			duration, err := time.ParseDuration(value)
			if err != nil {
				return err
			}
			field.SetInt(int64(duration))
		} else {
			// Handle regular integers
			var intVal int64
			if _, err := fmt.Sscanf(value, "%d", &intVal); err != nil {
				return err
			}
			field.SetInt(intVal)
		}
	case reflect.Float32, reflect.Float64:
		var floatVal float64
		if _, err := fmt.Sscanf(value, "%f", &floatVal); err != nil {
			return err
		}
		field.SetFloat(floatVal)
	case reflect.Slice:
		// Handle string slices
		if field.Type().Elem().Kind() == reflect.String {
			values := strings.Split(value, ",")
			slice := reflect.MakeSlice(field.Type(), len(values), len(values))
			for i, v := range values {
				slice.Index(i).SetString(strings.TrimSpace(v))
			}
			field.Set(slice)
		}
	}

	return nil
}

// validateConfig validates the configuration
func (m *Manager) validateConfig(config *Config) error {
	if config == nil {
		return errors.NewValidationError(errors.CodeInvalidConfig, "configuration is nil")
	}

	// Validate app config
	if config.App.Name == "" {
		return errors.NewValidationError(errors.CodeMissingRequired, "app name is required")
	}

	// Validate performance config
	if config.Performance.BatchSize <= 0 {
		return errors.NewValidationError(errors.CodeInvalidInput, "batch size must be positive").WithContext("batch_size", config.Performance.BatchSize)
	}

	if config.Performance.MaxBufferSize <= 0 {
		return errors.NewValidationError(errors.CodeInvalidInput, "max buffer size must be positive").WithContext("max_buffer_size", config.Performance.MaxBufferSize)
	}

	// Validate profiling config
	if config.Profiling.Enabled {
		if config.Profiling.HTTPServer.Enabled && config.Profiling.HTTPServer.Port <= 0 {
			return errors.NewValidationError(errors.CodeInvalidInput, "profiling HTTP port must be positive").WithContext("port", config.Profiling.HTTPServer.Port)
		}
	}

	// Validate observability config
	if config.Observability.Metrics.Enabled && config.Observability.Metrics.Port <= 0 {
		return errors.NewValidationError(errors.CodeInvalidInput, "metrics port must be positive").WithContext("port", config.Observability.Metrics.Port)
	}

	return nil
}

// copyConfig creates a deep copy of the configuration
func (m *Manager) copyConfig(config *Config) *Config {
	if config == nil {
		return nil
	}

	// Use YAML marshal/unmarshal for deep copy
	data, err := yaml.Marshal(config)
	if err != nil {
		m.logger.Error("Failed to marshal config for copying", map[string]interface{}{
			"error": err.Error(),
		})
		return config // Return original if copy fails
	}

	var copy Config
	if err := yaml.Unmarshal(data, &copy); err != nil {
		m.logger.Error("Failed to unmarshal config for copying", map[string]interface{}{
			"error": err.Error(),
		})
		return config // Return original if copy fails
	}

	return &copy
}

// notifyWatchers notifies all registered watchers of configuration changes
func (m *Manager) notifyWatchers(oldConfig, newConfig *Config) {
	m.watchMutex.RLock()
	watchers := make([]ConfigWatcher, len(m.watchers))
	copy(watchers, m.watchers)
	m.watchMutex.RUnlock()

	for _, watcher := range watchers {
		if err := watcher.OnConfigChanged(oldConfig, newConfig); err != nil {
			m.logger.Error("Config watcher failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
}

// GetDefaultConfig returns the default configuration
func GetDefaultConfig() *Config {
	return &Config{
		App: AppConfig{
			Name:        "cipgram",
			Version:     "2.0.0",
			Environment: "development",
			Debug:       false,
		},
		PCAP: PCAPConfig{
			ShowHostnames:      true,
			EnableVendorLookup: true,
			EnableDNSLookup:    false,
			FastMode:           false,
			HideUnknown:        false,
			MaxNodes:           0,
			Detection: DetectionConfig{
				EnablePortBased:     true,
				EnableDPI:           true,
				EnableHeuristic:     true,
				ConfidenceThreshold: 0.7,
				EnabledProtocols:    []string{"all"},
				DPI: DPIConfig{
					EnableHTTP:       true,
					EnableTLS:        true,
					EnableDNS:        true,
					EnableIndustrial: true,
					EnableModern:     true,
				},
			},
			Output: OutputConfig{
				GenerateDiagrams: true,
				OutputFormats:    []string{"dot", "svg", "png", "json"},
				DiagramThemes:    []string{"default"},
				FastModeEnabled:  true,
			},
		},
		Performance: PerformanceConfig{
			EnableMemoryPooling:        true,
			EnablePacketBatching:       true,
			EnableZeroCopy:             true,
			BatchSize:                  1000,
			MaxBufferSize:              65536,
			PoolPreallocation:          1000,
			OptimizationStrategy:       "adaptive",
			GCOptimization:             true,
			MemoryProfileInterval:      30 * time.Second,
			EnableAdaptiveOptimization: true,
		},
		Profiling: ProfilingConfig{
			Enabled: false,
			HTTPServer: HTTPServerConfig{
				Enabled: false,
				Address: "localhost",
				Port:    6060,
			},
			FileProfiles: FileProfilesConfig{
				Enabled:   true,
				Directory: "./profiles",
				AutoSave:  false,
				MaxFiles:  10,
			},
			Monitoring: MonitoringConfig{
				Interval:                 30 * time.Second,
				EnableAllocationTracking: false,
			},
			Thresholds: ThresholdsConfig{
				GCThresholdMB:    100,
				AlertThresholdMB: 500,
			},
			Sampling: SamplingConfig{
				MemProfileRate:       512 * 1024,
				BlockProfileRate:     1,
				MutexProfileFraction: 1,
			},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			Output:     "stdout",
			File:       "",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		},
		Observability: ObservabilityConfig{
			Metrics: MetricsConfig{
				Enabled:   false,
				Address:   "localhost",
				Port:      9090,
				Path:      "/metrics",
				Namespace: "cipgram",
			},
			HealthCheck: HealthCheckConfig{
				Enabled:  false,
				Address:  "localhost",
				Port:     8080,
				Path:     "/health",
				Interval: 30 * time.Second,
			},
			Tracing: TracingConfig{
				Enabled:     false,
				ServiceName: "cipgram",
				Endpoint:    "",
				SampleRate:  0.1,
			},
		},
	}
}
