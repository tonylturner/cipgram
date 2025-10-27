// Package config provides configuration file watching and hot-reloading
package config

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"cipgram/pkg/logging"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher watches configuration files for changes and triggers reloads
type FileWatcher struct {
	manager    *Manager
	watcher    *fsnotify.Watcher
	logger     *logging.Logger
	configPath string

	// Debouncing
	debounceDelay time.Duration
	lastEvent     time.Time
}

// NewFileWatcher creates a new configuration file watcher
func NewFileWatcher(manager *Manager, configPath string) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	fw := &FileWatcher{
		manager:       manager,
		watcher:       watcher,
		logger:        logging.NewLogger("config-watcher", logging.INFO, false),
		configPath:    configPath,
		debounceDelay: 500 * time.Millisecond, // Debounce file events
	}

	return fw, nil
}

// Start starts watching the configuration file for changes
func (fw *FileWatcher) Start(ctx context.Context) error {
	if fw.configPath == "" {
		fw.logger.Info("No config file to watch", nil)
		return nil
	}

	// Watch the directory containing the config file
	configDir := filepath.Dir(fw.configPath)
	if err := fw.watcher.Add(configDir); err != nil {
		return err
	}

	fw.logger.Info("Started watching config file", map[string]interface{}{
		"config_path": fw.configPath,
		"config_dir":  configDir,
	})

	go fw.watchLoop(ctx)

	return nil
}

// Stop stops watching the configuration file
func (fw *FileWatcher) Stop() error {
	if fw.watcher != nil {
		return fw.watcher.Close()
	}
	return nil
}

// watchLoop runs the file watching loop
func (fw *FileWatcher) watchLoop(ctx context.Context) {
	defer fw.watcher.Close()

	for {
		select {
		case <-ctx.Done():
			fw.logger.Info("Config watcher stopped", nil)
			return

		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}

			fw.handleFileEvent(event)

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}

			fw.logger.Error("Config watcher error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
}

// handleFileEvent handles file system events
func (fw *FileWatcher) handleFileEvent(event fsnotify.Event) {
	// Only handle events for our config file
	if event.Name != fw.configPath {
		return
	}

	// Debounce events to avoid multiple reloads for rapid file changes
	now := time.Now()
	if now.Sub(fw.lastEvent) < fw.debounceDelay {
		return
	}
	fw.lastEvent = now

	// Handle different event types
	switch {
	case event.Op&fsnotify.Write == fsnotify.Write:
		fw.logger.Info("Config file modified, reloading", map[string]interface{}{
			"config_path": event.Name,
		})
		fw.reloadConfig()

	case event.Op&fsnotify.Create == fsnotify.Create:
		fw.logger.Info("Config file created, reloading", map[string]interface{}{
			"config_path": event.Name,
		})
		fw.reloadConfig()

	case event.Op&fsnotify.Remove == fsnotify.Remove:
		fw.logger.Warn("Config file removed", map[string]interface{}{
			"config_path": event.Name,
		})

	case event.Op&fsnotify.Rename == fsnotify.Rename:
		fw.logger.Info("Config file renamed", map[string]interface{}{
			"config_path": event.Name,
		})
	}
}

// reloadConfig reloads the configuration from file
func (fw *FileWatcher) reloadConfig() {
	// Load new configuration
	newConfig, err := fw.manager.LoadConfig(fw.configPath)
	if err != nil {
		fw.logger.Error("Failed to reload config", map[string]interface{}{
			"error":       err.Error(),
			"config_path": fw.configPath,
		})
		return
	}

	// Update the manager's configuration
	if err := fw.manager.UpdateConfig(newConfig); err != nil {
		fw.logger.Error("Failed to update config", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	fw.logger.Info("Configuration reloaded successfully", map[string]interface{}{
		"config_path": fw.configPath,
	})
}

// ConfigValidator provides validation for configuration changes
type ConfigValidator struct {
	logger *logging.Logger
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		logger: logging.NewLogger("config-validator", logging.INFO, false),
	}
}

// ValidateChange validates a configuration change
func (cv *ConfigValidator) ValidateChange(oldConfig, newConfig *Config) error {
	if oldConfig == nil || newConfig == nil {
		return nil // Skip validation if either config is nil
	}

	// Validate critical changes that might affect running operations
	if err := cv.validatePerformanceChanges(oldConfig, newConfig); err != nil {
		return err
	}

	if err := cv.validateProfilingChanges(oldConfig, newConfig); err != nil {
		return err
	}

	if err := cv.validateObservabilityChanges(oldConfig, newConfig); err != nil {
		return err
	}

	cv.logger.Info("Configuration change validation passed", nil)
	return nil
}

// validatePerformanceChanges validates performance configuration changes
func (cv *ConfigValidator) validatePerformanceChanges(oldConfig, newConfig *Config) error {
	old := &oldConfig.Performance
	new := &newConfig.Performance

	// Warn about changes that require restart
	if old.EnableMemoryPooling != new.EnableMemoryPooling {
		cv.logger.Warn("Memory pooling change requires restart to take full effect", nil)
	}

	if old.PoolPreallocation != new.PoolPreallocation {
		cv.logger.Warn("Pool preallocation change requires restart to take full effect", nil)
	}

	// Validate new values
	if new.BatchSize <= 0 {
		return fmt.Errorf("batch size must be positive, got %d", new.BatchSize)
	}

	if new.MaxBufferSize <= 0 {
		return fmt.Errorf("max buffer size must be positive, got %d", new.MaxBufferSize)
	}

	return nil
}

// validateProfilingChanges validates profiling configuration changes
func (cv *ConfigValidator) validateProfilingChanges(oldConfig, newConfig *Config) error {
	old := &oldConfig.Profiling
	new := &newConfig.Profiling

	// Validate HTTP server settings
	if new.HTTPServer.Enabled && new.HTTPServer.Port <= 0 {
		return fmt.Errorf("profiling HTTP port must be positive, got %d", new.HTTPServer.Port)
	}

	// Log significant changes
	if old.Enabled != new.Enabled {
		if new.Enabled {
			cv.logger.Info("Profiling will be enabled", nil)
		} else {
			cv.logger.Info("Profiling will be disabled", nil)
		}
	}

	return nil
}

// validateObservabilityChanges validates observability configuration changes
func (cv *ConfigValidator) validateObservabilityChanges(oldConfig, newConfig *Config) error {
	old := &oldConfig.Observability
	new := &newConfig.Observability

	// Validate metrics settings
	if new.Metrics.Enabled && new.Metrics.Port <= 0 {
		return fmt.Errorf("metrics port must be positive, got %d", new.Metrics.Port)
	}

	// Validate health check settings
	if new.HealthCheck.Enabled && new.HealthCheck.Port <= 0 {
		return fmt.Errorf("health check port must be positive, got %d", new.HealthCheck.Port)
	}

	// Log significant changes
	if old.Metrics.Enabled != new.Metrics.Enabled {
		if new.Metrics.Enabled {
			cv.logger.Info("Metrics will be enabled", map[string]interface{}{
				"address": new.Metrics.Address,
				"port":    new.Metrics.Port,
			})
		} else {
			cv.logger.Info("Metrics will be disabled", nil)
		}
	}

	return nil
}
