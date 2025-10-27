// Package cli provides profiling command utilities
package cli

import (
	"fmt"
	"time"

	"cipgram/pkg/pcap/profiling"
)

// ProfilingCommands provides CLI commands for memory profiling
type ProfilingCommands struct {
	profiler *profiling.MemoryProfiler
}

// NewProfilingCommands creates a new profiling commands handler
func NewProfilingCommands() *ProfilingCommands {
	return &ProfilingCommands{}
}

// EnableProfiling enables memory profiling with HTTP server
func (pc *ProfilingCommands) EnableProfiling(httpAddr string) error {
	if pc.profiler != nil {
		return fmt.Errorf("profiling is already enabled")
	}

	config := &profiling.ProfilerConfig{
		EnableHTTPServer:         true,
		HTTPAddr:                 httpAddr,
		EnableFileProfiles:       true,
		ProfileDir:               "./profiles",
		MonitorInterval:          10 * time.Second,
		EnableAllocationTracking: false,      // Disabled for performance
		GCThreshold:              200,        // 200MB
		MemoryAlertThreshold:     1000,       // 1GB
		MemProfileRate:           512 * 1024, // Sample every 512KB
		BlockProfileRate:         1,
		MutexProfileFraction:     1,
	}

	pc.profiler = profiling.NewMemoryProfiler(config)

	fmt.Printf("Memory profiling enabled!\n")
	fmt.Printf("HTTP server: http://%s/debug/pprof/\n", httpAddr)
	fmt.Printf("Profile directory: %s\n", config.ProfileDir)
	fmt.Printf("Monitor interval: %s\n", config.MonitorInterval)

	return nil
}

// GetMemoryStats returns current memory statistics
func (pc *ProfilingCommands) GetMemoryStats() (*profiling.MemoryStats, error) {
	if pc.profiler == nil {
		return nil, fmt.Errorf("profiling is not enabled")
	}

	stats := pc.profiler.GetStats()
	return &stats, nil
}

// TakeHeapProfile takes a heap profile
func (pc *ProfilingCommands) TakeHeapProfile(filename string) error {
	if pc.profiler == nil {
		return fmt.Errorf("profiling is not enabled")
	}

	return pc.profiler.TakeHeapProfile(filename)
}

// TakeCPUProfile takes a CPU profile
func (pc *ProfilingCommands) TakeCPUProfile(filename string, duration time.Duration) error {
	if pc.profiler == nil {
		return fmt.Errorf("profiling is not enabled")
	}

	return pc.profiler.TakeCPUProfile(filename, duration)
}

// PrintMemoryReport prints a detailed memory report
func (pc *ProfilingCommands) PrintMemoryReport() error {
	if pc.profiler == nil {
		return fmt.Errorf("profiling is not enabled")
	}

	pc.profiler.PrintMemoryReport()
	return nil
}

// IsEnabled returns whether profiling is enabled
func (pc *ProfilingCommands) IsEnabled() bool {
	return pc.profiler != nil
}
