package profiling_test

import (
	"context"
	"os"
	"testing"
	"time"

	"cipgram/pkg/pcap/profiling"
)

func TestNewMemoryProfiler(t *testing.T) {
	profiler := profiling.NewMemoryProfiler(nil)
	if profiler == nil {
		t.Fatal("Expected profiler to be created")
	}
}

func TestMemoryProfiler_StartStop(t *testing.T) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:         false, // Disable HTTP server for testing
		MonitorInterval:          100 * time.Millisecond,
		EnableAllocationTracking: false,
		GCThreshold:              100,
		MemoryAlertThreshold:     500,
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test start
	err := profiler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}

	// Wait a bit for monitoring to start
	time.Sleep(200 * time.Millisecond)

	// Test double start (should fail)
	err = profiler.Start(ctx)
	if err == nil {
		t.Error("Expected error when starting already running profiler")
	}

	// Test stop
	err = profiler.Stop()
	if err != nil {
		t.Fatalf("Failed to stop profiler: %v", err)
	}

	// Test double stop (should fail)
	err = profiler.Stop()
	if err == nil {
		t.Error("Expected error when stopping already stopped profiler")
	}
}

func TestMemoryProfiler_GetStats(t *testing.T) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:         false,
		MonitorInterval:          50 * time.Millisecond,
		EnableAllocationTracking: false,
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := profiler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer profiler.Stop()

	// Wait for some monitoring cycles
	time.Sleep(150 * time.Millisecond)

	stats := profiler.GetStats()

	// Check that stats are populated
	if stats.AllocBytes == 0 {
		t.Error("Expected non-zero allocated bytes")
	}

	if stats.SysBytes == 0 {
		t.Error("Expected non-zero system bytes")
	}

	if stats.LastUpdate.IsZero() {
		t.Error("Expected last update time to be set")
	}
}

func TestMemoryProfiler_TakeHeapProfile(t *testing.T) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:   false,
		EnableFileProfiles: true,
		ProfileDir:         "./test_profiles",
		MonitorInterval:    time.Second,
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := profiler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer profiler.Stop()

	// Take heap profile
	filename := "./test_profiles/test_heap.prof"
	err = profiler.TakeHeapProfile(filename)
	if err != nil {
		t.Fatalf("Failed to take heap profile: %v", err)
	}

	// Check that file was created
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Error("Expected heap profile file to be created")
	}

	// Cleanup
	os.RemoveAll("./test_profiles")
}

func TestMemoryProfiler_TakeCPUProfile(t *testing.T) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:   false,
		EnableFileProfiles: true,
		ProfileDir:         "./test_profiles",
		MonitorInterval:    time.Second,
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := profiler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer profiler.Stop()

	// Take CPU profile
	filename := "./test_profiles/test_cpu.prof"
	duration := 100 * time.Millisecond

	err = profiler.TakeCPUProfile(filename, duration)
	if err != nil {
		t.Fatalf("Failed to take CPU profile: %v", err)
	}

	// Check that file was created
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Error("Expected CPU profile file to be created")
	}

	// Cleanup
	os.RemoveAll("./test_profiles")
}

func TestMemoryProfiler_MemoryMonitoring(t *testing.T) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:         false,
		MonitorInterval:          50 * time.Millisecond,
		EnableAllocationTracking: false,
		GCThreshold:              1,    // Very low threshold to trigger GC
		MemoryAlertThreshold:     1000, // High threshold to avoid alerts
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := profiler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer profiler.Stop()

	// Allocate some memory to trigger monitoring
	data := make([][]byte, 1000)
	for i := range data {
		data[i] = make([]byte, 1024)
	}

	// Wait for monitoring cycles
	time.Sleep(200 * time.Millisecond)

	stats := profiler.GetStats()

	// Check that monitoring detected the allocations
	if stats.TotalAllocBytes == 0 {
		t.Error("Expected non-zero total allocated bytes")
	}

	if stats.NumGC == 0 {
		t.Error("Expected at least one GC cycle")
	}

	// Keep reference to data to prevent premature GC
	_ = data
}

func TestAllocationTracker(t *testing.T) {
	tracker := profiling.NewAllocationTracker(true)
	if tracker == nil {
		t.Fatal("Expected tracker to be created")
	}

	// Test with disabled tracker
	disabledTracker := profiling.NewAllocationTracker(false)
	hotspots := disabledTracker.GetTopAllocators(5)
	if len(hotspots) != 0 {
		t.Error("Expected no hotspots from disabled tracker")
	}
}

func TestGetDefaultProfilerConfig(t *testing.T) {
	config := profiling.GetDefaultProfilerConfig()

	if config == nil {
		t.Fatal("Expected config to be created")
	}

	if config.HTTPAddr == "" {
		t.Error("Expected HTTP address to be set")
	}

	if config.MonitorInterval <= 0 {
		t.Error("Expected positive monitor interval")
	}

	if config.GCThreshold <= 0 {
		t.Error("Expected positive GC threshold")
	}

	if config.MemoryAlertThreshold <= 0 {
		t.Error("Expected positive memory alert threshold")
	}
}

func TestMemoryProfiler_PrintReport(t *testing.T) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:         false,
		MonitorInterval:          50 * time.Millisecond,
		EnableAllocationTracking: false,
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := profiler.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer profiler.Stop()

	// Wait for some monitoring
	time.Sleep(100 * time.Millisecond)

	// This should not panic
	profiler.PrintMemoryReport()
}

// Benchmark tests
func BenchmarkMemoryProfiler_GetStats(b *testing.B) {
	config := &profiling.ProfilerConfig{
		EnableHTTPServer:         false,
		MonitorInterval:          time.Second, // Slow monitoring for benchmark
		EnableAllocationTracking: false,
	}

	profiler := profiling.NewMemoryProfiler(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	profiler.Start(ctx)
	defer profiler.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profiler.GetStats()
	}
}

func BenchmarkAllocationTracker_GetTopAllocators(b *testing.B) {
	tracker := profiling.NewAllocationTracker(true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.GetTopAllocators(10)
	}
}
