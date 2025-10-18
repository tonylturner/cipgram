package optimization_test

import (
	"testing"

	"cipgram/pkg/pcap/optimization"
)

func TestNewStringOptimizer(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()
	if optimizer == nil {
		t.Fatal("Expected optimizer to be created")
	}

	stats := optimizer.GetStats()
	if stats.CacheSize == 0 {
		t.Error("Expected cache to be pre-populated")
	}
}

func TestStringOptimizer_BuildString(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Test empty
	result := optimizer.BuildString()
	if result != "" {
		t.Errorf("Expected empty string, got %q", result)
	}

	// Test single part
	result = optimizer.BuildString("hello")
	if result != "hello" {
		t.Errorf("Expected 'hello', got %q", result)
	}

	// Test multiple parts
	result = optimizer.BuildString("hello", " ", "world", "!")
	if result != "hello world!" {
		t.Errorf("Expected 'hello world!', got %q", result)
	}
}

func TestStringOptimizer_InternString(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Test interning the same string multiple times
	s1 := optimizer.InternString("test_protocol")
	s2 := optimizer.InternString("test_protocol")

	if s1 != s2 {
		t.Error("Expected interned strings to be identical")
	}

	stats := optimizer.GetStats()
	if stats.CacheHits == 0 {
		t.Error("Expected cache hits from string interning")
	}
}

func TestStringOptimizer_OptimizedJoin(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Test empty slice
	result := optimizer.OptimizedJoin([]string{}, ",")
	if result != "" {
		t.Errorf("Expected empty string, got %q", result)
	}

	// Test single element
	result = optimizer.OptimizedJoin([]string{"hello"}, ",")
	if result != "hello" {
		t.Errorf("Expected 'hello', got %q", result)
	}

	// Test multiple elements
	result = optimizer.OptimizedJoin([]string{"a", "b", "c"}, ",")
	if result != "a,b,c" {
		t.Errorf("Expected 'a,b,c', got %q", result)
	}
}

func TestStringOptimizer_FormatProtocolKey(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	key := optimizer.FormatProtocolKey("TCP", "192.168.1.1", "192.168.1.2", 80, 443)
	expected := "TCP:192.168.1.1:192.168.1.2:80:443"

	if key != expected {
		t.Errorf("Expected %q, got %q", expected, key)
	}

	// Test that the same key is interned
	key2 := optimizer.FormatProtocolKey("TCP", "192.168.1.1", "192.168.1.2", 80, 443)
	if key != key2 {
		t.Error("Expected identical interned keys")
	}
}

func TestStringOptimizer_FormatAssetKey(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Test with MAC
	key := optimizer.FormatAssetKey("192.168.1.1", "aa:bb:cc:dd:ee:ff")
	expected := "192.168.1.1:aa:bb:cc:dd:ee:ff"

	if key != expected {
		t.Errorf("Expected %q, got %q", expected, key)
	}

	// Test without MAC
	key = optimizer.FormatAssetKey("192.168.1.1", "")
	expected = "192.168.1.1"

	if key != expected {
		t.Errorf("Expected %q, got %q", expected, key)
	}
}

func TestStringOptimizer_BuilderPool(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Get and return builders to test pooling
	builder1 := optimizer.GetBuilder()
	builder1.WriteString("test")
	optimizer.PutBuilder(builder1)

	builder2 := optimizer.GetBuilder()
	if builder2.String() != "" {
		t.Error("Expected builder to be reset when retrieved from pool")
	}
	optimizer.PutBuilder(builder2)

	stats := optimizer.GetStats()
	if stats.BuilderHits == 0 {
		t.Error("Expected builder hits from pool usage")
	}
}

func TestStringOptimizer_PrePopulatedStrings(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Test that common protocols are pre-populated
	commonProtocols := []string{"TCP", "UDP", "HTTP", "HTTPS", "DNS", "EtherNet/IP"}

	for _, protocol := range commonProtocols {
		interned := optimizer.InternString(protocol)
		if interned != protocol {
			t.Errorf("Expected pre-populated protocol %q to be interned", protocol)
		}
	}

	stats := optimizer.GetStats()
	if stats.CacheHits == 0 {
		t.Error("Expected cache hits from pre-populated strings")
	}
}

func TestStringOptimizer_ClearCache(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Add some strings to cache
	optimizer.InternString("custom_protocol")

	initialStats := optimizer.GetStats()
	if initialStats.CacheSize == 0 {
		t.Error("Expected cache to have entries")
	}

	// Clear cache
	optimizer.ClearCache()

	stats := optimizer.GetStats()
	// Cache should still have pre-populated strings
	if stats.CacheSize == 0 {
		t.Error("Expected cache to have pre-populated strings after clear")
	}

	// Should be smaller than before (custom string removed)
	if stats.CacheSize >= initialStats.CacheSize {
		t.Error("Expected cache size to be reduced after clear")
	}
}

func TestStringOptimizer_Stats(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Perform some operations
	optimizer.BuildString("test", "string")
	optimizer.InternString("test_protocol")
	optimizer.InternString("test_protocol") // Should be a cache hit

	stats := optimizer.GetStats()

	if stats.BuilderHits == 0 {
		t.Error("Expected builder hits")
	}

	if stats.CacheHits == 0 {
		t.Error("Expected cache hits")
	}

	if stats.CacheHitRate < 0 || stats.CacheHitRate > 1 {
		t.Errorf("Expected hit rate between 0 and 1, got %f", stats.CacheHitRate)
	}
}

func TestStringOptimizer_ConcurrentAccess(t *testing.T) {
	optimizer := optimization.NewStringOptimizer()

	// Test concurrent access doesn't panic
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				protocol := optimizer.InternString("TCP")
				key := optimizer.FormatProtocolKey(protocol, "192.168.1.1", "192.168.1.2", 80, 443)
				builder := optimizer.GetBuilder()
				builder.WriteString(key)
				optimizer.PutBuilder(builder)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := optimizer.GetStats()
	if stats.BuilderHits == 0 {
		t.Error("Expected builder hits from concurrent access")
	}
}

// Benchmark tests
func BenchmarkStringOptimizer_BuildString(b *testing.B) {
	optimizer := optimization.NewStringOptimizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		optimizer.BuildString("protocol", ":", "192.168.1.1", ":", "80")
	}
}

func BenchmarkStringOptimizer_StandardConcat(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = "protocol" + ":" + "192.168.1.1" + ":" + "80"
	}
}

func BenchmarkStringOptimizer_InternString(b *testing.B) {
	optimizer := optimization.NewStringOptimizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		optimizer.InternString("TCP")
	}
}

func BenchmarkStringOptimizer_FormatProtocolKey(b *testing.B) {
	optimizer := optimization.NewStringOptimizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		optimizer.FormatProtocolKey("TCP", "192.168.1.1", "192.168.1.2", 80, 443)
	}
}
