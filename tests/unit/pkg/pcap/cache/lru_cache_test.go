package cache_test

import (
	"fmt"
	"testing"
	"time"

	"cipgram/pkg/pcap/cache"
)

func TestNewLRUCache(t *testing.T) {
	cache := cache.NewLRUCache(10, time.Minute)
	if cache == nil {
		t.Fatal("Expected cache to be created")
	}

	if cache.Size() != 0 {
		t.Errorf("Expected empty cache, got size %d", cache.Size())
	}
}

func TestLRUCache_PutAndGet(t *testing.T) {
	cache := cache.NewLRUCache(3, time.Minute)

	// Test basic put and get
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	if value, found := cache.Get("key1"); !found || value != "value1" {
		t.Errorf("Expected to find key1 with value1, got %v, %v", value, found)
	}

	if value, found := cache.Get("key2"); !found || value != "value2" {
		t.Errorf("Expected to find key2 with value2, got %v, %v", value, found)
	}

	if _, found := cache.Get("nonexistent"); found {
		t.Error("Expected not to find nonexistent key")
	}
}

func TestLRUCache_Capacity(t *testing.T) {
	cache := cache.NewLRUCache(2, time.Minute)

	// Fill cache to capacity
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	if cache.Size() != 2 {
		t.Errorf("Expected size 2, got %d", cache.Size())
	}

	// Add one more - should evict least recently used
	cache.Put("key3", "value3")

	if cache.Size() != 2 {
		t.Errorf("Expected size to remain 2, got %d", cache.Size())
	}

	// key1 should be evicted (least recently used)
	if _, found := cache.Get("key1"); found {
		t.Error("Expected key1 to be evicted")
	}

	// key2 and key3 should still exist
	if _, found := cache.Get("key2"); !found {
		t.Error("Expected key2 to still exist")
	}

	if _, found := cache.Get("key3"); !found {
		t.Error("Expected key3 to exist")
	}
}

func TestLRUCache_LRUOrdering(t *testing.T) {
	cache := cache.NewLRUCache(2, time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	// Access key1 to make it most recently used
	cache.Get("key1")

	// Add key3 - should evict key2 (now least recently used)
	cache.Put("key3", "value3")

	if _, found := cache.Get("key2"); found {
		t.Error("Expected key2 to be evicted")
	}

	if _, found := cache.Get("key1"); !found {
		t.Error("Expected key1 to still exist")
	}

	if _, found := cache.Get("key3"); !found {
		t.Error("Expected key3 to exist")
	}
}

func TestLRUCache_TTL(t *testing.T) {
	cache := cache.NewLRUCache(10, 50*time.Millisecond)

	cache.Put("key1", "value1")

	// Should exist immediately
	if _, found := cache.Get("key1"); !found {
		t.Error("Expected key1 to exist immediately")
	}

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Should be expired now
	if _, found := cache.Get("key1"); found {
		t.Error("Expected key1 to be expired")
	}
}

func TestLRUCache_Update(t *testing.T) {
	cache := cache.NewLRUCache(10, time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key1", "value2") // Update

	if value, found := cache.Get("key1"); !found || value != "value2" {
		t.Errorf("Expected updated value2, got %v", value)
	}

	if cache.Size() != 1 {
		t.Errorf("Expected size 1 after update, got %d", cache.Size())
	}
}

func TestLRUCache_Delete(t *testing.T) {
	cache := cache.NewLRUCache(10, time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	cache.Delete("key1")

	if _, found := cache.Get("key1"); found {
		t.Error("Expected key1 to be deleted")
	}

	if _, found := cache.Get("key2"); !found {
		t.Error("Expected key2 to still exist")
	}

	if cache.Size() != 1 {
		t.Errorf("Expected size 1 after delete, got %d", cache.Size())
	}
}

func TestLRUCache_Clear(t *testing.T) {
	cache := cache.NewLRUCache(10, time.Minute)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}

	if _, found := cache.Get("key1"); found {
		t.Error("Expected no keys after clear")
	}
}

func TestLRUCache_Stats(t *testing.T) {
	cache := cache.NewLRUCache(10, time.Minute)

	// Initial stats
	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("Expected 0 hits/misses initially, got %d/%d", stats.Hits, stats.Misses)
	}

	// Add and access items
	cache.Put("key1", "value1")
	cache.Get("key1") // Hit
	cache.Get("key2") // Miss

	stats = cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
	if stats.HitRate != 0.5 {
		t.Errorf("Expected hit rate 0.5, got %f", stats.HitRate)
	}
}

func TestLRUCache_CleanupExpired(t *testing.T) {
	cache := cache.NewLRUCache(10, 50*time.Millisecond)

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Add a fresh entry
	cache.Put("key3", "value3")

	// Cleanup expired entries
	removed := cache.CleanupExpired()

	if removed != 2 {
		t.Errorf("Expected 2 expired entries removed, got %d", removed)
	}

	if cache.Size() != 1 {
		t.Errorf("Expected size 1 after cleanup, got %d", cache.Size())
	}

	if _, found := cache.Get("key3"); !found {
		t.Error("Expected key3 to still exist")
	}
}

func TestLRUCache_ConcurrentAccess(t *testing.T) {
	cache := cache.NewLRUCache(100, time.Minute)

	// Test concurrent access doesn't panic
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key_%d_%d", id, j)
				cache.Put(key, fmt.Sprintf("value_%d_%d", id, j))
				cache.Get(key)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have some entries
	if cache.Size() == 0 {
		t.Error("Expected cache to have entries after concurrent access")
	}
}

func TestLRUCache_EvictionStats(t *testing.T) {
	cache := cache.NewLRUCache(2, time.Minute)

	// Fill beyond capacity to trigger evictions
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3") // Should evict key1

	stats := cache.Stats()
	if stats.Evicts != 1 {
		t.Errorf("Expected 1 eviction, got %d", stats.Evicts)
	}
}
