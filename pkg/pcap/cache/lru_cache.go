// Package cache provides LRU caching functionality for PCAP processing
package cache

import (
	"container/list"
	"sync"
	"time"
)

// CacheEntry represents a cached item with TTL support
type CacheEntry struct {
	Key       string
	Value     interface{}
	ExpiresAt time.Time
	Element   *list.Element
}

// LRUCache implements a thread-safe LRU cache with TTL support
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	ttl      time.Duration
	items    map[string]*CacheEntry
	lruList  *list.List

	// Metrics
	hits   int64
	misses int64
	evicts int64
}

// NewLRUCache creates a new LRU cache with specified capacity and TTL
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[string]*CacheEntry),
		lruList:  list.New(),
	}
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.items[key]
	if !exists {
		c.misses++
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		c.removeEntry(entry)
		c.misses++
		return nil, false
	}

	// Move to front (most recently used)
	c.lruList.MoveToFront(entry.Element)
	c.hits++
	return entry.Value, true
}

// Put adds or updates a value in the cache
func (c *LRUCache) Put(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if entry, exists := c.items[key]; exists {
		// Update existing entry
		entry.Value = value
		entry.ExpiresAt = time.Now().Add(c.ttl)
		c.lruList.MoveToFront(entry.Element)
		return
	}

	// Create new entry
	entry := &CacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}

	// Add to front of list
	entry.Element = c.lruList.PushFront(entry)
	c.items[key] = entry

	// Check capacity and evict if necessary
	if len(c.items) > c.capacity {
		c.evictLRU()
	}
}

// Delete removes a key from the cache
func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.items[key]; exists {
		c.removeEntry(entry)
	}
}

// Clear removes all entries from the cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*CacheEntry)
	c.lruList.Init()
}

// Size returns the current number of items in the cache
func (c *LRUCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Stats returns cache statistics
func (c *LRUCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	return CacheStats{
		Hits:     c.hits,
		Misses:   c.misses,
		Evicts:   c.evicts,
		HitRate:  hitRate,
		Size:     len(c.items),
		Capacity: c.capacity,
	}
}

// CleanupExpired removes expired entries from the cache
func (c *LRUCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	// Walk from back (oldest) to front
	for element := c.lruList.Back(); element != nil; {
		entry := element.Value.(*CacheEntry)
		next := element.Prev() // Get next before potential removal

		if now.After(entry.ExpiresAt) {
			c.removeEntry(entry)
			removed++
		} else {
			// Since we're walking from oldest to newest,
			// if this entry isn't expired, no newer ones will be
			break
		}

		element = next
	}

	return removed
}

// evictLRU removes the least recently used item
func (c *LRUCache) evictLRU() {
	if c.lruList.Len() == 0 {
		return
	}

	// Remove from back (least recently used)
	element := c.lruList.Back()
	if element != nil {
		entry := element.Value.(*CacheEntry)
		c.removeEntry(entry)
		c.evicts++
	}
}

// removeEntry removes an entry from both the map and list
func (c *LRUCache) removeEntry(entry *CacheEntry) {
	delete(c.items, entry.Key)
	c.lruList.Remove(entry.Element)
}

// CacheStats represents cache performance metrics
type CacheStats struct {
	Hits     int64   `json:"hits"`
	Misses   int64   `json:"misses"`
	Evicts   int64   `json:"evicts"`
	HitRate  float64 `json:"hit_rate"`
	Size     int     `json:"size"`
	Capacity int     `json:"capacity"`
}
