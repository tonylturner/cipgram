# Enhanced Online OUI Lookup System

## 🌐 What's New
Replaced the static OUI table with a comprehensive online lookup system that provides **real-time, up-to-date vendor identification** for all MAC addresses.

## 🔧 Implementation Features

### **Multiple Data Sources**
1. **MacVendors.com API** - Fast, reliable REST API
2. **IEEE Official Registry** - Authoritative source, auto-downloaded
3. **Wireshark Manuf Database** - Community-maintained, frequently updated
4. **Local Cache System** - Fast offline lookups with persistence

### **Intelligent Caching**
- **Memory Cache** - Instant lookups for repeated MACs
- **Disk Persistence** - Cache survives program restarts
- **Auto-refresh** - IEEE database updates weekly
- **Thread-safe** - Concurrent access supported

### **Graceful Fallbacks**
1. **Cache Hit** → Instant response
2. **Online APIs** → Real-time lookup (5s timeout)
3. **Local IEEE DB** → Offline comprehensive lookup
4. **Static Fallback** → Critical industrial vendors only
5. **Empty Response** → Unknown vendor handled gracefully

## 📁 Cache Structure
```
.oui_cache/
├── oui_cache.json        # Fast lookup cache
└── ieee_oui.txt         # Official IEEE registry
```

## 🎯 Benefits

### **Always Current**
- No more outdated static lists
- Automatic updates from authoritative sources
- New vendors discovered immediately

### **Industrial Focus**
- Standardized vendor names (e.g., "Rockwell Automation")
- Intelligent name cleaning and consolidation
- Priority for automation/industrial vendors

### **Performance Optimized**
- Local cache for repeated lookups
- Multiple timeout strategies
- Non-blocking concurrent access
- Minimal network overhead

### **Reliability**
- Multiple fallback mechanisms
- Graceful network failure handling
- Offline operation capability
- No single point of failure

## 🔍 Example Usage
```go
// Automatic online lookup with caching
vendor := lookupOUI("00:0E:8C:12:34:56")  // → "Rockwell Automation"

// Cache persisted for future runs
SaveOUICache()  // Called automatically on exit
```

## 🚀 Impact
- **Comprehensive Coverage**: 30,000+ vendors vs. 28 static entries
- **Always Accurate**: Real-time updates from IEEE registry
- **Better Diagrams**: More detailed vendor identification
- **Future-Proof**: Automatically discovers new industrial vendors

This transforms CipGram from having basic vendor detection to comprehensive, enterprise-grade MAC address identification suitable for professional industrial network analysis.
