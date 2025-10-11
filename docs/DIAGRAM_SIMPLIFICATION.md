# 🎨 CIPgram Diagram Simplification Guide

## 🚨 **Problem Solved: Messy Network Diagrams**

CIPgram now includes powerful features to create **clean, readable network diagrams** instead of cluttered, overwhelming visualizations.

## 🎯 **New Simplification Options**

### **1. Connection Filtering (`-min-packets`)**
```bash
# Only show connections with significant traffic (default: 10 packets)
./cipgram -pcap network.pcap -min-packets 50

# Show all connections (might be cluttered)
./cipgram -pcap network.pcap -min-packets 1
```
**Result**: Eliminates noise from brief/test connections

### **2. Node Limiting (`-max-nodes`)**
```bash
# Show only top 20 most active devices (default: 50)
./cipgram -pcap network.pcap -max-nodes 20

# Show unlimited nodes (might be overwhelming)
./cipgram -pcap network.pcap -max-nodes 0
```
**Result**: Focuses on the most important network participants

### **3. Hide Unknown Devices (`-hide-unknown`)**
```bash
# Hide devices that couldn't be classified
./cipgram -pcap network.pcap -hide-unknown
```
**Result**: Shows only devices with clear industrial roles

### **4. Summary Mode (`-summary`)**
```bash
# Create ultra-clean summary by grouping similar devices
./cipgram -pcap network.pcap -summary
```
**Result**: Groups multiple PLCs, HMIs, etc. into single nodes

## 🎨 **Visual Improvements**

### **Enhanced Layout**
- **Top-to-bottom flow** (Level 3 → Level 2 → Level 1)
- **Orthogonal edges** for cleaner connections
- **Better spacing** between nodes and clusters
- **Improved fonts** and sizing

### **Cleaner Node Labels**
- **Shortened IP addresses** (192.168.1.10 → 1.10)
- **Abbreviated roles** (Engineering Station → ENG)
- **Single primary role** instead of multiple roles

### **Simplified Edge Labels**
- **Short protocol names** (ENIP-TCP-44818 → ENIP)
- **Packet counts** only for significant traffic
- **Color-coded connections** by protocol type
- **Bidirectional edge consolidation**

### **Better Colors**
- **Level 2**: Changed from red to yellow for better contrast
- **Protocol colors**: Green (EtherNet/IP), Orange (Modbus), Purple (S7)
- **Role-based node colors**: PLCs slightly darker than HMIs

## 🔥 **Recommended Usage Patterns**

### **For Complex Networks (50+ devices)**
```bash
# Ultra-clean summary view
./cipgram -pcap complex_network.pcap -summary -min-packets 100

# Focus on key devices only
./cipgram -pcap complex_network.pcap -max-nodes 15 -hide-unknown
```

### **For Medium Networks (10-50 devices)**
```bash
# Clean view with moderate filtering
./cipgram -pcap medium_network.pcap -min-packets 25

# Hide noise devices
./cipgram -pcap medium_network.pcap -hide-unknown
```

### **For Small Networks (<10 devices)**
```bash
# Minimal filtering for complete view
./cipgram -pcap small_network.pcap -min-packets 5

# Or use defaults (they work well for small networks)
./cipgram -pcap small_network.pcap
```

## 📊 **Before vs. After Examples**

### **Before (Messy)**
- 50+ nodes with full IP addresses
- Hundreds of low-traffic connections
- Cluttered edge labels with full protocol names
- All devices shown regardless of importance

### **After (Clean)**
- Top 20 key devices with short labels
- Only significant connections (>10 packets)
- Clean protocol names (ENIP, Modbus, S7)
- Summary groups of similar devices

## 🎛️ **Fine-Tuning Your Diagrams**

```bash
# Very strict filtering for executive summary
./cipgram -pcap network.pcap -summary -min-packets 1000 -max-nodes 10

# Moderate cleaning for technical analysis  
./cipgram -pcap network.pcap -min-packets 50 -hide-unknown

# Minimal filtering for detailed investigation
./cipgram -pcap network.pcap -min-packets 5
```

## 🎉 **Result: Professional Network Diagrams**

Your CIPgram diagrams are now:
- ✅ **Clean and readable**
- ✅ **Focused on important devices**
- ✅ **Professional presentation quality**
- ✅ **Customizable complexity level**
- ✅ **Color-coded for quick understanding**

No more messy, overwhelming network diagrams!
