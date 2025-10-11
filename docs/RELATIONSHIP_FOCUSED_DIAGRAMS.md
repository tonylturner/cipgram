# 🎨 CIPgram Relationship-Focused Diagrams

## 🎯 **New Approach: Device Relationships Over Packet Counts**

CIPgram now focuses on **what devices communicate with what** and **how they communicate**, rather than traffic volume. Perfect for understanding network architecture and device roles!

## 🏗️ **Key Changes Made**

### ✅ **Removed Packet Count Filtering**
- **Before**: Filtered connections by packet volume (noisy, missed important low-traffic connections)
- **After**: Shows **all device relationships** regardless of traffic volume
- **Why**: A PLC talking to an HMI once is still an important relationship!

### ✅ **Added Hostname & Device Detection**
- **Hostname Resolution**: Automatically resolves IP addresses to hostnames when possible
- **Device Identification**: Detects device types from protocol patterns
- **Smart Labeling**: Shows hostname → device type → IP for maximum clarity

### ✅ **Protocol & Port Focus**
- **Clean Protocol Names**: "EtherNet/IP" instead of "ENIP-TCP-44818"
- **Port Information**: Shows TCP/502, TCP/44818, etc. for context
- **Color-Coded Protocols**: Green (EtherNet/IP), Orange (Modbus), Purple (S7)
- **CIP Service Details**: Shows specific CIP services when detected

### ✅ **Enhanced Purdue Level Visualization**
- **Top-Down Layout**: Level 3 at top → Level 2 → Level 1 at bottom (natural flow)
- **Clear Level Clusters**: Each level is a distinct, labeled cluster
- **Better Colors**: Light backgrounds with strong borders for readability

## 🎛️ **New Command Options**

```bash
# Show all device relationships with hostnames (default)
./cipgram -pcap network.pcap

# Hide devices that couldn't be classified (cleaner view)
./cipgram -pcap network.pcap -hide-unknown

# Limit to most important devices only
./cipgram -pcap network.pcap -max-nodes 20

# Create ultra-clean summary by grouping similar devices
./cipgram -pcap network.pcap -summary

# Disable hostname resolution (faster for large networks)
./cipgram -pcap network.pcap -hostnames=false
```

## 🎨 **Visual Improvements**

### **Node Labels Now Show:**
1. **Primary ID**: Hostname (preferred) → Device Name → Short IP
2. **Device Role**: (Siemens PLC), (HMI), (I/O Device)
3. **IP Address**: As secondary info if hostname used
4. **Configuration**: [configured] if from YAML mapping

### **Edge Labels Focus On:**
1. **Protocol Name**: Clear, readable protocol names
2. **Port/Transport**: TCP/502, UDP/2222, etc.
3. **CIP Services**: Get Attr, Set Attr, etc. (when relevant)
4. **Color Coding**: Each protocol family has distinct colors

### **Examples:**
```
Before (messy):
192.168.1.10 → 192.168.1.20
ENIP-TCP-44818
pkts:1247

After (clean):
HMI-STATION-01       →    SIEMENS-PLC-01
(ENG Station)              (Siemens PLC)
192.168.1.10              192.168.1.20

EtherNet/IP
TCP/44818
Get Attr
```

## 🏭 **Perfect for Industrial Networks**

### **Architecture Understanding**
- **Device Relationships**: See which devices communicate
- **Protocol Usage**: Understand what protocols are used where
- **Purdue Compliance**: Verify proper level separation
- **Vendor Identification**: Automatic detection of Siemens, Rockwell, Omron, etc.

### **Use Cases**
- ✅ **Network Documentation**: Professional diagrams showing device relationships
- ✅ **Security Assessments**: Understand communication flows
- ✅ **Troubleshooting**: See protocol relationships at a glance  
- ✅ **Compliance**: Verify Purdue Model implementation

## 🎯 **Result: Professional Network Architecture Diagrams**

Your diagrams now show:
- 🏷️ **Clear device identification** (hostnames + device types)
- 🔗 **All communication relationships** (not just high-traffic)
- 🌈 **Color-coded protocols** (easy to understand at a glance)
- 📊 **Proper Purdue level organization** (L3 → L2 → L1 flow)
- 🎨 **Clean, readable layout** (no more clutter)

**Perfect for understanding WHO talks to WHOM using WHAT protocols!** 🎉
