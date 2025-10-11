# Both Diagrams Feature - Complete Guide

## 🎯 **Generate Both Purdue and Network Diagrams**

CIPgram now supports generating **both diagram types simultaneously** with separate, clearly named files.

## 🚀 **Usage Options**

### **Option 1: Use -both flag**
```bash
./cipgram -pcap network.pcap -both
```

### **Option 2: Use -diagram both**
```bash
./cipgram -pcap network.pcap -diagram both
```

### **Option 3: Fast mode for large files**
```bash
./cipgram -pcap large_network.pcap -both -fast
```

## 📁 **Output Files**

When you use `-both` or `-diagram both`, you get:

```
diagrams/your_pcap_name/
├── purdue_diagram.dot       # Purdue functional model DOT
├── purdue_diagram.png       # Purdue functional model PNG
├── purdue_diagram.svg       # Purdue functional model SVG
├── purdue_diagram_hires.png # Purdue high-res PNG
├── network_diagram.dot      # Network segmentation DOT
├── network_diagram.png      # Network segmentation PNG
├── network_diagram.svg      # Network segmentation SVG
├── network_diagram_hires.png# Network high-res PNG
└── diagram.json             # Raw analysis data
```

## 🔍 **Individual Diagram Types**

### **Purdue Only (Default)**
```bash
./cipgram -pcap network.pcap
# or explicitly:
./cipgram -pcap network.pcap -diagram purdue
```
**Creates**: `diagram.dot`, `diagram.png`, `diagram.svg`

### **Network Only**
```bash
./cipgram -pcap network.pcap -diagram network
```
**Creates**: `diagram.dot`, `diagram.png`, `diagram.svg`

### **Both Diagrams**
```bash
./cipgram -pcap network.pcap -both
```
**Creates**: Both sets with descriptive names

## 📊 **Diagram Comparison**

| Feature | Purdue Diagram | Network Diagram |
|---------|----------------|-----------------|
| **Purpose** | Functional modeling | Segmentation planning |
| **Layout** | Vertical (L3→L2→L1) | Horizontal (networks) |
| **Focus** | Device roles & protocols | Network topology |
| **Elements** | PLCs, HMIs, Servers | Routers, Firewalls, Segments |
| **Colors** | Purdue levels | Network types |
| **Use Case** | Operations analysis | Security planning |

## 🎯 **Recommended Workflows**

### **Complete Analysis**
```bash
# Get both views for comprehensive understanding
./cipgram -pcap industrial.pcap -both -hostnames
```

### **Quick Assessment**
```bash
# Fast analysis of large networks
./cipgram -pcap large.pcap -both -fast -max-nodes 50
```

### **Security Planning**
```bash
# Focus on segmentation with full details
./cipgram -pcap security_audit.pcap -both -max-nodes 100
```

### **Documentation**
```bash
# Generate clean diagrams for reports
./cipgram -pcap baseline.pcap -both -hide-unknown
```

## 🔧 **Advanced Options**

### **Custom Output Paths**
```bash
# Both diagrams with custom directory
./cipgram -pcap network.pcap -both -out /custom/path/
```

### **Selective Generation**
```bash
# Generate Purdue only
./cipgram -pcap network.pcap -diagram purdue

# Generate Network only  
./cipgram -pcap network.pcap -diagram network

# Generate both
./cipgram -pcap network.pcap -diagram both
```

### **Performance Tuning**
```bash
# Maximum speed for large files
./cipgram -pcap huge.pcap -both -fast -max-nodes 25 -hide-unknown

# Full detail for smaller networks
./cipgram -pcap detailed.pcap -both -hostnames
```

## 🎨 **Visual Differences**

### **Purdue Diagram Features**
- **Vertical hierarchy**: L3 (top) → L2 → L1 (bottom)
- **Traditional colors**: Blue (L3), Orange (L2), Green (L1)
- **Protocol flows**: EtherNet/IP, Modbus, S7, OPC connections
- **Device details**: Full IP, MAC, vendor, role information

### **Network Diagram Features**
- **Horizontal layout**: Left-to-right network flow
- **Infrastructure elements**: Internet, Firewall, Router nodes
- **Network segments**: CIDR-based groupings with color coding
- **Key assets**: Top 5 most important devices per segment

## 🚀 **Benefits of Both Diagrams**

### **Operational Teams**
- **Purdue diagram**: Understand functional relationships
- **Network diagram**: Plan maintenance and access

### **Security Teams**
- **Purdue diagram**: Identify critical control paths
- **Network diagram**: Design segmentation strategy

### **Management**
- **Purdue diagram**: Operational risk assessment
- **Network diagram**: Infrastructure investment planning

## 📈 **Example Scenarios**

### **OT Security Assessment**
```bash
./cipgram -pcap ot_network.pcap -both -hostnames -max-nodes 75
```
**Result**: Functional view shows control relationships, network view shows segmentation opportunities.

### **Incident Response**
```bash
./cipgram -pcap incident.pcap -both -fast
```
**Result**: Quick analysis showing both operational impact (Purdue) and network scope (Network).

### **Compliance Documentation**
```bash
./cipgram -pcap compliance.pcap -both -hide-unknown
```
**Result**: Clean diagrams for regulatory submissions showing both functional architecture and network security.

---

**With the both diagrams feature, you get comprehensive network analysis covering both operational functionality and infrastructure architecture in a single command.**
