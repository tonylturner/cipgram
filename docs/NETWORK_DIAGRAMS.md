# Network Diagram Generation Guide

## 🌐 **Network Diagram vs Purdue Diagram**

CIPgram now supports **two diagram types** for different use cases:

### **1. Purdue Diagram (Default)**
```bash
./cipgram -pcap network.pcap -diagram purdue
```
- **Purpose**: Functional modeling and operational understanding
- **Layout**: Vertical hierarchy (L3 → L2 → L1)
- **Focus**: Device roles, industrial protocols, functional relationships
- **Colors**: Traditional Purdue colors (Blue L3, Orange L2, Green L1)

### **2. Network Diagram (New)**
```bash
./cipgram -pcap network.pcap -diagram network
```
- **Purpose**: Network segmentation planning and infrastructure design
- **Layout**: Horizontal network topology
- **Focus**: Network segments, routers, firewalls, CIDR boundaries
- **Colors**: Network type based (Green OT, Blue IT, Gray Mixed)

## 🔧 **Generating Network Diagrams**

### **Basic Network Diagram**
```bash
./cipgram -pcap your_network.pcap -diagram network
```

### **Fast Network Analysis**
```bash
./cipgram -pcap your_network.pcap -diagram network -fast
```

### **Network Diagram with Hostnames**
```bash
./cipgram -pcap your_network.pcap -diagram network -hostnames
```

## 📊 **Network Diagram Features**

### **Infrastructure Elements**
- **Internet Cloud**: External connectivity representation
- **Firewall**: Security boundary visualization  
- **Core Router**: Central network hub
- **Network Segments**: CIDR-based groupings

### **Network Segment Types**
- **OT Networks**: Green background, industrial devices
- **IT Networks**: Blue background, corporate systems
- **Mixed Networks**: Gray background, hybrid environments

### **Automatic Network Detection**
- **CIDR Inference**: Automatically detects network boundaries
- **Host Classification**: Groups devices by network segment
- **Key Asset Selection**: Shows 5 most important devices per segment
- **Traffic Analysis**: Identifies network communication patterns

## 🎯 **Output Files**

When you run with `-diagram network`, you get:

```
diagrams/your_pcap_name/
├── diagram.dot          # Network DOT source
├── diagram.png          # Network diagram image
├── diagram.svg          # Scalable vector graphics
├── diagram_hires.png    # High-resolution PNG
└── diagram.json         # Raw network analysis data
```

## 🔍 **Network Diagram Structure**

### **Visual Layout**
```
[Internet] → [Firewall] → [Core Router]
                             ↓
                    ┌─────────┼─────────┐
                    ↓         ↓         ↓
              [OT Network] [IT Network] [DMZ]
               192.168.1.0  10.0.1.0    172.16.1.0
                    ↓         ↓         ↓
               [Key Assets] [Servers] [Services]
```

### **Network Segment Details**
Each network segment shows:
- **CIDR Range**: e.g., "192.168.1.0/24"
- **Host Count**: Number of devices detected
- **Network Type**: OT, IT, or Mixed classification
- **Key Assets**: Most important devices (PLCs, servers, etc.)

## 🚀 **Use Cases**

### **OT Network Segmentation Planning**
```bash
./cipgram -pcap industrial.pcap -diagram network -max-nodes 100
```
**Result**: Shows network topology with industrial segments clearly separated from IT networks, helping plan micro-segmentation.

### **Security Assessment**
```bash
./cipgram -pcap security_audit.pcap -diagram network -hostnames
```
**Result**: Network view with device names and network boundaries for security zone analysis.

### **Network Architecture Documentation**
```bash
./cipgram -pcap network_baseline.pcap -diagram network
```
**Result**: Clean network topology diagram for documentation and planning.

## ⚡ **Performance Tips**

### **Large Networks**
```bash
./cipgram -pcap large_network.pcap -diagram network -fast -max-nodes 50
```

### **Quick Overview**
```bash
./cipgram -pcap network.pcap -diagram network -fast -hide-unknown
```

## 🔧 **Troubleshooting**

### **No Network Images Generated**
1. **Check Graphviz**: `dot -V` (install with `brew install graphviz`)
2. **Enable Images**: Use `-images=true` (default)
3. **Check Permissions**: Ensure write access to output directory

### **Empty Network Diagram**
- **Check PCAP**: Ensure file contains network traffic
- **Try Fast Mode**: Use `-fast` to skip slow lookups
- **Increase Nodes**: Use `-max-nodes 0` for unlimited

### **Network Segments Not Detected**
- **Check IP Ranges**: Ensure diverse IP addresses in capture
- **Disable Filtering**: Use `-hide-unknown=false`
- **Check Traffic**: Ensure inter-network communication exists

## 📋 **Example Commands**

```bash
# Generate both diagram types
./cipgram -pcap network.pcap -diagram purdue
./cipgram -pcap network.pcap -diagram network

# Compare functional vs network views
./cipgram -pcap industrial.pcap -diagram purdue -out diagrams/functional.dot
./cipgram -pcap industrial.pcap -diagram network -out diagrams/network.dot

# Fast network analysis for large files
./cipgram -pcap large.pcap -diagram network -fast -max-nodes 25
```

---

**The network diagram type provides a complementary view to the Purdue diagram, focusing on infrastructure and segmentation rather than functional relationships.**
