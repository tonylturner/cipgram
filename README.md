# CIPgram - Industrial Network Analysis Tool

**Advanced PCAP analysis for industrial control systems with intelligent Purdue Model classification**

## 🎯 Purpose
CIPgram helps with **OT network segmentation planning** and **functional modeling** by analyzing network traffic and automatically classifying devices according to the Purdue Model.

## 🔧 Key Features

### **Dual Diagram Types**
- **Purdue Diagrams** - Functional modeling with proper vertical hierarchy (L3→L2→L1)
- **Network Diagrams** - Segmentation planning with infrastructure elements

### **Smart Asset Identification**
- **Full IP addresses** with MAC address correlation
- **Online OUI lookup** with vendor identification (Siemens, Rockwell, etc.)
- **Automatic deduplication** based on MAC addresses
- **Protocol-based device classification** (PLCs, HMIs, I/O devices)

### **Comprehensive Protocol Support**
- **EtherNet/IP** (CIP, I/O, Explicit messaging)
- **Modbus TCP** 
- **Siemens S7**
- **OPC/OPC-UA**
- **DNP3, BACnet, FINS, SLMP** and 15+ other industrial protocols

## 🚀 Quick Start

```bash
# Basic Purdue functional model
go build -o cipgram
./cipgram -pcap network.pcap -diagram purdue

# Network segmentation planning  
./cipgram -pcap network.pcap -diagram network

# Live capture with hostname resolution
./cipgram -iface eth0 -hostnames -diagram purdue
```

## 📊 Diagram Types

### **Purdue Diagrams** (`-diagram purdue`)
**Use Case**: Functional modeling and operational understanding

**Features**:
- Traditional vertical Purdue hierarchy
- Full asset details (IP, MAC, vendor, role)
- Protocol flows showing functional relationships
- Clear L3 (Management) → L2 (Control) → L1 (Field) structure

### **Network Diagrams** (`-diagram network`)  
**Use Case**: OT network segmentation planning

**Features**:
- Network infrastructure view (routers, firewalls, segments)
- CIDR-based network grouping
- Key assets per network segment
- Segmentation recommendations (OT/IT boundaries)

## 🔧 Command Line Options

```bash
cipgram [options]

Input:
  -pcap string     Path to pcap/pcapng file
  -iface string    Live capture interface
  -config string   Optional YAML subnet mappings

Output:
  -out string      DOT file path (default: diagrams/$pcapname/diagram.dot)
  -json string     JSON data path (default: diagrams/$pcapname/diagram.json)
  -images          Generate PNG/SVG images (default: true)

Diagram Options:
  -diagram string  Diagram type: 'purdue' or 'network' (default: purdue)
  -hostnames       Resolve hostnames (default: true)
  -hide-unknown    Hide unclassified devices
  -max-nodes int   Limit nodes shown (0 = unlimited)
  -summary         Create simplified summary
```

## 📁 Output Structure

```
diagrams/
└── your_capture/
    ├── diagram.dot          # Graphviz source
    ├── diagram.png          # Standard image
    ├── diagram_hires.png    # High resolution
    ├── diagram.svg          # Vector format
    └── diagram.json         # Raw analysis data
```

## 🏭 Industrial Protocol Detection

**Automatic Classification**:
- **Level 1**: PLCs, I/O devices, drives (receive control, send data)
- **Level 2**: HMIs, SCADA systems (initiate connections, poll devices)
- **Level 3**: Engineering workstations, historians (management/IT functions)

**Protocol Intelligence**:
- **EtherNet/IP**: Distinguishes Explicit vs I/O traffic for role classification
- **Modbus**: Master/slave detection for Purdue level assignment
- **Vendor-Specific**: Siemens S7, Omron FINS, Mitsubishi SLMP recognition
- **CIP Services**: Decodes Allen-Bradley service calls

## 🌐 Online OUI Integration

- **Real-time vendor lookup** from IEEE registry and MacVendors.com
- **Local caching** for offline operation
- **Industrial focus** with vendor name standardization
- **Fallback mechanisms** for reliable identification

## 📋 Use Cases

### **Network Segmentation Planning**
```bash
# Generate network view for segmentation analysis
./cipgram -pcap industrial.pcap -diagram network
```
**Result**: Infrastructure-focused diagram showing network segments, key assets, and segmentation boundaries.

### **Functional Process Analysis**
```bash
# Generate Purdue model for operational understanding
./cipgram -pcap process.pcap -diagram purdue -hostnames
```
**Result**: Traditional Purdue hierarchy showing functional relationships and protocol flows.

### **Asset Discovery**
```bash
# Comprehensive asset identification with vendor details
./cipgram -iface eth0 -diagram purdue -max-nodes 50
```
**Result**: Detailed asset inventory with MAC addresses, vendors, and device roles.

## 🔧 Advanced Configuration

**Custom Subnet Mappings** (`purdue_config.yaml`):
```yaml
subnets:
  192.168.1.0/24:
    level: "Level 1"
    role: "PLC Network"
  192.168.10.0/24:
    level: "Level 2" 
    role: "HMI Network"
```

## 📈 Technical Architecture

**Modular Design**:
- `main.go` - Packet processing and analysis
- `protocols.go` - Industrial protocol detection
- `classification.go` - Purdue level assignment
- `oui.go` - MAC address vendor lookup
- `writers.go` - Diagram generation
- `graph.go` - Data structures and deduplication

**Performance**:
- **Concurrent processing** for large PCAP files
- **Smart caching** for repeated MAC lookups
- **Memory efficient** with selective filtering
- **Deduplication** to eliminate redundant entries

## 🤝 Contributing

See `docs/` for detailed documentation:
- Architecture overview
- Protocol detection details
- Classification algorithms
- Diagram generation process

## 📄 License

Open source - see LICENSE file for details.

---

**CIPgram** - Making industrial network analysis simple and comprehensive.