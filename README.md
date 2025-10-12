# CIPgram - OT Network Segmentation Analysis Tool

**Advanced PCAP and firewall analysis for industrial control system segmentation planning**

## 🎯 Purpose
CIPgram helps with **OT network segmentation planning** and **compliance assessment** by analyzing network traffic and firewall configurations to automatically classify devices and identify segmentation opportunities.

## 🔧 Key Features

### **Multi-Source Analysis**
- **PCAP Analysis** - Traffic-based asset discovery and behavior analysis
- **Firewall Integration** - OPNsense, FortiGate, Vyatta, iptables, and Firewalla support
- **Combined Analysis** - Policy compliance and segmentation opportunity detection

### **Industry Standards Compliance**
- **IEC 62443** zone and conduit mapping
- **Purdue Model** automatic classification (L1/L2/L3)
- **Risk Assessment** based on exposure and criticality

### **Comprehensive Protocol Support**
- **EtherNet/IP** (CIP, I/O, Explicit messaging)
- **Modbus TCP**, **Siemens S7**, **OPC/OPC-UA**
- **DNP3**, **BACnet**, **FINS**, **SLMP** and 15+ other industrial protocols

## 🚀 Quick Start

```bash
# Build the tool
go build -o cipgram cmd/cipgram/main.go

# Analyze firewall configuration only
./cipgram -firewall-config fwconfigs/opnsense_config.xml -project "my_analysis"

# Analyze PCAP traffic only  
./cipgram -pcap traffic.pcap -project "network_baseline"

# Combined analysis (when you have both)
./cipgram -pcap traffic.pcap -firewall-config firewall.xml -project "compliance_assessment"

# Generate images (requires Graphviz)
./cipgram -firewall-config config.xml -project "visual_analysis" -images=true
```

## 📊 Output Structure

```
output/
└── [project-name]/
    ├── network_diagrams/          # Network topology views
    ├── iec62443_diagrams/         # IEC 62443 zone/conduit analysis
    ├── firewall_analysis/         # Policy and rule analysis
    ├── combined_analysis/         # Advanced compliance assessment
    └── data/                      # Raw analysis data (JSON)
```

## 🏭 Analysis Types

### **Firewall-Only Analysis**
- Network topology from configuration
- Security policy mapping
- IEC 62443 zone inference
- Risk assessment by network segment

### **PCAP-Only Analysis**  
- Asset discovery and classification
- Protocol behavior analysis
- Network segment inference from traffic
- Purdue Model level assignment

### **Combined Analysis**
- Policy violation detection
- Segmentation opportunity identification
- Security posture assessment
- Compliance scoring

## 📋 Use Cases

### **OT Network Segmentation Planning**
Generate network topology and identify microsegmentation opportunities for industrial networks.

### **IEC 62443 Compliance Assessment**
Analyze current network architecture against IEC 62443 zone and conduit requirements.

### **Security Policy Validation**
Compare actual network traffic against configured firewall policies to identify violations.

### **Asset Discovery and Classification**
Automatically discover and classify industrial devices based on protocol behavior.

## 🔧 Advanced Usage

See `docs/` for detailed information on:
- **Integrations**: OPNsense setup and configuration
- **Advanced Analysis**: IEC 62443 compliance and combined analysis features

## 📄 License

Open source - see LICENSE file for details.

---

**CIPgram** - Professional OT network segmentation analysis made simple.