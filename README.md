# CIPgram - OT Network Segmentation Analysis Tool

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)](https://github.com/tturner/cipgram)
[![Industrial](https://img.shields.io/badge/Focus-Industrial%20OT-orange?style=for-the-badge)](https://github.com/tturner/cipgram)

**Advanced PCAP and firewall analysis for industrial control system segmentation planning**

## 🎯 Purpose
CIPgram analyzes network traffic and firewall configurations to automatically discover OT assets, classify devices according to the Purdue Model, and generate professional network diagrams for segmentation planning and compliance assessment.

## 🔧 Key Features

### **PCAP Traffic Analysis**
- **Asset Discovery** - Automatic identification of industrial devices from network traffic
- **Protocol Detection** - Deep packet inspection for 20+ industrial protocols
- **Vendor Identification** - MAC address lookup with OUI database (78,000+ vendors)
- **Network Mapping** - Traffic-based topology discovery and visualization
- **Conversation Analysis** - Detailed communication flow tracking with CSV export

### **Firewall Configuration Analysis**
- **OPNsense Support** - Full XML configuration parsing (production ready)
- **Network Topology** - Interface and routing analysis
- **Security Policy Mapping** - Rule analysis and risk assessment
- **IEC 62443 Zone Inference** - Automatic zone classification

### **Professional Visualization**
- **Network Topology Diagrams** - Traditional network layouts with routing visualization
- **Purdue Model Diagrams** - Industrial control system hierarchy (L0-L4, DMZ)
- **Multiple Formats** - DOT, JSON, SVG, PNG output with interactive legends
- **Compliance Views** - IEC 62443 zone and conduit mapping

### **Industrial Protocol Support**
- **EtherNet/IP** (Port 44818) - Rockwell Automation, CIP
- **Modbus TCP** (Port 502) - Industrial automation standard
- **Siemens S7** (Port 102) - S7Comm protocol
- **OPC/OPC-UA** (Ports 135, 4840) - Industrial data exchange
- **DNP3** (Port 20000) - Utility and power systems
- **PROFINET** - Siemens industrial Ethernet
- **SLMP** (Port 5007) - Mitsubishi communication
- **FINS** (Port 9600) - Omron industrial protocol
- **BACnet**, **SINEC**, **EGD/SRTP** and more

## 🚀 Quick Start

```bash
# Build the tool
go build -o cipgram ./cmd/cipgram

# Analyze PCAP traffic
./cipgram pcap network_traffic.pcap project "network_analysis"

# Analyze firewall configuration (OPNsense)
./cipgram config firewall_config.xml project "security_audit"

# Advanced PCAP analysis with vendor lookup
./cipgram pcap traffic.pcap project "detailed_analysis" vendor-lookup=true

# Generate specific diagram types
./cipgram pcap traffic.pcap project "purdue_only" diagram=purdue
./cipgram pcap traffic.pcap project "network_only" diagram=network

# Fast analysis (no vendor/DNS lookups)
./cipgram pcap large_capture.pcap project "fast_scan" fast=true
```

## 📊 Output Structure

```
output/
└── [project-name]/
    ├── network_diagrams/          # Network topology and Purdue diagrams
    │   ├── network_topology.{dot,json,svg,png}
    │   └── purdue_diagram.{dot,json,svg,png}
    ├── iec62443_diagrams/         # IEC 62443 compliance views (firewall configs)
    ├── firewall_analysis/         # Security policy analysis (firewall configs)
    └── data/
        ├── conversations.csv      # Communication flow analysis (PCAP)
        └── analysis.json         # Raw analysis data
```

## 🔍 Analysis Capabilities

### **PCAP Analysis**
- **Asset Discovery**: Identifies all communicating devices with IP, MAC, and vendor info
- **Protocol Classification**: Detects industrial protocols and standard network traffic
- **Network Segmentation**: Groups devices by communication patterns and subnets
- **Purdue Model Mapping**: Automatically assigns devices to appropriate control levels
- **Conversation Tracking**: Records all network conversations with packet/byte counts
- **Routing Analysis**: Identifies inter-network communications requiring routing

### **Firewall Analysis** (OPNsense)
- **Network Topology**: Extracts network structure from interface configurations
- **Security Policy Review**: Analyzes firewall rules for compliance and risk
- **Zone Classification**: Maps networks to IEC 62443 security zones
- **Risk Assessment**: Evaluates security posture based on rule patterns
- **Compliance Scoring**: Measures adherence to industrial security standards

## 📋 Use Cases

### **Network Discovery and Asset Inventory**
- Discover all devices communicating on industrial networks
- Identify device vendors and types from MAC addresses
- Generate comprehensive asset inventories for compliance

### **Security Assessment and Risk Analysis**
- Analyze firewall configurations for security gaps
- Identify unauthorized or risky network communications
- Assess compliance with industrial security standards

### **Network Segmentation Planning**
- Visualize current network topology and communication flows
- Identify opportunities for improved network segmentation
- Plan Purdue Model implementation for industrial networks

### **Compliance Documentation**
- Generate professional network diagrams for audits
- Document network architecture for IEC 62443 compliance
- Create visual evidence of security controls and segmentation

## 🔧 Command Reference

### **PCAP Analysis Options**
```bash
cipgram pcap <file.pcap> [options]
  project <name>           # Project name for organized output
  config <file.yaml>       # Optional subnet→Purdue level mappings  
  vendor-lookup=true       # Enable MAC vendor identification (default: true)
  dns-lookup=true          # Enable hostname resolution (default: false)
  fast=true               # Disable lookups for maximum speed
  diagram=purdue          # Generate only Purdue model diagram
  diagram=network         # Generate only network topology diagram
  diagram=both            # Generate both diagram types (default)
  max-nodes=100           # Limit nodes shown (0=unlimited)
  hide-unknown=true       # Hide devices with unknown Purdue levels
```

### **Firewall Analysis Options**
```bash
cipgram config <file.xml> [options]
  project <name>           # Project name for organized output
  diagram=both            # Diagram types to generate
```

## 📚 Documentation

See `docs/` directory for detailed guides:
- **FIREWALL_CONFIG_GUIDE.md** - OPNsense configuration analysis
- **SECURITY_RULES_BEST_PRACTICES.md** - Industrial security guidelines
- **integrations/opnsense.md** - OPNsense setup and integration

## 📄 License

Apache 2.0 - see LICENSE file for details.

---

**CIPgram** - Professional OT network segmentation analysis made simple.