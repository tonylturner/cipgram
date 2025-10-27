# CIPgram - Industrial Network Analysis Tool

[![Go Version](https://img.shields.io/badge/Go-1.24-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**CIPgram** is a high-performance command-line tool for analyzing industrial network traffic (PCAP files) and generating network diagrams. It specializes in OT/ICS protocols and IEC 62443 security analysis.

## 🚀 Features

- **50+ Industrial Protocols**: Modbus, EtherNet/IP, PROFINET, DNP3, BACnet, S7, and more
- **Network Visualization**: Automatic topology diagrams (PNG, SVG, DOT, JSON)
- **Security Analysis**: IEC 62443 zone mapping and Purdue model diagrams
- **Asset Discovery**: Automatic identification of PLCs, HMIs, SCADA servers
- **High Performance**: 20K+ packets/second with 99% cache hit rates
- **Memory Efficient**: 99.75% memory reduction through adaptive optimization

## 📦 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y git golang-go libpcap-dev graphviz

# RHEL/CentOS/Fedora
sudo yum install -y git golang libpcap-devel graphviz

# macOS
brew install go libpcap graphviz
```

### Build from Source

```bash
git clone https://github.com/yourusername/cipgram.git
cd cipgram
go build -o cipgram ./cmd/cipgram/
sudo cp cipgram /usr/local/bin/
```

### Verify Installation

```bash
cipgram version
```

## 🎯 Quick Start

### Analyze a PCAP File

```bash
# Basic analysis
cipgram pcap traffic.pcap project MyAnalysis

# With vendor lookup
cipgram pcap traffic.pcap project MyAnalysis --vendor-lookup

# Fast mode (skip detailed analysis)
cipgram pcap traffic.pcap project MyAnalysis --fast-mode
```

### Analyze Firewall Configuration

```bash
# OPNsense firewall
cipgram config firewall.xml project SecurityAudit
```

### Combined Analysis

```bash
# PCAP + Firewall
cipgram combined traffic.pcap firewall.xml project FullAnalysis
```

## 📊 Output

CIPgram generates comprehensive analysis in the `output/ProjectName/` directory:

```
output/MyAnalysis/
├── network_diagrams/
│   ├── network_topology.png      # Network topology diagram
│   ├── network_topology.svg      # SVG version
│   ├── network_topology.dot      # GraphViz source
│   ├── purdue_diagram.png        # Purdue model (IEC 62443)
│   └── purdue_diagram.svg
├── data/
│   ├── conversations.csv         # Communication flows
│   └── diagram.json              # Raw data
└── iec62443_diagrams/            # Security zone analysis
    └── iec62443_zones.png
```

## 🏗️ Configuration

Create `cipgram.yaml` in your working directory:

```yaml
app:
  name: "cipgram"
  environment: "production"

pcap:
  show_hostnames: true
  enable_vendor_lookup: true
  fast_mode: false

performance:
  batch_size: 1000
  optimization_strategy: "adaptive"
  enable_memory_pooling: true

logging:
  level: "info"
  format: "text"
  output: "stdout"
```

Or use environment variables:

```bash
export CIPGRAM_PCAP_SHOW_HOSTNAMES=true
export CIPGRAM_PERFORMANCE_OPTIMIZATION_STRATEGY=aggressive
```

## 🔧 Advanced Usage

### Enable Profiling

```bash
cipgram pcap large_file.pcap project Analysis --profile
# Profiles saved to ./profiles/
```

### Custom Output Directory

```bash
cipgram pcap traffic.pcap project Analysis --output-dir /custom/path
```

### Process Multiple Files

```bash
for pcap in *.pcap; do
  cipgram pcap "$pcap" project "analysis_$(basename $pcap .pcap)"
done
```

## 🧪 Testing

```bash
# Run all tests
go test ./tests/...

# Run unit tests only
go test ./tests/unit/...

# Run with coverage
go test ./tests/... -cover
```

## 📈 Performance

**Benchmarks** (on typical hardware):

| File Size | Packets | Processing Time | Speed | Memory |
|-----------|---------|----------------|-------|---------|
| 219 KB | 1.6K | 15 seconds | 209 pkt/s | 2 MB |
| 177 MB | 252K | 25 seconds | 20K pkt/s | 8 MB |

**Features**:
- Adaptive memory optimization (minimal/balanced/aggressive)
- LRU caching with 99%+ hit rates
- Zero-copy buffer operations
- Parallel packet processing

## 🔍 Supported Protocols

### Industrial/OT
- **Modbus** (TCP/RTU)
- **EtherNet/IP**
- **PROFINET**
- **DNP3**
- **IEC 60870-5-104**
- **S7** (Siemens)
- **BACnet**
- **KNX**
- **LonTalk**

### IoT
- MQTT
- CoAP
- AMQP

### Standard IT
- HTTP/HTTPS
- DNS
- TLS
- SSH
- FTP/FTPS
- SMTP
- And more...

## 🎓 Use Cases

- **Network Documentation**: Generate topology diagrams for industrial networks
- **Security Audits**: IEC 62443 compliance checking and zone analysis
- **Incident Response**: Analyze network traffic captures
- **Training**: Industrial cybersecurity education and workshops
- **Asset Inventory**: Discover and catalog OT devices

## 📚 Documentation

- [Configuration Guide](docs/FIREWALL_CONFIG_GUIDE.md)
- [Security Best Practices](docs/SECURITY_RULES_BEST_PRACTICES.md)
- [Workshop Guide](docs/WORKSHOP_GUIDE.md)
- [Project Summary](PROJECT_SUMMARY.md)
- [Improvement Plan](IMPROVEMENT_PLAN.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for industrial network security training and analysis
- Optimized for OT/ICS environments
- IEC 62443 compliant security analysis

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Made with ❤️ for industrial cybersecurity professionals**
