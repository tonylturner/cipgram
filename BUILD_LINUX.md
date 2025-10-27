# Building CIPgram on Linux

## Quick Start (Ubuntu/Debian)

```bash
# 1. Install dependencies
sudo apt-get update
sudo apt-get install -y git golang-go libpcap-dev graphviz

# 2. Clone repository
git clone https://github.com/yourusername/cipgram.git
cd cipgram

# 3. Build
go build ./cmd/cipgram/

# This creates a binary named 'cipgram' in the current directory
# Or use: go build -o cipgram ./cmd/cipgram/

# 4. Test it works
./cipgram version

# 5. Install system-wide (optional)
sudo cp cipgram /usr/local/bin/
sudo chmod +x /usr/local/bin/cipgram

# Verify installation
cipgram version
```

## Quick Start (RHEL/CentOS/Fedora)

```bash
# 1. Install dependencies
sudo yum install -y git golang libpcap-devel graphviz

# Or on Fedora/newer RHEL:
sudo dnf install -y git golang libpcap-devel graphviz

# 2-5. Same as Ubuntu above
```

## Verify Installation

```bash
# Check version
cipgram version

# Quick test with sample PCAP
cipgram pcap pcaps/PROFINET.pcap project TestRun

# View output
ls -la output/TestRun/
```

## Troubleshooting

### "libpcap.so not found"
```bash
# Ubuntu/Debian
sudo apt-get install libpcap0.8

# RHEL/CentOS
sudo yum install libpcap
```

### "graphviz not found" (diagrams won't generate)
```bash
# Ubuntu/Debian
sudo apt-get install graphviz

# RHEL/CentOS
sudo yum install graphviz
```

### Go version too old
CIPgram requires Go 1.20 or newer. Check your version:
```bash
go version

# If too old, install latest Go from https://golang.org/dl/
```

## Performance

CIPgram is optimized for Linux and runs great on:
- Physical servers
- VMs (minimal 2GB RAM recommended)
- Containers (Docker/Podman)
- Edge devices (Raspberry Pi 4+)

Typical performance: **20,000+ packets/second** on modern hardware.

