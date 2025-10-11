#!/bin/bash

# CIPgram Test Script
# This script demonstrates how to use the CIPgram tool

set -e

echo "=== CIPgram Industrial Network Analyzer ==="
echo "🎯 Now with organized output directories and automatic image generation!"
echo ""

# Check if the binary exists
if [ ! -f "./cipgram" ]; then
    echo "Error: cipgram binary not found. Please run 'go build -o cipgram main.go' first."
    exit 1
fi

echo "✓ CIPgram binary found"

# Test the new directory structure
echo ""
echo "=== New Features ===
🗂️  Organized output: diagrams/\$pcapname/
🖼️  Automatic image generation (PNG, SVG, high-res)
🧠 Intelligent classification (no config required)
📊 Enhanced analysis with 20+ protocols"
echo ""

# Check if we have a sample pcap file
if [ -f "sample_industrial.pcap" ]; then
    echo "✓ Sample pcap file found, analyzing with new organized output..."
    
    # Run analysis - will create diagrams/sample_industrial/ directory
    ./cipgram -pcap sample_industrial.pcap
    
    echo ""
    echo "✓ Analysis complete! Check the organized output:"
    echo "📁 Directory: diagrams/sample_industrial/"
    ls -la diagrams/sample_industrial/ 2>/dev/null || echo "   (Directory will be created after analysis)"
    
else
    echo "⚠ No sample pcap file found."
    echo ""
    echo "🚀 To test CIPgram's new organized output:"
    echo ""
    echo "1. 📁 Automatic directory creation:"
    echo "   ./cipgram -pcap your_file.pcap"
    echo "   → Creates: diagrams/your_file/"
    echo ""
    echo "2. 🖼️ Images generated automatically:"
    echo "   • diagram.png (standard view)"
    echo "   • diagram.svg (scalable)"  
    echo "   • diagram_hires.png (high resolution)"
    echo ""
    echo "3. 📊 All files organized:"
    echo "   • diagram.dot (source)"
    echo "   • diagram.json (data)"
    echo ""
    echo "4. 🔴 Live capture creates timestamped directories:"
    echo "   sudo ./cipgram -iface en0"
    echo "   → Creates: diagrams/live_capture_timestamp/"
fi

echo ""
echo "=== Configuration Files ==="
if [ -f "purdue_config.yaml" ]; then
    echo "✓ Configuration file: purdue_config.yaml"
else
    echo "⚠ Configuration file not found"
fi

if [ -f "README.md" ]; then
    echo "✓ Documentation: README.md"
else
    echo "⚠ README.md not found"
fi

echo ""
echo "=== Supported Protocols ==="
echo "• EtherNet/IP (CIP) - TCP/44818, UDP/2222"
echo "• Modbus TCP - 502"
echo "• DNP3 - 20000"
echo "• BACnet/IP - 47808"
echo "• OPC-UA - 4840"
echo "• S7Comm - 102"
echo "• FINS/Omron - 9600"
echo "• SLMP/Mitsubishi - 5007"
echo "• Profinet DCP/RT"
echo "• And many more..."

echo ""
echo "=== Next Steps ==="
echo "1. Obtain a pcap file of industrial network traffic"
echo "2. Run: ./cipgram -pcap your_file.pcap -config purdue_config.yaml"
echo "3. View results: diagram.dot and diagram.json"
echo "4. Generate visualization: dot -Tpng diagram.dot -o network.png"
echo ""
echo "For more information, see README.md"
