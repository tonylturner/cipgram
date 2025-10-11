#!/bin/bash

# Quick Firewall Config Analysis Script
# This demonstrates using your existing firewall analysis infrastructure

echo "🔧 CIPgram Firewall Configuration Analysis"
echo "=========================================="

# Check if config file is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <config.xml> <project-name>"
    echo "Example: $0 opnsense_config.xml factory_analysis"
    exit 1
fi

CONFIG_FILE="$1"
PROJECT_NAME="$2"

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Config file not found: $CONFIG_FILE"
    exit 1
fi

echo "📁 Input: $CONFIG_FILE"
echo "🎯 Project: $PROJECT_NAME"
echo ""

# Create output directory
OUTPUT_DIR="output/${PROJECT_NAME}"
mkdir -p "$OUTPUT_DIR/firewall_analysis"
mkdir -p "$OUTPUT_DIR/iec62443_diagrams"
mkdir -p "$OUTPUT_DIR/data"

echo "📊 Analyzing firewall configuration..."

# Copy config to project for processing
cp "$CONFIG_FILE" "tests/configs/opnsense/test_opnsense_config.xml"

# Run firewall analysis using existing test
cd tests/integration
go run test_firewall_diagrams.go

# Move results to proper project structure
if [ -d "firewall_diagrams" ]; then
    echo "📁 Moving results to project structure..."
    mv firewall_diagrams/* "../../${OUTPUT_DIR}/firewall_analysis/"
    rmdir firewall_diagrams
    
    echo "✅ Analysis complete!"
    echo ""
    echo "📊 Results available in:"
    echo "   • ${OUTPUT_DIR}/firewall_analysis/network_topology.dot"
    echo "   • ${OUTPUT_DIR}/firewall_analysis/iec62443_zones.dot"
    echo "   • ${OUTPUT_DIR}/firewall_analysis/network_topology.png (if Graphviz available)"
    echo "   • ${OUTPUT_DIR}/firewall_analysis/iec62443_zones.png (if Graphviz available)"
else
    echo "❌ Analysis failed - check config file format"
fi

echo ""
echo "🎯 To convert DOT files to images manually:"
echo "   dot -Tpng ${OUTPUT_DIR}/firewall_analysis/network_topology.dot -o ${OUTPUT_DIR}/firewall_analysis/network_topology.png"
echo "   dot -Tsvg ${OUTPUT_DIR}/firewall_analysis/iec62443_zones.dot -o ${OUTPUT_DIR}/firewall_analysis/iec62443_zones.svg"
