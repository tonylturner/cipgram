#!/bin/bash

# CIPgram Integration Test Runner
# Runs all integration tests with organized output structure

set -e

echo "🧪 **CIPgram Integration Test Suite**"
echo "═══════════════════════════════════════"
echo ""

# Build the project first
echo "🔨 Building CIPgram..."
cd ../..
go build -o cipgram
echo "✓ Build completed"
echo ""

# Return to tests directory
cd tests/integration

# Test 1: OPNsense Integration
echo "Test 1: OPNsense Configuration Analysis"
echo "────────────────────────────────────────"

if [ -f "../configs/opnsense/test_opnsense_config.xml" ]; then
    go run test_opnsense.go
    echo ""
else
    echo "⚠️  Skipping OPNsense test - config file not found"
    echo "   Place OPNsense config at: tests/configs/opnsense/test_opnsense_config.xml"
    echo ""
fi

# Test 2: PCAP Analysis (when sample files available)
echo "Test 2: PCAP Analysis"
echo "──────────────────────"

if [ -f "../pcaps/samples/industrial_sample.pcap" ]; then
    echo "✓ Running PCAP analysis test..."
    # Future: add PCAP test
    echo "   (PCAP integration test pending sample data)"
else
    echo "⚠️  Skipping PCAP test - sample file not found"
    echo "   Place sample PCAP at: tests/pcaps/samples/industrial_sample.pcap"
fi
echo ""

# Test 3: Combined Analysis (when both sources available)
echo "Test 3: Combined Analysis"
echo "─────────────────────────"
echo "⚠️  Combined analysis test requires matching PCAP and firewall config"
echo "   This will be available when you add data from your OT lab"
echo ""

# Show test results
echo "📊 **Test Results Summary**"
echo "═══════════════════════════"
echo ""

if [ -d "../../output" ]; then
    echo "Output directory structure:"
    find ../../output -type d | head -20 | sort
    echo ""
    
    echo "Generated test projects:"
    ls -la ../../output/ | grep "^d" | awk '{print "  • " $9}' | grep -v "^\.$\|^\.\.$"
else
    echo "No output generated (tests may have been skipped)"
fi

echo ""
echo "🎯 **Integration tests completed!**"
echo "📁 Test outputs available in: ../../output/"
echo "📖 For more details, see project summary files in each test directory"
