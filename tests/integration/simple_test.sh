#!/bin/bash

# Simple test to debug the integration test issue

set -e

echo "🧪 Simple CIPgram Test"
echo "====================="

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "Project root: $PROJECT_ROOT"

cd "$PROJECT_ROOT"

# Build
echo "Building..."
make build

# Test with smallest PCAP
echo "Testing with PROFINET.pcap..."
./cipgram pcap pcaps/PROFINET.pcap project simple_test

# Check output
echo "Checking output..."
if [[ -d "output/simple_test" ]]; then
    echo "✓ Output directory created"
    find output/simple_test -type f | head -10
else
    echo "✗ Output directory not found"
    exit 1
fi

echo "✅ Simple test completed successfully!"
