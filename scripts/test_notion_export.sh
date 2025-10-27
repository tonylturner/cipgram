#!/bin/bash

# Test the Notion export functionality with existing CIPgram output

echo "🧪 Testing Notion Export with Sample Analysis"

# Test with an existing configuration
TEST_CONFIG="fwconfigs/manufacturing_insecure.xml"
TEST_PROJECT="notion_test"

if [ ! -f "$TEST_CONFIG" ]; then
    echo "❌ Test configuration not found: $TEST_CONFIG"
    echo "💡 Please ensure you're in the CIPgram root directory"
    exit 1
fi

echo "🔨 Building CIPgram..."
go build -o cipgram ./cmd/cipgram

echo "🔍 Running analysis on test configuration..."
./cipgram -firewall-config "$TEST_CONFIG" -project "$TEST_PROJECT"

echo "📊 Generating Notion export..."
./scripts/notion_export.sh "$TEST_PROJECT"

echo ""
echo "✅ Test complete! Check the notion_exports/ directory for:"
echo "   - ${TEST_PROJECT}_assets.csv"
echo "   - ${TEST_PROJECT}_findings.csv" 
echo "   - ${TEST_PROJECT}_compliance.csv"
echo "   - ${TEST_PROJECT}_diagrams.md"
echo ""
echo "🎓 These files are ready to import into your Notion lab workbook!"
