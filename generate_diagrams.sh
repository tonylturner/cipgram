#!/bin/bash

# CIPgram Visualization Generator
# This script helps generate various visualization formats from CIPgram output

set -e

DOT_FILE=${1:-"diagram.dot"}
OUTPUT_PREFIX=${2:-"network"}

if [ ! -f "$DOT_FILE" ]; then
    echo "Error: DOT file '$DOT_FILE' not found."
    echo "Usage: $0 [dot_file] [output_prefix]"
    echo "Example: $0 diagram.dot industrial_network"
    exit 1
fi

echo "=== CIPgram Visualization Generator ==="
echo "Input: $DOT_FILE"
echo "Output prefix: $OUTPUT_PREFIX"
echo ""

# Check if Graphviz is installed
if ! command -v dot >/dev/null 2>&1; then
    echo "Error: Graphviz not found."
    echo ""
    echo "Install Graphviz:"
    echo "• macOS: brew install graphviz"
    echo "• Ubuntu/Debian: sudo apt-get install graphviz"
    echo "• RHEL/CentOS: sudo yum install graphviz"
    exit 1
fi

echo "✓ Graphviz found"

# Generate different formats
echo ""
echo "Generating visualizations..."

# PNG - Good for web/presentations
echo "• PNG format..."
dot -Tpng "$DOT_FILE" -o "${OUTPUT_PREFIX}.png"

# SVG - Scalable vector graphics
echo "• SVG format..."
dot -Tsvg "$DOT_FILE" -o "${OUTPUT_PREFIX}.svg"

# PDF - Good for reports
echo "• PDF format..."
dot -Tpdf "$DOT_FILE" -o "${OUTPUT_PREFIX}.pdf"

# Large network layout (if needed)
echo "• Large network PNG..."
dot -Tpng -Gdpi=150 -Gsize="20,15!" -Gratio=fill "$DOT_FILE" -o "${OUTPUT_PREFIX}_large.png"

echo ""
echo "✓ Visualization files created:"
echo "  - ${OUTPUT_PREFIX}.png (standard)"
echo "  - ${OUTPUT_PREFIX}.svg (scalable)"
echo "  - ${OUTPUT_PREFIX}.pdf (document)"
echo "  - ${OUTPUT_PREFIX}_large.png (high-res)"

echo ""
echo "=== Layout Tips ==="
echo "For complex networks, try different layout engines:"
echo "• dot -Kneato: Force-directed layout"
echo "• dot -Kfdp: Force-directed with overlap removal"
echo "• dot -Ksfdp: Scaled force-directed"
echo "• dot -Kcirco: Circular layout"

echo ""
echo "Example with different layout:"
echo "  dot -Kneato -Tpng $DOT_FILE -o ${OUTPUT_PREFIX}_neato.png"
