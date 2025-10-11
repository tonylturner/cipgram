# CIPgram Enhanced Output Structure

## 🎉 **New Features Implemented!**

### 📁 **Organized Directory Structure**
CIPgram now automatically creates organized output directories based on your pcap filename:

```bash
# Instead of cluttering your current directory with files
./cipgram -pcap network_capture.pcap

# Now creates organized structure:
diagrams/
└── network_capture/
    ├── diagram.dot         # Graphviz network definition
    ├── diagram.json        # Detailed analysis data
    ├── diagram.png         # Auto-generated network image
    ├── diagram.svg         # Scalable vector version
    └── diagram_hires.png   # High-resolution version
```

### 🖼️ **Automatic Image Generation**
- **No more manual DOT conversion!** CIPgram automatically generates:
  - **PNG**: Standard network diagram (perfect for sharing)
  - **SVG**: Scalable vector graphics (great for presentations)
  - **High-res PNG**: Large format for detailed analysis
- Gracefully handles missing Graphviz (just skips image generation)
- Works seamlessly on macOS, Linux, and Windows

### 🚀 **Enhanced User Experience**

#### Live Capture Support:
```bash
sudo ./cipgram -iface en0
# Creates: diagrams/live_capture_1634567890/
```

#### Custom Output Paths (Optional):
```bash
# Still works if you want custom paths
./cipgram -pcap network.pcap -out custom/my_diagram.dot -json custom/my_data.json
```

#### Image Generation Control:
```bash
# Disable image generation if desired
./cipgram -pcap network.pcap -images=false
```

### 📊 **Progress Reporting**
The tool now provides detailed progress information:
- Packet processing counts (every 1000 packets)
- Host and flow discovery statistics
- File generation confirmations
- Clear output directory information

### 🎯 **Example Output**
```
=== CIPgram Analysis Complete ===
Output directory: diagrams/industrial_network/
• DOT file: diagrams/industrial_network/diagram.dot
• JSON file: diagrams/industrial_network/diagram.json  
• PNG/SVG images generated (if Graphviz available)
Analyzed 15 hosts across 42 communication flows
```

## 🔧 **Implementation Details**

- **`createOutputDir()`**: Extracts pcap filename and creates organized directory structure
- **`generateImage()`**: Automatically creates PNG, SVG, and high-res versions using Graphviz
- **Enhanced main()**: Integrated directory creation and image generation into analysis workflow
- **Smart fallbacks**: Works even without Graphviz installed (just skips images)

## 📈 **Benefits**

1. **Clean Organization**: No more cluttered working directories
2. **Ready-to-Share**: Images automatically generated and ready to view
3. **Batch Analysis**: Each pcap gets its own organized folder
4. **Professional Output**: High-quality visualizations in multiple formats
5. **Zero Configuration**: Works out of the box with intelligent defaults

Your CIPgram tool now provides a complete, professional-grade industrial network analysis experience with organized outputs and beautiful visualizations!
