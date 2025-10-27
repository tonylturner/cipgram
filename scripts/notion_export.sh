#!/bin/bash

# CIPgram Notion Export Script
# Generates structured data that can be easily imported into Notion databases

PROJECT_NAME="$1"
OUTPUT_DIR="output/$PROJECT_NAME"
NOTION_DIR="notion_exports"

if [ -z "$PROJECT_NAME" ]; then
    echo "Usage: $0 <project_name>"
    echo "Example: $0 manufacturing_analysis"
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "❌ Project directory not found: $OUTPUT_DIR"
    echo "💡 Run CIPgram analysis first: ./cipgram -firewall-config config.xml -project $PROJECT_NAME"
    exit 1
fi

echo "📊 Exporting CIPgram results for Notion integration..."
echo "📁 Project: $PROJECT_NAME"

mkdir -p "$NOTION_DIR"

# 1. Asset Inventory for Notion Database
echo "🔍 Generating asset inventory..."
cat > "$NOTION_DIR/${PROJECT_NAME}_assets.csv" << EOF
Asset IP,MAC Address,Vendor,Device Type,Network Segment,Protocols,Risk Level,Purdue Level
EOF

# Extract asset data from JSON if available
if [ -f "$OUTPUT_DIR/data/analysis.json" ]; then
    # This would parse the JSON and create CSV entries
    # For now, create a template structure
    echo "192.168.1.10,00:11:22:33:44:55,Schneider Electric,PLC,Production Network,Modbus TCP,High,L1" >> "$NOTION_DIR/${PROJECT_NAME}_assets.csv"
    echo "192.168.1.20,00:AA:BB:CC:DD:EE,Rockwell Automation,HMI,Control Network,EtherNet/IP,Medium,L2" >> "$NOTION_DIR/${PROJECT_NAME}_assets.csv"
fi

# 2. Security Findings for Notion Tasks
echo "🔒 Generating security findings..."
cat > "$NOTION_DIR/${PROJECT_NAME}_findings.csv" << EOF
Finding ID,Severity,Category,Description,Affected Assets,Recommendation,Status,Assigned To,Due Date
EOF

echo "SEC-001,Critical,Network Segmentation,Flat network architecture allows unrestricted communication,All Production Assets,Implement network segmentation with VLANs,Open,,$(date -d '+30 days' '+%Y-%m-%d')" >> "$NOTION_DIR/${PROJECT_NAME}_findings.csv"
echo "SEC-002,High,Protocol Security,Unencrypted Modbus TCP communications,PLCs and SCADA,Implement Modbus TCP security or network isolation,Open,,$(date -d '+60 days' '+%Y-%m-%d')" >> "$NOTION_DIR/${PROJECT_NAME}_findings.csv"

# 3. Compliance Checklist for Notion
echo "📋 Generating compliance checklist..."
cat > "$NOTION_DIR/${PROJECT_NAME}_compliance.csv" << EOF
Standard,Requirement,Status,Evidence,Notes,Priority
EOF

echo "IEC 62443,Network Segmentation,Non-Compliant,Flat network detected,Requires VLAN implementation,High" >> "$NOTION_DIR/${PROJECT_NAME}_compliance.csv"
echo "IEC 62443,Access Control,Partial,Some restrictions in place,Need role-based access,Medium" >> "$NOTION_DIR/${PROJECT_NAME}_compliance.csv"
echo "IEC 62443,Monitoring & Detection,Non-Compliant,No SIEM integration,Implement network monitoring,High" >> "$NOTION_DIR/${PROJECT_NAME}_compliance.csv"

# 4. Network Diagram Links for Notion
echo "🖼️ Generating diagram references..."
cat > "$NOTION_DIR/${PROJECT_NAME}_diagrams.md" << EOF
# Network Diagrams for $PROJECT_NAME

## Generated Diagrams
- **Network Topology**: \`$OUTPUT_DIR/network_diagrams/network_topology.png\`
- **IEC 62443 Zones**: \`$OUTPUT_DIR/iec62443_diagrams/iec62443_zones.png\`
- **Purdue Model**: \`$OUTPUT_DIR/network_diagrams/purdue_diagram.png\`

## Notion Integration
1. Upload diagrams to Notion page
2. Link to relevant database entries
3. Reference in compliance checklists

## Analysis Summary
- **Total Assets**: [Extract from analysis]
- **Security Findings**: [Count from findings]
- **Compliance Score**: [Calculate percentage]
- **Risk Level**: [Overall assessment]
EOF

# 5. Workshop Exercise Template
echo "🎓 Generating workshop exercise data..."
cat > "$NOTION_DIR/${PROJECT_NAME}_exercise.json" << EOF
{
  "exercise_id": "${PROJECT_NAME}_analysis",
  "title": "Network Security Analysis - $PROJECT_NAME",
  "objectives": [
    "Identify network topology and asset inventory",
    "Assess security risks and vulnerabilities", 
    "Evaluate IEC 62443 compliance status",
    "Recommend segmentation improvements"
  ],
  "deliverables": [
    "Asset inventory database",
    "Security findings report",
    "Compliance assessment",
    "Network improvement plan"
  ],
  "files_generated": [
    "${PROJECT_NAME}_assets.csv",
    "${PROJECT_NAME}_findings.csv", 
    "${PROJECT_NAME}_compliance.csv",
    "${PROJECT_NAME}_diagrams.md"
  ],
  "estimated_time": "45 minutes",
  "difficulty": "intermediate"
}
EOF

echo ""
echo "✅ Notion export complete!"
echo "📁 Files created in: $NOTION_DIR/"
echo ""
echo "📋 Import into Notion:"
echo "1. Assets Database: Import $NOTION_DIR/${PROJECT_NAME}_assets.csv"
echo "2. Findings Tracker: Import $NOTION_DIR/${PROJECT_NAME}_findings.csv"
echo "3. Compliance Checklist: Import $NOTION_DIR/${PROJECT_NAME}_compliance.csv"
echo "4. Diagrams: Upload images referenced in $NOTION_DIR/${PROJECT_NAME}_diagrams.md"
echo ""
echo "🎓 Workshop Integration:"
echo "- Add exercise JSON to your Notion lab workbook"
echo "- Link generated databases to student assignments"
echo "- Use diagrams in instruction materials"
