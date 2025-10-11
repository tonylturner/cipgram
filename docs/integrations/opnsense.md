# OPNsense Integration Guide

## Overview
CIPgram can parse OPNsense firewall configurations to extract network topology, security policies, and perform IEC 62443 zone analysis.

## Supported Features

### Configuration Parsing
- **Network interfaces** with IP addressing and CIDR notation
- **Firewall rules** including source, destination, protocol, and action
- **Network aliases** for grouping and reference
- **System information** for context

### Automatic Analysis
- **IEC 62443 zone classification** based on interface names and purposes
- **Risk assessment** by network segment
- **Security policy extraction** for compliance analysis

## Getting OPNsense Configuration

### Method 1: Web Interface Export
1. Log into OPNsense web interface
2. Navigate to **System > Configuration > Backups**
3. Click **Download configuration** 
4. Save as `config.xml`

### Method 2: SSH/Console Export
```bash
# On OPNsense system
cp /conf/config.xml /tmp/backup_config.xml
scp /tmp/backup_config.xml user@analysis-host:configs/
```

## Configuration Analysis

### Basic Analysis
```bash
./cipgram -firewall-config configs/opnsense_config.xml -project "factory_security_audit"
```

### Advanced Options
```bash
./cipgram -firewall-config configs/config.xml \
          -project "compliance_assessment" \
          -output-format "both" \
          -include-policies \
          -iec62443-analysis
```

## Zone Classification Rules

CIPgram automatically infers IEC 62443 zones based on:

### **Manufacturing Zone** (Level 0-2)
- Interfaces named `lan`, `production`, `ot`
- Networks with industrial device indicators
- Default for most internal networks

### **DMZ Zone** (Network Perimeter)  
- Interfaces named `wan`, `dmz`, `perimeter`
- Internet-facing or inter-network connections

### **Enterprise Zone** (Level 3-5)
- Interfaces named `management`, `admin`, `enterprise`
- Networks with IT/business system indicators

### **Remote Access Zone**
- VPN interfaces (`wireguard`, `openvpn`)
- Remote access configurations

## Output Analysis

### Network Topology Diagram
Shows actual network structure from firewall configuration:
- Network segments with CIDR ranges
- Interface relationships
- Security policy flows

### IEC 62443 Zone Diagram
Compliance-focused view showing:
- Zone classifications and boundaries
- Conduit connections between zones
- Risk levels by zone

### Security Policy Analysis
Detailed firewall rule analysis:
- Rule effectiveness and coverage
- Policy violations and gaps
- Segmentation opportunities

## Common Issues

### Missing Network Information
**Problem**: Interfaces show no IP/CIDR information
**Solution**: Ensure static IP configuration or check DHCP assignments

### Incorrect Zone Classification
**Problem**: Networks assigned to wrong IEC 62443 zones
**Solution**: Use descriptive interface names or manual classification overrides

### Complex Rule Analysis
**Problem**: Floating rules or complex aliases not properly parsed
**Solution**: Simplify rule structure or use manual policy documentation

## Integration with PCAP Analysis

When combined with PCAP traffic analysis:
```bash
./cipgram -pcap network_traffic.pcap \
          -firewall-config opnsense_config.xml \
          -project "complete_assessment"
```

Provides:
- **Policy validation** against actual traffic
- **Unauthorized communication detection**
- **Segmentation opportunity identification**
- **Compliance gap analysis**

## Best Practices

### Configuration Preparation
1. **Use descriptive interface names** (e.g., "Production_OT", "SCADA_DMZ")
2. **Document firewall rules** with clear descriptions
3. **Group related networks** using aliases
4. **Regular configuration backups** for trend analysis

### Analysis Workflow
1. Export current configuration
2. Run initial analysis to identify issues
3. Compare with previous analyses for changes
4. Generate compliance reports
5. Plan segmentation improvements

## Troubleshooting

### Parse Errors
```bash
# Validate XML structure
xmllint --noout config.xml

# Check file permissions
ls -la config.xml
```

### Missing Analysis Data
```bash
# Enable debug output
./cipgram -firewall-config config.xml -debug -verbose
```

For additional support, see the main documentation or submit an issue with your configuration structure (sanitized).
