# Creating Diagrams from Firewall Configurations

## 🔧 **Two Ways to Analyze Firewall Configs**

### **Method 1: Quick Script (Available Now)**
```bash
# Use the ready-made script
./analyze_firewall_config.sh your_opnsense_config.xml factory_audit

# This will create:
# output/factory_audit/firewall_analysis/network_topology.dot
# output/factory_audit/firewall_analysis/iec62443_zones.dot
```

### **Method 2: Main Command (Enhanced)**
I've added firewall config support to your main command:

```bash
# Build with new firewall support
go build -o cipgram

# Firewall-only analysis
./cipgram -firewall-config config.xml -project "security_audit"

# Combined PCAP + Firewall analysis  
./cipgram -pcap traffic.pcap -firewall-config config.xml -project "full_assessment"
```

## 📁 **Supported Config Types**

### ✅ **OPNsense** (Ready)
- Export from System > Configuration > Backups
- Download as `config.xml`
- Supports full network topology and policy analysis

### 🔜 **Future Support**
- **pfSense** configurations
- **FortiGate** configurations  
- **Generic firewall** rule imports

## 🎯 **What Gets Generated**

### **Network Topology Diagram**
- Shows actual network structure from firewall interfaces
- Network segments with CIDR ranges
- Security policy flows between zones

### **IEC 62443 Zone Diagram**  
- Compliance-focused view
- Zone classifications and boundaries
- Conduit connections between zones
- Risk levels by zone

### **Analysis Data**
- JSON export of all network and policy information
- Security policy effectiveness analysis
- Segmentation opportunity identification

## 🏭 **Perfect for Training Workshops**

### **Workshop Scenario 1: Firewall Audit**
```bash
./cipgram -firewall-config student_firewall.xml -project "security_review"
```
**Students Learn:**
- Network topology visualization
- IEC 62443 zone compliance
- Security policy analysis

### **Workshop Scenario 2: Before/After Comparison**
```bash
# Analyze current state
./cipgram -firewall-config current_config.xml -project "before_segmentation"

# Analyze improved state  
./cipgram -firewall-config improved_config.xml -project "after_segmentation"
```

### **Workshop Scenario 3: Combined Analysis**
```bash
# Full network assessment
./cipgram -pcap network_traffic.pcap -firewall-config firewall.xml -project "complete_audit"
```
**Shows:**
- What the firewall *should* allow vs what traffic *actually* flows
- Policy violations and unauthorized communications
- Segmentation opportunities

## 🚀 **Try It Now**

You have a test config ready:
```bash
cd /Users/tturner/Documents/GitHub/cipgram

# Quick test with existing sample
./analyze_firewall_config.sh tests/configs/opnsense/test_opnsense_config.xml demo_audit

# Or build and use main command
go build -o cipgram
./cipgram -firewall-config tests/configs/opnsense/test_opnsense_config.xml -project "demo_firewall"
```

This will create professional network diagrams showing your firewall's network topology and IEC 62443 compliance zones! 🎉
