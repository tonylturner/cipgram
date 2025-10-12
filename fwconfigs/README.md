# Firewall Configuration Samples

This directory contains sample OPNsense firewall configurations for OT network security training and testing.

## Configuration Files

### 1. **opnsense_paintshop_sample.xml** - Automotive Paint Shop
- **Scenario**: Automotive paint and body shop with mixed security
- **Networks**: Corporate, SMZ, Assembly, Paint Shop, Maintenance, DMZ
- **Security Level**: Medium - Some good practices, some weak rules
- **Key Features**: Port aliases, zone-based rules, some any-to-any issues
- **Best For**: General OT segmentation training

### 2. **water_treatment_secure.xml** - Water Treatment Plant (SECURE)
- **Scenario**: Municipal water treatment facility
- **Networks**: Corporate, SCADA (L2), HMI (L1), Field Devices (L0), Historian DMZ, VPN
- **Security Level**: High - Well-implemented Purdue Model
- **Key Features**: 
  - Strict Purdue Model implementation
  - Protocol-specific rules (Modbus, S7, CIP)
  - Field devices completely isolated
  - Historian in DMZ
  - Comprehensive deny rules
- **Best For**: Demonstrating security best practices

### 3. **manufacturing_insecure.xml** - Plastics Manufacturing (INSECURE)
- **Scenario**: Plastics manufacturing plant with terrible security
- **Networks**: Main, Production Line A/B, Quality Control, Maintenance
- **Security Level**: Very Low - Multiple critical vulnerabilities
- **Key Features**:
  - LAN-to-any rules (complete bypass)
  - Production networks with internet access
  - Vendor remote access from internet
  - Insecure protocols (Telnet)
  - No network segmentation
- **Best For**: Security violation identification training

### 4. **power_substation_mixed.xml** - Power Substation (MIXED)
- **Scenario**: Electric utility substation
- **Networks**: Control Center, SCADA, Protection Relays, Substation Automation, Engineering, Historian DMZ
- **Security Level**: Medium - Good practices with some gaps
- **Key Features**:
  - IEC 61850 protocol support
  - Protection relays properly isolated
  - SCADA internet access (risky)
  - Engineering broad access
  - Emergency vendor access
- **Best For**: Realistic utility security assessment

### 5. **test_industrial_config.xml** - Simple Test Configuration
- **Scenario**: Basic industrial setup for testing
- **Networks**: WAN, LAN, Corporate, DMZ, Manufacturing Cell
- **Security Level**: Basic - Minimal rules
- **Best For**: Parser testing and basic functionality

### 6. **weak_test_config.xml** - Weak Security Test
- **Scenario**: Simple configuration with dangerous rules
- **Networks**: Basic setup with LAN-to-any rules
- **Security Level**: Very Low - Designed to trigger security warnings
- **Best For**: Testing risk detection algorithms

## Usage Examples

### Analyze a secure configuration:
```bash
./cipgram -firewall-config fwconfigs/water_treatment_secure.xml -project "water_secure_analysis"
```

### Test risk detection on insecure config:
```bash
./cipgram -firewall-config fwconfigs/manufacturing_insecure.xml -project "manufacturing_risks"
```

### Compare mixed security approach:
```bash
./cipgram -firewall-config fwconfigs/power_substation_mixed.xml -project "utility_assessment"
```

## Training Scenarios

1. **Best Practices Workshop**: Use `water_treatment_secure.xml` to show proper Purdue Model implementation
2. **Vulnerability Identification**: Use `manufacturing_insecure.xml` to practice finding security issues
3. **Risk Assessment**: Use `power_substation_mixed.xml` for realistic security evaluation
4. **Comparative Analysis**: Run multiple configs to compare security postures

## Industrial Protocols Covered

- **Modbus TCP** (Port 502) - Manufacturing, water treatment
- **DNP3** (Port 20000) - Power utilities
- **IEC 61850** (Ports 102, 2404) - Power substation automation
- **EtherNet/IP** (Port 44818) - Industrial Ethernet
- **S7** (Port 102) - Siemens PLCs
- **MQTT** (Ports 1883, 8883) - IoT messaging

## Security Patterns Demonstrated

### Good Practices:
- Purdue Model implementation
- Protocol-specific restrictions  
- DMZ for historians
- Explicit deny rules
- Zone-based segmentation

### Common Issues:
- Any-to-any rules
- Production internet access
- Insecure protocols (Telnet)
- Overly broad engineering access
- Missing inter-zone blocks

These configurations provide comprehensive training material for OT network security workshops and assessments.
