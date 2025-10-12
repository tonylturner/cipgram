# 🛡️ CIPgram Security Rules & Best Practices

This document outlines the security rules, patterns, and best practices that CIPgram uses to analyze firewall configurations and generate recommendations for OT network segmentation.

## 🎯 **Critical Security Violations Detected**

### **1. ANY-TO-ANY Rules (Highest Risk)**
- **Pattern**: Rules allowing `any source` → `any destination`
- **Risk Level**: 🚨 **CRITICAL**
- **Detection Logic**: `policy.Source.CIDR == "any" && policy.Destination.CIDR == "any"`
- **Why Dangerous**: Completely bypasses all network segmentation
- **Example**: `ALLOW lan → any` with `any protocol` and `any ports`
- **Recommendation**: Replace with specific source/destination networks and required ports only

### **2. Overly Broad Destination Rules**
- **Pattern**: Specific source → `any destination` with `any protocol/ports`
- **Risk Level**: 🚨 **CRITICAL** 
- **Detection Logic**: `isAnyDest && isAnyPorts && (protocol == "any" || protocol == "")`
- **Why Dangerous**: Allows unrestricted outbound access from critical networks
- **Example**: `ALLOW opt1 → any` with `any protocol`
- **Recommendation**: Restrict to specific destinations and protocols

### **3. Industrial Zone Risks**
- **Pattern**: Industrial Zone networks with overly broad access
- **Risk Level**: ⚠️ **HIGH RISK** - Critical OT Systems
- **Detection Logic**: `network.Zone == IndustrialZone && (isAnyDest && isAnyPorts)`
- **Why Dangerous**: OT networks should have very restricted, specific access patterns
- **Recommendation**: OT networks should only access specific MES/Historian/DNS servers

### **4. DMZ Zone Risks**
- **Pattern**: DMZ networks with unrestricted access
- **Risk Level**: 🌐 **MEDIUM RISK** - Internet-Exposed Systems
- **Detection Logic**: DMZ zone with `any source` or `any destination`
- **Why Dangerous**: DMZ should have minimal, controlled access patterns
- **Recommendation**: DMZ access should be limited to specific external endpoints

## 🏭 **Network Zone Classification Rules**

### **Zone Assignment Logic**
CIPgram automatically classifies networks into **network security zones** based on interface names and descriptions. These are network segmentation zones inspired by IEC 62443 principles but focused on firewall/network boundaries:

| **Interface Pattern** | **Assigned Zone** | **Risk Level** | **Reasoning** |
|----------------------|-------------------|----------------|---------------|
| **`wan`** | **DMZ Zone** | Medium | Internet-facing interfaces |
| **`lan`** | **Industrial Zone** | High | Typically contains OT devices |
| **`wireguard`** or "wireguard" in description | **Remote Access Zone** | Low | VPN connections |
| Description contains **`production`**, **`ot`**, **`scada`**, **`control`**, **`process`**, **`automation`** | **Industrial Zone** | High | Production/OT systems |
| Description contains **`dmz`** | **DMZ Zone** | Medium | Explicitly marked DMZ |
| Description contains **`management`**, **`admin`**, **`corp`**, **`corporate`**, **`office`**, **`business`**, **`enterprise`** | **Enterprise Zone** | Low | IT management networks |
| **Everything else** | **Enterprise Zone** | Low | Default fallback |

### **Industrial Keywords Detection**
The following terms trigger **Industrial Zone** classification:
- **Manufacturing**: `cell`, `line`, `plant`, `factory`, `manufacturing`, `industrial`
- **OT Protocols**: `scada`, `hmi`, `plc`, `control`, `process`, `automation`
- **Production Areas**: `field`, `shop`, `assembly`, `packaging`, `machining`, `welding`, `robotics`, `cnc`

## ⚠️ **Risk Assessment Rules**

### **Zone-Based Risk Calculation**
| **Zone** | **Risk Level** | **Justification** |
|----------|----------------|-------------------|
| **Industrial Zone** | **High Risk** | Contains critical OT systems, PLCs, HMIs, SCADA |
| **DMZ Zone** | **Medium Risk** | Internet-exposed but with some protection |
| **Enterprise Zone** | **Low Risk** | IT systems, typically more hardened |
| **Remote Access Zone** | **Low Risk** | VPN access, controlled entry point |

### **Rule Pattern Risk Factors**
1. **Any-to-Any Communication**: Immediate critical risk
2. **Internet Access from OT**: High risk (malware, remote attacks)
3. **Insecure Protocols**: Telnet (port 23), unencrypted protocols
4. **Vendor Remote Access**: Direct internet access to production systems
5. **Missing Inter-Zone Blocks**: No explicit deny rules between zones

## 🔒 **Security Best Practices Enforced**

### **1. Purdue Model Implementation**
- **Level 0-2 (Industrial Zone)**: Field devices, control systems, SCADA
- **Level 3-5 (Enterprise Zone)**: MES, ERP, corporate networks
- **DMZ**: Historians, web services, external interfaces
- **Principle**: Strict separation between levels, controlled communication paths

### **2. Protocol-Specific Restrictions**
**Good Practice Patterns Detected:**
- **Modbus TCP** (502): Only between SCADA and field devices
- **DNP3** (20000): Power utility protocols
- **IEC 61850** (102, 2404): Substation automation
- **EtherNet/IP** (44818): Industrial Ethernet
- **HTTPS** (443): Secure web interfaces only
- **SSH** (22): Secure administrative access

**Bad Practice Patterns Flagged:**
- **Telnet** (23): Insecure, flagged as critical risk
- **Any Protocol**: Overly permissive
- **HTTP** (80): Unencrypted web traffic in production

### **3. Network Segmentation Rules**

#### **✅ Good Segmentation Patterns:**
1. **Explicit Deny Rules**: Block inter-zone communication by default
2. **Specific Destinations**: Rules target specific servers/services
3. **Port Restrictions**: Only required protocols/ports allowed
4. **DMZ Isolation**: Historians/web services in separate DMZ
5. **VPN Access**: Remote access through controlled VPN zones

#### **❌ Bad Segmentation Patterns:**
1. **Flat Networks**: All systems on same subnet
2. **Any-to-Any Rules**: No traffic restrictions
3. **Internet Access from OT**: Production systems with web access
4. **Missing Deny Rules**: Relying only on implicit default deny
5. **Vendor Backdoors**: Direct internet access to production

### **4. Industrial Protocol Security**

#### **Secure Protocol Usage:**
- **IEC 61850**: Modern power system protocol with security features
- **Secure Modbus**: Modbus over TLS/SSL
- **OPC-UA Security**: Certificate-based authentication
- **MQTT with TLS**: Encrypted IoT messaging

#### **Insecure Protocol Warnings:**
- **Plain Modbus**: Unencrypted, easily intercepted
- **Telnet**: Clear-text passwords, immediate security risk
- **SNMP v1/v2**: Weak authentication
- **HTTP**: Unencrypted web interfaces

## 📋 **Recommendation Generation Rules**

### **Priority Levels**
1. **🚨 URGENT**: Any-to-any rules, internet access from OT, insecure protocols
2. **⚠️ REVIEW**: Overly broad rules, missing port restrictions
3. **💡 SUGGESTION**: Configuration appears controlled but could be improved
4. **✅ GOOD**: Explicit deny rules, proper segmentation

### **Dynamic Recommendations Based on Findings**

#### **If ANY-TO-ANY Rules Found:**
- "Replace with specific source/destination networks and required ports only"
- "These rules bypass all network segmentation!"

#### **If Industrial Zone Risks Found:**
- "OT networks should only access specific MES/Historian/DNS servers"
- "Implement strict protocol controls (Modbus, OPC-UA, EtherNet/IP only)"
- "Block internet access except for specific vendor support tunnels"

#### **If DMZ Risks Found:**
- "DMZ access should be limited to specific external endpoints"
- "Allow only required external services (NTP, vendor support, updates)"
- "Block all lateral movement to internal networks"

#### **If Good Deny Rules Found:**
- "Current DENY rules are excellent - maintain these!"
- "Consider adding logging to monitor blocked traffic patterns"

#### **If No Critical Issues Found:**
- "No critical rule violations detected in this configuration"
- "Consider adding explicit DENY rules before default deny for better logging"
- "Monitor traffic patterns and tighten rules based on actual usage"

## 🔍 **Monitoring & Alerting Recommendations**

### **Dynamic Monitoring Rules**
1. **If Risky Rules Exist**: "Enable detailed logging on risky ALLOW rules"
2. **If Industrial Zones Present**: "Monitor Industrial Zone outbound connections for anomalies"
3. **If DMZ Zones Present**: "Monitor DMZ Zone for suspicious inbound/outbound connections"
4. **Always**: "Set up alerts for any traffic hitting the implicit default deny rule (∞)"
5. **If Many Rules**: "Consider rule utilization analysis to remove unused rules"
6. **If Deny Rules Exist**: "Monitor DENY rule hits to validate security policies"

### **Recommended Monitoring Points**
- **Implicit Default Deny Hits**: Indicates blocked traffic, potential security events
- **Inter-Zone Communication**: Unusual cross-zone traffic patterns
- **Protocol Anomalies**: Unexpected protocols on OT networks
- **Time-Based Patterns**: Access outside normal business hours
- **Failed Authentication**: VPN and administrative access attempts

## 🛠️ **Implementation Guidelines**

### **Immediate Actions (Critical)**
1. Remove any-to-any rules immediately
2. Block internet access from Industrial Zone networks
3. Replace insecure protocols (Telnet) with secure alternatives (SSH)
4. Implement explicit deny rules between zones

### **Short-term Improvements (High Priority)**
1. Segment networks according to Purdue Model
2. Implement protocol-specific restrictions
3. Set up DMZ for historians and external interfaces
4. Add comprehensive logging and monitoring

### **Long-term Enhancements (Medium Priority)**
1. Implement microsegmentation within Industrial Zones
2. Deploy time-based access controls
3. Regular security assessments and rule reviews
4. Advanced threat detection and response

## 📊 **Compliance & Standards Alignment**

### **IEC 62443 Principles Applied**
- **Network Segmentation**: Proper separation of network zones (not to be confused with IEC 62443 logical zones)
- **Zone & Conduit Concept**: CIPgram's network zones represent **conduits** (network pathways) between **logical security zones**
- **Defense in Depth**: Multiple layers of network protection
- **Risk-Based Security**: Higher security controls for higher-risk network segments

**Note**: CIPgram implements **network security zones** for firewall analysis, which support the implementation of IEC 62443's logical security zones but are not equivalent to them. IEC 62443 zones are based on criticality and function, while CIPgram's zones are based on network topology and segmentation boundaries.

### **NIST Cybersecurity Framework**
- **Identify**: Asset inventory and risk assessment
- **Protect**: Access controls and network segmentation
- **Detect**: Monitoring and anomaly detection
- **Respond**: Incident response procedures
- **Recover**: Business continuity planning

### **Industry-Specific Standards**
- **NERC CIP**: Electric utility compliance
- **ISA/IEC 62443**: Industrial automation security (logical zones and conduits)
- **NIST 800-82**: Industrial control systems security
- **API 1164**: Pipeline SCADA security

---

*This document represents the collective security knowledge and best practices built into CIPgram's analysis engine. These rules are continuously updated based on emerging threats and industry best practices.*
