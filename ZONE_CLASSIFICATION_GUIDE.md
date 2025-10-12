# 🔍 Zone Classification & Risk Assessment in CIPgram

## 🏭 **How IEC 62443 Zones Are Determined**

CIPgram uses **heuristic analysis** of firewall interface names and descriptions to automatically classify networks into IEC 62443 zones:

### **Zone Classification Logic** (from `internal/parsers/opnsense/parser.go`)

```go
func (p *OPNsenseParser) inferZoneFromInterface(name string, iface *Interface) interfaces.IEC62443Zone {
    purpose := p.inferPurpose(iface.Descr, name)

    switch {
    case strings.Contains(strings.ToLower(name), "wan"):
        return interfaces.DMZZone // WAN typically goes to DMZ
    case strings.Contains(strings.ToLower(name), "lan"):
        return interfaces.ManufacturingZone // LAN often contains OT devices
    case strings.Contains(strings.ToLower(purpose), "production"):
        return interfaces.ManufacturingZone
    case strings.Contains(strings.ToLower(purpose), "dmz"):
        return interfaces.DMZZone
    case strings.Contains(strings.ToLower(purpose), "management"):
        return interfaces.EnterpriseZone
    case strings.Contains(strings.ToLower(name), "wireguard") || strings.Contains(strings.ToLower(iface.Descr), "wireguard"):
        return interfaces.RemoteAccessZone
    default:
        return interfaces.EnterpriseZone
    }
}
```

### **Zone Assignment Rules:**

| **Interface Pattern** | **Assigned Zone** | **Reasoning** |
|----------------------|-------------------|---------------|
| **`wan`** | **DMZ Zone** | Internet-facing interfaces |
| **`lan`** | **Manufacturing Zone** | Typically contains OT devices |
| **`wireguard`** or description contains "wireguard" | **Remote Access Zone** | VPN connections |
| Description contains **`production`** or **`ot`** | **Manufacturing Zone** | Production systems |
| Description contains **`dmz`** | **DMZ Zone** | Explicitly marked DMZ |
| Description contains **`management`** or **`admin`** | **Enterprise Zone** | IT management networks |
| **Everything else** | **Enterprise Zone** | Default fallback |

### **Purpose Classification** (Used in Zone Logic)

```go
func (p *OPNsenseParser) inferPurpose(descr, ifName string) string {
    lower := strings.ToLower(descr + " " + ifName)

    if strings.Contains(lower, "production") || strings.Contains(lower, "ot") {
        return "Production OT"
    }
    if strings.Contains(lower, "dmz") {
        return "DMZ"
    }
    if strings.Contains(lower, "management") || strings.Contains(lower, "admin") {
        return "Management"
    }
    if strings.Contains(lower, "wan") || strings.Contains(lower, "internet") {
        return "Internet"
    }

    return "General"
}
```

## ⚠️ **How Risk Levels Are Calculated**

Risk assessment is **zone-based** with simple but effective logic:

```go
func (p *OPNsenseParser) calculateSegmentRisk(segment *interfaces.NetworkSegment, policies []*interfaces.SecurityPolicy) interfaces.RiskLevel {
    // Simple risk assessment based on zone and policies
    switch segment.Zone {
    case interfaces.ManufacturingZone:
        return interfaces.HighRisk // Critical OT systems
    case interfaces.DMZZone:
        return interfaces.MediumRisk
    default:
        return interfaces.LowRisk
    }
}
```

### **Risk Level Rules:**

| **Zone** | **Risk Level** | **Justification** |
|----------|----------------|-------------------|
| **Manufacturing Zone** | **High Risk** | Contains critical OT systems, PLCs, HMIs |
| **DMZ Zone** | **Medium Risk** | Internet-exposed but with some protection |
| **Enterprise Zone** | **Low Risk** | IT systems, typically more hardened |
| **Remote Access Zone** | **Low Risk** | VPN access, controlled entry point |

## 🎯 **Example from Your Test Config**

Looking at your test results:

```
📊 Network Segments:
• lan (192.168.1.1/24) → Manufacturing Zone zone, High risk
• wan () → DMZ Zone zone, Medium risk  
• opt5 () → Remote Access Zone zone, Low risk
```

### **How These Were Classified:**

1. **`lan`** interface → **Manufacturing Zone** (High Risk)
   - Interface name contains "lan" 
   - Assumed to contain OT devices
   - High risk due to critical systems

2. **`wan`** interface → **DMZ Zone** (Medium Risk)
   - Interface name contains "wan"
   - Internet-facing network
   - Medium risk due to exposure

3. **`opt5`** interface → **Remote Access Zone** (Low Risk)
   - Description contains "Wireguard"
   - VPN access point
   - Low risk due to controlled access

## 🔧 **Customizing Zone Classification**

### **To Get Different Zone Assignments:**

1. **Use Descriptive Interface Names:**
   ```
   production_ot    → Manufacturing Zone (High Risk)
   scada_network    → Manufacturing Zone (High Risk)  
   admin_mgmt       → Enterprise Zone (Low Risk)
   public_dmz       → DMZ Zone (Medium Risk)
   vpn_remote       → Remote Access Zone (Low Risk)
   ```

2. **Use Descriptive Interface Descriptions:**
   - "Production OT Network" → Manufacturing Zone
   - "Management Network" → Enterprise Zone
   - "DMZ Web Servers" → DMZ Zone

3. **Future Enhancement:** Custom zone mapping configuration files

## 🚀 **For Your Training Workshop**

This **heuristic approach** works well because:

✅ **Intuitive**: Network engineers already use these naming conventions
✅ **Automatic**: No manual configuration required  
✅ **Educational**: Shows real-world IEC 62443 zone thinking
✅ **Practical**: Based on actual firewall interface patterns

Students learn that **zone classification** in real networks often starts with **naming conventions** and **network purpose**, which is exactly how experienced engineers think about segmentation! 🎓
