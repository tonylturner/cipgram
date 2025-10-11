# Enhanced Purdue Model Classification 

## Overview
The cipgram tool has been significantly improved to address proper Purdue Model implementation with accurate device identification and level classification.

## Key Improvements

### ✅ 1. MAC Address & OUI-Based Device Identification
- **Industrial OUI Database**: Added comprehensive database of industrial automation vendor MAC address prefixes
- **Vendor Detection**: Automatically identifies device manufacturers (Siemens, Rockwell/Allen-Bradley, Schneider Electric, Omron, Mitsubishi, etc.)
- **Enhanced Device Names**: Uses vendor information combined with protocol analysis for accurate device naming

### ✅ 2. Removed Error-Prone IP Range Classification
- **Problem Fixed**: Eliminated unreliable subnet-based Purdue level inference
- **Root Cause**: IP addresses are arbitrary and vary by organization
- **Solution**: 100% protocol and communication pattern-based classification

### ✅ 3. Enhanced Protocol-Based Level Classification
- **Level 1 (Field Devices)**: 
  - PLCs that receive configuration and send I/O data
  - I/O adapters with multicast participation
  - Devices with vendor-specific protocol slaves (Modbus, S7, FINS, etc.)
- **Level 2 (Supervisory Control)**:
  - HMIs/Engineering stations initiating connections to multiple devices
  - SCADA masters polling field devices
  - OPC-UA clients with IT capabilities
- **Level 3 (Management/IT)**:
  - Strong IT protocols with minimal direct ICS communication
  - Servers and workstations with management functions

### ✅ 4. Traditional Purdue Model Vertical Layout
- **Proper Stacking**: L3 (top) → L2 (middle) → L1 (bottom) → Unknown
- **Visual Spacing**: Adequate spacing between levels for connection clarity
- **Industrial Color Scheme**: Traditional Purdue model colors with vendor-specific styling
- **Level Labels**: Clear "Level 1 - Field Devices", "Level 2 - Supervisory Control", etc.

## Technical Implementation

### MAC Address Processing
```go
// Extract MAC addresses during packet processing
srcHost.MAC = eth.SrcMAC.String()
dstHost.MAC = eth.DstMAC.String()
// Resolve vendor from OUI
srcHost.Vendor = lookupOUI(srcHost.MAC)
```

### Protocol-Based Classification Logic
```go
// Classification based on communication patterns and device behavior
switch {
case rcvENIPPeers >= 1 && hasIO && h.ITScore <= 1:
    h.InferredLevel = L1 // Field Device
case initENIPPeers >= 3 && h.ITScore >= 1:
    h.InferredLevel = L2 // HMI/Engineering
case h.ITScore >= 3 && h.ICSScore <= 1:
    h.InferredLevel = L3 // IT/Management
}
```

### Vertical Purdue Layout
```dot
// Traditional Purdue Model vertical stacking
graph [rankdir=TB, ranksep=3.0, nodesep=1.5];
subgraph cluster_L3 { label="Level 3 - Manufacturing Operations"; }
subgraph cluster_L2 { label="Level 2 - Supervisory Control"; }
subgraph cluster_L1 { label="Level 1 - Field Devices"; }
```

## Device Recognition Improvements

### Vendor-Specific Identification
- **Siemens**: Identified by OUI + S7 protocol usage → "Siemens S7 PLC"
- **Rockwell**: Identified by OUI + EtherNet/IP → "Rockwell PLC"
- **Schneider**: Identified by OUI + Modbus → "Schneider PLC"
- **Omron**: Identified by OUI + FINS protocol → "Omron PLC"
- **Mitsubishi**: Identified by OUI + SLMP/MelsecQ → "Mitsubishi PLC"

### Communication Pattern Analysis
- **Master/Slave Detection**: Analyzes initiated vs received communications
- **I/O Device Recognition**: Multicast participation + minimal explicit traffic
- **HMI Identification**: Multiple device connections + IT protocols
- **Gateway Detection**: Multi-protocol support without field I/O

## Visual Improvements

### Node Styling
- **Vendor Colors**: Siemens (blue), Rockwell (red), Schneider (green), Omron (orange), Mitsubishi (purple)
- **Role Emphasis**: PLCs, HMIs, and critical devices visually distinct
- **Information Hierarchy**: Hostname/Device Name → Vendor → Role → IP

### Edge Styling
- **Protocol Colors**: EtherNet/IP (green), Modbus (orange), S7 (blue), OPC-UA (purple)
- **Industrial Focus**: Bold styling for critical protocols
- **Clean Labels**: Protocol name + port + CIP service (when relevant)

## Benefits

1. **Accurate Classification**: No more IP-based guessing, pure protocol analysis
2. **Vendor Recognition**: Immediate identification of device manufacturers
3. **True Purdue Model**: Proper vertical stacking as per industrial standards
4. **Better Visualization**: Clear device relationships and protocol flows
5. **Industry Standard**: Follows established Purdue Model conventions

## Example Output

```
Level 3 - Manufacturing Operations
├── Engineering-WS-01 [192.168.1.100] (HMI/Engineering Station)
└── SCADA-Server [192.168.1.200] (SCADA Master)

Level 2 - Supervisory Control  
├── HMI-Panel-02 [192.168.2.50] (OPC-UA Client/HMI)
└── Data-Historian [192.168.2.100] (DNP3 Master/RTU)

Level 1 - Field Devices
├── Rockwell PLC [192.168.10.1] (Rockwell PLC)
├── Siemens S7 PLC [192.168.10.2] (Siemens S7 PLC)
└── VFD-Drive-03 [192.168.10.10] (I/O Adapter/Drive)
```

This implementation now properly represents the Purdue Model with accurate device identification and appropriate level classification based on actual device function and communication patterns.
