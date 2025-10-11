## SOLUTION: Clear Purdue Model Diagrams

You're absolutely right - the current diagram is cluttered and doesn't show clear Purdue levels. Here's what I'm fixing:

## The Core Problems:
1. **Too many "Unknown" devices** - Most devices ending up unclassified
2. **Poor visual hierarchy** - Levels not clearly separated  
3. **Cluttered layout** - Too much information, not enough clarity
4. **Missing L3 level** - No clear management layer shown

## The Solution:
### 1. **Better Classification Logic**  
- More aggressive classification (fewer "Unknown" devices)
- Protocol-based level assignment instead of IP-based guessing
- Vendor identification from MAC addresses

### 2. **Cleaner Visual Layout**
- Clear vertical stacking: **L3 (top) → L2 (middle) → L1 (bottom)**  
- Traditional Purdue colors: **Blue (L3), Orange (L2), Green (L1)**
- Hide cluttering unknown devices (show only industrial relevance)
- Simplified node labels: **Device Type + Vendor + Key Info**

### 3. **Focus on Industrial Protocols**
- Show only **EtherNet/IP, Modbus, S7** connections for clarity
- Hide noise protocols that don't add value
- Bold lines for critical communications

## What You'll Get:
```
┌─────────────────────────────────────┐
│  Level 3 - Management & IT          │ (Blue)
│  ├─ HMI-Station-01 [Rockwell]       │
│  └─ SCADA-Server [192.168.1.100]    │  
└─────────────────────────────────────┘
         │ EtherNet/IP
         ▼
┌─────────────────────────────────────┐
│  Level 2 - Control & HMI            │ (Orange)  
│  ├─ Panel-View [AB] (HMI)           │
│  └─ Process-Controller (PLC)        │
└─────────────────────────────────────┘
         │ Modbus TCP
         ▼  
┌─────────────────────────────────────┐
│  Level 1 - Field Devices            │ (Green)
│  ├─ PLC-01 [Siemens] (S7 PLC)       │
│  ├─ Drive-Motor-03 (I/O Device)     │
│  └─ Sensor-Bank [Omron] (Field)     │
└─────────────────────────────────────┘
```

**Result**: Clean, traditional Purdue Model diagram that immediately shows the industrial network hierarchy and device relationships.

Ready to implement this fix?
