#!/bin/bash

# Generate Additional Workshop Configurations
# Creates industry-specific scenarios for enhanced workshop training

echo "🏭 Generating additional workshop configurations..."

CONFIGS_DIR="fwconfigs/workshop"
mkdir -p "$CONFIGS_DIR"

# 1. Pharmaceutical Manufacturing Configuration
cat > "$CONFIGS_DIR/pharma_manufacturing.xml" << 'EOF'
<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>pharma-firewall</hostname>
    <domain>pharma.local</domain>
    <description>Pharmaceutical Manufacturing Network</description>
  </system>
  
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>203.0.113.10</ipaddr>
      <subnet>24</subnet>
      <gateway>wan_gw</gateway>
      <descr>WAN Interface</descr>
    </wan>
    <lan>
      <enable>1</enable>
      <if>em1</if>
      <ipaddr>192.168.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Corporate Network</descr>
    </lan>
    <opt1>
      <enable>1</enable>
      <if>em2</if>
      <ipaddr>10.10.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Manufacturing Execution System</descr>
    </opt1>
    <opt2>
      <enable>1</enable>
      <if>em3</if>
      <ipaddr>10.20.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Batch Control Network</descr>
    </opt2>
    <opt3>
      <enable>1</enable>
      <if>em4</if>
      <ipaddr>10.30.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Quality Control Lab</descr>
    </opt3>
    <opt4>
      <enable>1</enable>
      <if>em5</if>
      <ipaddr>172.16.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Validation DMZ</descr>
    </opt4>
  </interfaces>

  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><network>lan</network></source>
      <destination><network>opt1</network></destination>
      <protocol>tcp</protocol>
      <destination_port>443</destination_port>
      <descr>Corporate to MES HTTPS</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt1</interface>
      <source><network>opt1</network></source>
      <destination><network>opt2</network></destination>
      <protocol>tcp</protocol>
      <destination_port>502</destination_port>
      <descr>MES to Batch Control Modbus</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt2</interface>
      <source><network>opt2</network></source>
      <destination><network>opt3</network></destination>
      <protocol>tcp</protocol>
      <destination_port>1433</destination_port>
      <descr>Batch to QC Database</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt4</interface>
      <source><network>opt4</network></source>
      <destination><any/></destination>
      <protocol>tcp</protocol>
      <destination_port>443</destination_port>
      <descr>Validation DMZ Internet Access</descr>
    </rule>
  </filter>
</opnsense>
EOF

# 2. Oil & Gas Pipeline Configuration
cat > "$CONFIGS_DIR/pipeline_control.xml" << 'EOF'
<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>pipeline-scada</hostname>
    <domain>pipeline.local</domain>
    <description>Oil & Gas Pipeline Control System</description>
  </system>
  
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>198.51.100.50</ipaddr>
      <subnet>24</subnet>
      <gateway>wan_gw</gateway>
      <descr>WAN Interface</descr>
    </wan>
    <lan>
      <enable>1</enable>
      <if>em1</if>
      <ipaddr>192.168.50.1</ipaddr>
      <subnet>24</subnet>
      <descr>Control Center Network</descr>
    </lan>
    <opt1>
      <enable>1</enable>
      <if>em2</if>
      <ipaddr>10.50.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>SCADA Network</descr>
    </opt1>
    <opt2>
      <enable>1</enable>
      <if>em3</if>
      <ipaddr>10.50.20.1</ipaddr>
      <subnet>24</subnet>
      <descr>Safety Instrumented Systems</descr>
    </opt2>
    <opt3>
      <enable>1</enable>
      <if>em4</if>
      <ipaddr>10.50.30.1</ipaddr>
      <subnet>24</subnet>
      <descr>Remote Terminal Units</descr>
    </opt3>
    <opt4>
      <enable>1</enable>
      <if>em5</if>
      <ipaddr>172.16.50.1</ipaddr>
      <subnet>24</subnet>
      <descr>Historian DMZ</descr>
    </opt4>
  </interfaces>

  <filter>
    <rule>
      <type>pass</type>
      <interface>opt1</interface>
      <source><network>opt1</network></source>
      <destination><network>opt3</network></destination>
      <protocol>tcp</protocol>
      <destination_port>20000</destination_port>
      <descr>SCADA to RTU DNP3</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt2</interface>
      <source><network>opt2</network></source>
      <destination><network>opt3</network></destination>
      <protocol>tcp</protocol>
      <destination_port>502</destination_port>
      <descr>SIS to RTU Modbus</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt1</interface>
      <source><network>opt1</network></source>
      <destination><network>opt4</network></destination>
      <protocol>tcp</protocol>
      <destination_port>1433</destination_port>
      <descr>SCADA to Historian</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><network>lan</network></source>
      <destination><network>opt4</network></destination>
      <protocol>tcp</protocol>
      <destination_port>443</destination_port>
      <descr>Control Center to Historian HTTPS</descr>
    </rule>
  </filter>
</opnsense>
EOF

# 3. Smart Building Configuration
cat > "$CONFIGS_DIR/smart_building.xml" << 'EOF'
<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>building-automation</hostname>
    <domain>smartbuilding.local</domain>
    <description>Smart Building Automation System</description>
  </system>
  
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>203.0.113.100</ipaddr>
      <subnet>24</subnet>
      <gateway>wan_gw</gateway>
      <descr>WAN Interface</descr>
    </wan>
    <lan>
      <enable>1</enable>
      <if>em1</if>
      <ipaddr>192.168.100.1</ipaddr>
      <subnet>24</subnet>
      <descr>Corporate IT Network</descr>
    </lan>
    <opt1>
      <enable>1</enable>
      <if>em2</if>
      <ipaddr>10.100.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Building Management System</descr>
    </opt1>
    <opt2>
      <enable>1</enable>
      <if>em3</if>
      <ipaddr>10.100.20.1</ipaddr>
      <subnet>24</subnet>
      <descr>HVAC Control Network</descr>
    </opt2>
    <opt3>
      <enable>1</enable>
      <if>em4</if>
      <ipaddr>10.100.30.1</ipaddr>
      <subnet>24</subnet>
      <descr>Security Systems</descr>
    </opt3>
    <opt4>
      <enable>1</enable>
      <if>em5</if>
      <ipaddr>10.100.40.1</ipaddr>
      <subnet>24</subnet>
      <descr>IoT Sensor Network</descr>
    </opt4>
  </interfaces>

  <filter>
    <rule>
      <type>pass</type>
      <interface>opt1</interface>
      <source><network>opt1</network></source>
      <destination><network>opt2</network></destination>
      <protocol>tcp</protocol>
      <destination_port>47808</destination_port>
      <descr>BMS to HVAC BACnet</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt1</interface>
      <source><network>opt1</network></source>
      <destination><network>opt4</network></destination>
      <protocol>tcp</protocol>
      <destination_port>1883</destination_port>
      <descr>BMS to IoT MQTT</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt3</interface>
      <source><network>opt3</network></source>
      <destination><network>opt1</network></destination>
      <protocol>tcp</protocol>
      <destination_port>443</destination_port>
      <descr>Security to BMS HTTPS</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><network>lan</network></source>
      <destination><network>opt1</network></destination>
      <protocol>tcp</protocol>
      <destination_port>443</destination_port>
      <descr>IT to BMS Management</descr>
    </rule>
  </filter>
</opnsense>
EOF

# 4. Food Processing Plant Configuration
cat > "$CONFIGS_DIR/food_processing.xml" << 'EOF'
<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>food-plant-fw</hostname>
    <domain>foodplant.local</domain>
    <description>Food Processing Plant Network</description>
  </system>
  
  <interfaces>
    <wan>
      <enable>1</enable>
      <if>em0</if>
      <ipaddr>198.51.100.200</ipaddr>
      <subnet>24</subnet>
      <gateway>wan_gw</gateway>
      <descr>WAN Interface</descr>
    </wan>
    <lan>
      <enable>1</enable>
      <if>em1</if>
      <ipaddr>192.168.200.1</ipaddr>
      <subnet>24</subnet>
      <descr>Administrative Network</descr>
    </lan>
    <opt1>
      <enable>1</enable>
      <if>em2</if>
      <ipaddr>10.200.10.1</ipaddr>
      <subnet>24</subnet>
      <descr>Production Line Control</descr>
    </opt1>
    <opt2>
      <enable>1</enable>
      <if>em3</if>
      <ipaddr>10.200.20.1</ipaddr>
      <subnet>24</subnet>
      <descr>Packaging Systems</descr>
    </opt2>
    <opt3>
      <enable>1</enable>
      <if>em4</if>
      <ipaddr>10.200.30.1</ipaddr>
      <subnet>24</subnet>
      <descr>Quality Assurance Lab</descr>
    </opt3>
    <opt4>
      <enable>1</enable>
      <if>em5</if>
      <ipaddr>10.200.40.1</ipaddr>
      <subnet>24</subnet>
      <descr>Environmental Monitoring</descr>
    </opt4>
  </interfaces>

  <filter>
    <rule>
      <type>pass</type>
      <interface>opt1</interface>
      <source><network>opt1</network></source>
      <destination><network>opt2</network></destination>
      <protocol>tcp</protocol>
      <destination_port>44818</destination_port>
      <descr>Production to Packaging EtherNet/IP</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt3</interface>
      <source><network>opt3</network></source>
      <destination><network>opt1</network></destination>
      <protocol>tcp</protocol>
      <destination_port>502</destination_port>
      <descr>QA to Production Modbus</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>opt4</interface>
      <source><network>opt4</network></source>
      <destination><network>opt1</network></destination>
      <protocol>tcp</protocol>
      <destination_port>1883</destination_port>
      <descr>Environmental to Production MQTT</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><network>lan</network></source>
      <destination><network>opt1</network></destination>
      <protocol>tcp</protocol>
      <destination_port>443</destination_port>
      <descr>Admin to Production HTTPS</descr>
    </rule>
  </filter>
</opnsense>
EOF

# Create workshop configuration index
cat > "$CONFIGS_DIR/README.md" << 'EOF'
# Workshop Configuration Library

## Industry-Specific Scenarios

### 1. Pharmaceutical Manufacturing (`pharma_manufacturing.xml`)
**Learning Focus**: Regulatory compliance, validation requirements
- **Networks**: Corporate, MES, Batch Control, QC Lab, Validation DMZ
- **Protocols**: HTTPS, Modbus TCP, SQL Server
- **Compliance**: FDA 21 CFR Part 11, GxP requirements
- **Key Challenges**: Data integrity, audit trails, system validation

### 2. Oil & Gas Pipeline (`pipeline_control.xml`)
**Learning Focus**: Critical infrastructure, remote operations
- **Networks**: Control Center, SCADA, SIS, RTU, Historian DMZ
- **Protocols**: DNP3, Modbus TCP, HTTPS, SQL Server
- **Compliance**: NERC CIP, API standards
- **Key Challenges**: Geographic distribution, emergency response, safety systems

### 3. Smart Building (`smart_building.xml`)
**Learning Focus**: IoT integration, building automation
- **Networks**: Corporate IT, BMS, HVAC, Security, IoT Sensors
- **Protocols**: BACnet, MQTT, HTTPS
- **Compliance**: Building codes, energy efficiency standards
- **Key Challenges**: IoT security, protocol diversity, integration complexity

### 4. Food Processing (`food_processing.xml`)
**Learning Focus**: Food safety, environmental monitoring
- **Networks**: Administrative, Production Control, Packaging, QA Lab, Environmental
- **Protocols**: EtherNet/IP, Modbus TCP, MQTT, HTTPS
- **Compliance**: FDA FSMA, HACCP requirements
- **Key Challenges**: Contamination prevention, traceability, environmental controls

## Workshop Usage

### Progressive Learning Path
1. **Beginner**: Start with `smart_building.xml` (simpler protocols)
2. **Intermediate**: Move to `food_processing.xml` (moderate complexity)
3. **Advanced**: Analyze `pharma_manufacturing.xml` and `pipeline_control.xml`

### Comparative Analysis Exercises
- Compare regulatory requirements across industries
- Analyze protocol security differences
- Evaluate risk management approaches
- Design cross-industry best practices

### Assessment Scenarios
- Identify industry-specific risks
- Propose compliance improvements
- Design emergency response procedures
- Evaluate operational impact of security changes
EOF

echo "✅ Generated 4 additional workshop configurations"
echo "📁 Configurations saved to: $CONFIGS_DIR/"
echo "📚 Documentation created: $CONFIGS_DIR/README.md"
echo ""
echo "🎓 Workshop configurations ready for use!"
echo "💡 Use these for industry-specific training scenarios"
