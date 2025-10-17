# CIPgram OT Network Segmentation Workshop Guide

## 🎯 Workshop Overview

This guide provides structured learning modules for conducting OT network segmentation workshops using CIPgram.

## 📚 Learning Modules

### **Module 1: Network Discovery & Visualization (30 min)**
**Objective**: Understand current network topology and asset inventory

#### **Exercise 1.1: Basic Network Analysis**
```bash
# Analyze a simple manufacturing network
./cipgram config fwconfigs/manufacturing_insecure.xml project "module1_discovery"

# Students examine:
# - Network topology diagram
# - Asset inventory
# - Protocol usage
```

**Discussion Points**:
- What networks are present?
- Which protocols are in use?
- Are there any unexpected connections?

#### **Exercise 1.2: PCAP Traffic Analysis**
```bash
# Analyze actual network traffic
./cipgram pcap pcaps/Cyberville.pcap project "module1_traffic"

# Students examine:
# - Discovered assets and vendors
# - Communication patterns
# - Protocol conversations
```

### **Module 2: Security Assessment (45 min)**
**Objective**: Identify security risks and vulnerabilities

#### **Exercise 2.1: Risk Identification**
```bash
# Compare secure vs insecure configurations
./cipgram config fwconfigs/water_treatment_secure.xml project "module2_secure"
./cipgram config fwconfigs/manufacturing_insecure.xml project "module2_insecure"
```

**Discussion Points**:
- What makes one configuration more secure?
- Identify specific risk factors
- Compare network segmentation approaches

#### **Exercise 2.2: Policy Violation Detection**
```bash
# Combined analysis to find policy violations
./cipgram combined network_traffic.pcap firewall.xml project "module2_violations"
```

### **Module 3: IEC 62443 Compliance (45 min)**
**Objective**: Understand zone-based security architecture

#### **Exercise 3.1: Zone Classification**
```bash
# Analyze different industry configurations
./cipgram config fwconfigs/power_substation_mixed.xml project "module3_power"
./cipgram config fwconfigs/water_treatment_secure.xml project "module3_water"
```

**Discussion Points**:
- How are zones defined in each industry?
- What are the conduit requirements?
- Compare risk levels between zones

### **Module 4: Segmentation Planning (60 min)**
**Objective**: Design improved network segmentation

#### **Exercise 4.1: Before/After Analysis**
```bash
# Analyze current state
./cipgram config fwconfigs/manufacturing_insecure.xml project "module4_before"

# Students design improvements, then analyze improved config
./cipgram config fwconfigs/manufacturing_improved.xml project "module4_after"
```

#### **Exercise 4.2: Custom Scenario Design**
Students create their own firewall configuration based on a given industrial scenario.

## 🛠️ Workshop Setup

### **Prerequisites**
- CIPgram installed with Graphviz
- Sample configurations in `fwconfigs/`
- Sample PCAP files in `pcaps/`
- Workshop handouts and scenarios

### **Instructor Preparation**
1. Review all sample configurations
2. Prepare discussion questions for each module
3. Set up student workstations
4. Create custom scenarios for advanced exercises

### **Student Materials**
- Workshop handout with exercises
- Reference sheets for IEC 62443 zones
- Purdue Model diagram
- Common industrial protocols guide

## 📊 Assessment Rubric

### **Knowledge Areas**
1. **Network Topology Understanding** (25%)
2. **Risk Assessment Skills** (25%)
3. **IEC 62443 Compliance Knowledge** (25%)
4. **Segmentation Design Ability** (25%)

### **Practical Skills**
- Tool usage proficiency
- Diagram interpretation
- Security recommendation quality
- Presentation of findings

## 🎯 Learning Outcomes

By the end of this workshop, participants will be able to:
1. Analyze network topology from firewall configurations
2. Identify security risks in OT networks
3. Apply IEC 62443 zone-based security principles
4. Design improved network segmentation strategies
5. Use CIPgram for ongoing security assessment

## 📝 Additional Resources

- IEC 62443 standards documentation
- Purdue Model best practices
- Industrial protocol security guides
- Network segmentation case studies
