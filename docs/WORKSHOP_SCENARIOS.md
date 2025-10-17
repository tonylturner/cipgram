# Workshop Scenarios & Sample Configurations

## 🏭 Industry-Specific Scenarios

### **Scenario 1: Manufacturing Plant Security Assessment**
**Files**: `manufacturing_insecure.xml` → `manufacturing_improved.xml`

**Background**: A automotive parts manufacturer needs to improve their network security after a recent audit found significant vulnerabilities.

**Current Issues**:
- Flat network architecture
- Any-to-any communication rules
- Production systems with internet access
- No DMZ for external interfaces

**Learning Objectives**:
- Identify flat network risks
- Design proper network segmentation
- Implement Purdue Model levels
- Create secure external access

### **Scenario 2: Water Treatment Facility Compliance**
**Files**: `water_treatment_secure.xml`

**Background**: A municipal water treatment facility implementing IEC 62443 compliance for critical infrastructure protection.

**Security Features**:
- Proper zone segmentation
- SCADA DMZ implementation
- Restricted protocol usage
- Emergency access controls

**Learning Objectives**:
- Understand critical infrastructure security
- Analyze compliant network design
- Evaluate emergency access procedures
- Assess protocol security measures

### **Scenario 3: Power Substation Mixed Security**
**Files**: `power_substation_mixed.xml`

**Background**: An electrical utility with mixed security practices - some good, some problematic.

**Mixed Practices**:
- ✅ IEC 61850 protocol isolation
- ✅ Protection relay segmentation
- ❌ SCADA internet access
- ❌ Overly broad engineering access

**Learning Objectives**:
- Identify security gaps in real-world scenarios
- Balance operational needs with security
- Evaluate utility-specific protocols
- Design risk mitigation strategies

### **Scenario 4: Pharmaceutical Manufacturing**
**Files**: `pharma_manufacturing.xml` (to be created)

**Background**: FDA-regulated pharmaceutical facility requiring both cybersecurity and compliance with 21 CFR Part 11.

**Requirements**:
- Batch control system isolation
- Quality control network separation
- Audit trail preservation
- Validated system protection

### **Scenario 5: Oil & Gas Pipeline Control**
**Files**: `pipeline_control.xml` (to be created)

**Background**: Pipeline control system with SCADA networks spanning multiple geographic locations.

**Challenges**:
- Remote site connectivity
- DNP3 protocol security
- Emergency shutdown systems
- Vendor remote access

## 🎯 Progressive Difficulty Levels

### **Level 1: Basic (Beginner)**
- Simple network topologies
- Clear security violations
- Obvious improvement opportunities
- Limited protocol complexity

**Recommended Files**:
- `weak_test_config.xml`
- `test_industrial_config.xml`

### **Level 2: Intermediate**
- Realistic industrial networks
- Mixed security practices
- Multiple protocol types
- Some compliance requirements

**Recommended Files**:
- `manufacturing_insecure.xml`
- `power_substation_mixed.xml`

### **Level 3: Advanced**
- Complex multi-zone architectures
- Subtle security issues
- Full compliance requirements
- Advanced threat scenarios

**Recommended Files**:
- `water_treatment_secure.xml`
- Custom scenarios based on real environments

## 🔄 Workshop Flow Recommendations

### **Day 1: Foundation (4 hours)**
1. **Hour 1**: Network discovery and visualization
2. **Hour 2**: Basic security assessment
3. **Hour 3**: Introduction to IEC 62443 zones
4. **Hour 4**: Hands-on analysis of simple scenarios

### **Day 2: Application (4 hours)**
1. **Hour 1**: Complex scenario analysis
2. **Hour 2**: Policy violation detection
3. **Hour 3**: Segmentation design workshop
4. **Hour 4**: Presentation and discussion

### **Advanced Workshop (2 days)**
- Day 1: All foundation topics plus advanced analysis
- Day 2: Custom scenario development and peer review

## 📊 Scenario Comparison Matrix

| Scenario | Complexity | Industry | Security Level | Learning Focus |
|----------|------------|----------|----------------|----------------|
| Manufacturing Insecure | Low | Automotive | Very Poor | Risk Identification |
| Water Treatment Secure | High | Utilities | Excellent | Best Practices |
| Power Substation Mixed | Medium | Energy | Mixed | Real-world Challenges |
| Pharmaceutical | High | Healthcare | Strict | Regulatory Compliance |
| Pipeline Control | High | Oil & Gas | Critical | Remote Operations |

## 🎓 Instructor Notes

### **Common Student Challenges**:
1. Understanding zone boundaries
2. Balancing security vs. operations
3. Protocol-specific security requirements
4. Emergency access procedures

### **Discussion Facilitators**:
- "What would happen if this rule was exploited?"
- "How would you explain this risk to management?"
- "What operational impact would this change have?"
- "How does this align with industry standards?"

### **Assessment Opportunities**:
- Scenario analysis presentations
- Risk assessment reports
- Segmentation design proposals
- Peer review exercises
