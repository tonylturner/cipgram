#!/bin/bash

# CIPgram Workshop Setup Script
# Automates workshop environment preparation

set -e

WORKSHOP_DIR="workshop_$(date +%Y%m%d_%H%M%S)"
STUDENT_COUNT=${1:-10}

echo "🎓 Setting up CIPgram Workshop Environment"
echo "📁 Workshop directory: $WORKSHOP_DIR"
echo "👥 Number of students: $STUDENT_COUNT"

# Create workshop directory structure
mkdir -p "$WORKSHOP_DIR"/{students,instructor,results,handouts}

echo "📋 Creating student workspaces..."
for i in $(seq 1 $STUDENT_COUNT); do
    student_dir="$WORKSHOP_DIR/students/student_$(printf "%02d" $i)"
    mkdir -p "$student_dir"/{configs,pcaps,output,notes}
    
    # Copy sample configurations
    cp fwconfigs/*.xml "$student_dir/configs/"
    
    # Copy sample PCAPs if available
    if [ -d "pcaps" ]; then
        cp -r pcaps/* "$student_dir/pcaps/" 2>/dev/null || true
    fi
    
    # Create student-specific analysis script
    cat > "$student_dir/analyze.sh" << EOF
#!/bin/bash
# Student $(printf "%02d" $i) Analysis Script

echo "🎯 CIPgram Analysis - Student $(printf "%02d" $i)"
echo "📁 Working directory: \$(pwd)"

# Build CIPgram if needed
if [ ! -f "../../../../cipgram" ]; then
    echo "🔨 Building CIPgram..."
    cd ../../../../
    go build -o cipgram ./cmd/cipgram
    cd -
fi

# Function to run analysis
analyze_config() {
    local config=\$1
    local project=\$2
    echo "🔍 Analyzing \$config..."
    ../../../../cipgram -firewall-config "configs/\$config" -project "\$project"
    echo "✅ Results saved to output/\$project/"
}

# Function to run PCAP analysis
analyze_pcap() {
    local pcap=\$1
    local project=\$2
    echo "🔍 Analyzing \$pcap..."
    ../../../../cipgram pcap "pcaps/\$pcap" project "\$project"
    echo "✅ Results saved to output/\$project/"
}

# Workshop exercises
echo "📚 Available exercises:"
echo "1. analyze_config manufacturing_insecure.xml module1_manufacturing"
echo "2. analyze_config water_treatment_secure.xml module1_water"
echo "3. analyze_config power_substation_mixed.xml module1_power"
echo "4. analyze_pcap Cyberville.pcap module2_traffic"
echo ""
echo "💡 Run exercises by calling the functions above"
echo "📊 View results in the output/ directory"
EOF
    chmod +x "$student_dir/analyze.sh"
    
    echo "✅ Created workspace for student $(printf "%02d" $i)"
done

# Create instructor materials
echo "📚 Setting up instructor materials..."
instructor_dir="$WORKSHOP_DIR/instructor"

# Copy all configurations for instructor reference
cp -r fwconfigs "$instructor_dir/"
cp -r docs "$instructor_dir/"

# Create instructor analysis script
cat > "$instructor_dir/batch_analysis.sh" << EOF
#!/bin/bash
# Instructor Batch Analysis Script

echo "🎓 Running batch analysis for all workshop scenarios..."

# Build CIPgram
cd ../../../
go build -o cipgram ./cmd/cipgram
cd -

# Analyze all configurations
configs=(
    "manufacturing_insecure.xml:manufacturing_insecure"
    "water_treatment_secure.xml:water_secure"
    "power_substation_mixed.xml:power_mixed"
    "opnsense_paintshop_sample.xml:paintshop_sample"
    "test_industrial_config.xml:test_industrial"
    "weak_test_config.xml:weak_security"
)

for config_pair in "\${configs[@]}"; do
    IFS=':' read -r config project <<< "\$config_pair"
    echo "🔍 Analyzing \$config..."
    ../../../cipgram -firewall-config "fwconfigs/\$config" -project "instructor_\$project"
done

echo "✅ All analyses complete!"
echo "📊 Results available in output/ directories"
EOF
chmod +x "$instructor_dir/batch_analysis.sh"

# Create workshop handouts
echo "📄 Creating workshop handouts..."
handouts_dir="$WORKSHOP_DIR/handouts"

# Exercise handout
cat > "$handouts_dir/exercise_guide.md" << EOF
# CIPgram Workshop Exercise Guide

## 🎯 Workshop Objectives
- Learn OT network segmentation principles
- Understand IEC 62443 compliance requirements
- Practice security risk assessment
- Design improved network architectures

## 📋 Exercise Instructions

### Module 1: Network Discovery (30 min)
1. Navigate to your student directory
2. Run: \`./analyze.sh\`
3. Execute: \`analyze_config manufacturing_insecure.xml module1_manufacturing\`
4. Open \`output/module1_manufacturing/network_diagrams/network_topology.png\`
5. Answer the questions in your worksheet

### Module 2: Security Assessment (45 min)
1. Compare secure vs insecure configurations
2. Identify specific security risks
3. Document findings in your notes

### Module 3: IEC 62443 Compliance (45 min)
1. Analyze zone-based architectures
2. Understand conduit requirements
3. Evaluate compliance levels

### Module 4: Segmentation Design (60 min)
1. Design improved network segmentation
2. Present your recommendations
3. Peer review other designs

## 📊 Deliverables
- Risk assessment report
- Segmentation improvement plan
- Presentation slides
EOF

# Create assessment worksheet
cat > "$handouts_dir/assessment_worksheet.md" << EOF
# CIPgram Workshop Assessment Worksheet

**Student Name**: _________________ **Date**: _________________

## Module 1: Network Discovery

### Exercise 1.1: Manufacturing Network Analysis
1. How many network segments are present?
   Answer: _________________

2. Which industrial protocols are in use?
   Answer: _________________

3. Identify any security concerns:
   Answer: _________________

### Exercise 1.2: Traffic Analysis
1. How many assets were discovered?
   Answer: _________________

2. Which vendors are represented?
   Answer: _________________

3. Are there any unexpected communications?
   Answer: _________________

## Module 2: Security Assessment

### Risk Identification
1. List the top 3 security risks identified:
   a) _________________
   b) _________________
   c) _________________

2. Which configuration is more secure and why?
   Answer: _________________

## Module 3: IEC 62443 Compliance

### Zone Analysis
1. Identify the zones present in each configuration:
   Manufacturing: _________________
   Water Treatment: _________________
   Power Substation: _________________

2. Are the conduit requirements properly implemented?
   Answer: _________________

## Module 4: Segmentation Design

### Improvement Recommendations
1. Describe your segmentation improvements:
   _________________________________

2. Justify your design decisions:
   _________________________________

3. What operational impacts might occur?
   _________________________________

## Final Assessment

### Knowledge Check
1. What is the Purdue Model? _________________
2. Name three IEC 62443 zones: _________________
3. Why is network segmentation important in OT? _________________

**Instructor Use Only**
- Network Understanding: ___/25
- Risk Assessment: ___/25  
- IEC 62443 Knowledge: ___/25
- Design Quality: ___/25
- **Total Score**: ___/100
EOF

# Create results analysis script
cat > "$WORKSHOP_DIR/collect_results.sh" << EOF
#!/bin/bash
# Collect and summarize workshop results

echo "📊 Collecting workshop results..."

results_dir="$WORKSHOP_DIR/results"
mkdir -p "\$results_dir"

# Collect all student outputs
for student_dir in students/*/; do
    student_name=\$(basename "\$student_dir")
    echo "📁 Collecting results from \$student_name..."
    
    if [ -d "\$student_dir/output" ]; then
        cp -r "\$student_dir/output" "\$results_dir/\$student_name"
    fi
    
    if [ -f "\$student_dir/notes.md" ]; then
        cp "\$student_dir/notes.md" "\$results_dir/\${student_name}_notes.md"
    fi
done

echo "✅ Results collected in \$results_dir/"
echo "🎓 Workshop complete!"
EOF
chmod +x "$WORKSHOP_DIR/collect_results.sh"

echo ""
echo "🎉 Workshop environment setup complete!"
echo ""
echo "📁 Workshop directory: $WORKSHOP_DIR"
echo "👥 Student workspaces: $WORKSHOP_DIR/students/student_01 through student_$(printf "%02d" $STUDENT_COUNT)"
echo "🎓 Instructor materials: $WORKSHOP_DIR/instructor/"
echo "📄 Handouts: $WORKSHOP_DIR/handouts/"
echo ""
echo "🚀 Next steps:"
echo "1. Review instructor materials in $WORKSHOP_DIR/instructor/"
echo "2. Print handouts from $WORKSHOP_DIR/handouts/"
echo "3. Test student environment: cd $WORKSHOP_DIR/students/student_01 && ./analyze.sh"
echo "4. Run instructor batch analysis: cd $WORKSHOP_DIR/instructor && ./batch_analysis.sh"
echo ""
echo "📚 Workshop is ready to begin!"
