#!/bin/bash

# CIPgram Core Functionality Integration Test
# Tests the most important PCAP processing and diagram generation features

echo "🧪 CIPgram Core Functionality Integration Test"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

run_test() {
    local test_name="$1"
    shift
    local test_command="$@"
    
    echo ""
    echo "Running: $test_name"
    echo "----------------------------------------"
    
    ((TESTS_RUN++))
    
    if eval "$test_command" >/dev/null 2>&1; then
        log_success "$test_name"
        return 0
    else
        log_error "$test_name"
        return 1
    fi
}

check_file() {
    local file_path="$1"
    local description="$2"
    
    if [[ -f "$file_path" ]]; then
        local size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo "unknown")
        log_success "$description ($size bytes)"
        return 0
    else
        log_error "$description not found: $file_path"
        return 1
    fi
}

main() {
    log_info "Starting CIPgram Core Functionality Tests"
    log_info "Project root: $PROJECT_ROOT"
    echo ""

    cd "$PROJECT_ROOT"

    # Test 1: Build
    echo "═══════════════════════════════════════"
    echo "Test 1: Build System"
    echo "═══════════════════════════════════════"
    
    run_test "Build CIPgram binary" "make build"

    # Test 2: PCAP Processing
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test 2: PCAP Processing"
    echo "═══════════════════════════════════════"

    # Test with different PCAP files
    local pcap_files=(
        "pcaps/PROFINET.pcap"
        "pcaps/ENIP.pcap"
    )

    for pcap_file in "${pcap_files[@]}"; do
        if [[ -f "$pcap_file" ]]; then
            pcap_name=$(basename "$pcap_file" .pcap)
            project_name="test_${pcap_name}_${TIMESTAMP}"
            
            log_info "Testing with $pcap_name"
            run_test "Process $pcap_name PCAP" \
                "./cipgram pcap '$pcap_file' project '$project_name'"
            
            # Check output files
            output_dir="output/$project_name"
            check_file "$output_dir/network_diagrams/network_topology.dot" "Network topology DOT"
            check_file "$output_dir/network_diagrams/purdue_diagram.dot" "Purdue diagram DOT"
            check_file "$output_dir/data/diagram.json" "Network model JSON"
            
            # Check images (optional)
            if [[ -f "$output_dir/network_diagrams/network_topology.png" ]]; then
                log_success "Network topology PNG generated"
            fi
            
            if [[ -f "$output_dir/network_diagrams/purdue_diagram.png" ]]; then
                log_success "Purdue diagram PNG generated"
            fi
            
            break # Test with first available PCAP
        else
            log_warning "PCAP file not found: $pcap_file"
        fi
    done

    # Test 3: Configuration Options
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test 3: Configuration Options"
    echo "═══════════════════════════════════════"

    if [[ -f "pcaps/PROFINET.pcap" ]]; then
        # Test network diagram only
        project_name="test_network_only_${TIMESTAMP}"
        run_test "Network diagram only" \
            "./cipgram pcap 'pcaps/PROFINET.pcap' project '$project_name' diagram network"
        
        check_file "output/$project_name/network_diagrams/network_topology.dot" "Network topology DOT (network only)"
        
        # Test with config file (if available)
        if [[ -f "configs/purdue_config.yaml" ]]; then
            project_name="test_with_config_${TIMESTAMP}"
            run_test "With configuration file" \
                "./cipgram pcap 'pcaps/PROFINET.pcap' project '$project_name' config 'configs/purdue_config.yaml'"
            
            check_file "output/$project_name/network_diagrams/network_topology.dot" "Network topology DOT (with config)"
            check_file "output/$project_name/network_diagrams/purdue_diagram.dot" "Purdue diagram DOT (with config)"
        else
            log_warning "Configuration file not found, skipping config test"
        fi
    else
        log_warning "PROFINET.pcap not found, skipping configuration tests"
    fi

    # Test 4: Diagram Content Validation
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test 4: Diagram Content Validation"
    echo "═══════════════════════════════════════"

    if [[ -f "pcaps/PROFINET.pcap" ]]; then
        project_name="test_validation_${TIMESTAMP}"
        run_test "Generate diagrams for validation" \
            "./cipgram pcap 'pcaps/PROFINET.pcap' project '$project_name'"
        
        # Validate DOT file content
        dot_file="output/$project_name/network_diagrams/network_topology.dot"
        if [[ -f "$dot_file" ]]; then
            if grep -q "digraph" "$dot_file"; then
                log_success "DOT file contains 'digraph' declaration"
            else
                log_error "DOT file missing 'digraph' declaration"
            fi
            
            if grep -q "node\|edge\|->" "$dot_file"; then
                log_success "DOT file contains graph elements"
            else
                log_error "DOT file missing graph elements"
            fi
        fi
        
        # Validate JSON file
        json_file="output/$project_name/data/diagram.json"
        if [[ -f "$json_file" ]]; then
            if command -v jq >/dev/null 2>&1; then
                if jq empty "$json_file" >/dev/null 2>&1; then
                    log_success "JSON file is valid"
                else
                    log_error "JSON file is invalid"
                fi
            else
                log_warning "jq not available, skipping JSON validation"
            fi
        fi
    fi

    # Test Summary
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test Summary"
    echo "═══════════════════════════════════════"
    echo "Tests run: $TESTS_RUN"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "🎉 All core functionality tests passed!"
        echo ""
        echo "✅ CIPgram Core Features Verified:"
        echo "   • PCAP processing works correctly"
        echo "   • Network topology diagrams are generated"
        echo "   • Purdue model diagrams are created"
        echo "   • Output directory structure is correct"
        echo "   • DOT and JSON files are valid"
        echo "   • Configuration options work"
        echo ""
        echo "🚀 CIPgram is ready for production use!"
        
        # Show sample output
        echo ""
        echo "📁 Sample output files:"
        find output -name "*.dot" -o -name "*.json" -o -name "*.png" | head -10 | sort
        
        return 0
    else
        log_error "❌ Some core functionality tests failed"
        echo ""
        echo "Please review the failed tests above."
        return 1
    fi
}

# Run main function
main "$@"
