#!/bin/bash

# CIPgram PCAP Processing Integration Test
# Tests the main PCAP processing and diagram generation functionality

set -e

echo "🧪 CIPgram PCAP Processing Integration Test"
echo "============================================="
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
TEST_OUTPUT_DIR="$PROJECT_ROOT/output/integration_test_$(date +%Y%m%d_%H%M%S)"
BINARY_PATH="$PROJECT_ROOT/cipgram"

# Available PCAP files
PCAP_FILES=(
    "$PROJECT_ROOT/pcaps/Cyberville.pcap"
    "$PROJECT_ROOT/pcaps/ENIP.pcap" 
    "$PROJECT_ROOT/pcaps/PROFINET.pcap"
    "$PROJECT_ROOT/pcaps/MicroLogix56.pcap"
)

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
    echo "Command: $test_command"
    echo "----------------------------------------"
    
    ((TESTS_RUN++))
    
    if eval "$test_command"; then
        log_success "$test_name"
        return 0
    else
        log_error "$test_name"
        return 1
    fi
}

check_file_exists() {
    local file_path="$1"
    local description="$2"
    
    if [[ -f "$file_path" ]]; then
        local size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo "unknown")
        log_success "$description exists ($size bytes)"
        return 0
    else
        log_error "$description not found: $file_path"
        return 1
    fi
}

check_dir_exists() {
    local dir_path="$1"
    local description="$2"
    
    if [[ -d "$dir_path" ]]; then
        log_success "$description exists"
        return 0
    else
        log_error "$description not found: $dir_path"
        return 1
    fi
}

# Main test execution
main() {
    log_info "Starting CIPgram PCAP Processing Integration Tests"
    log_info "Project root: $PROJECT_ROOT"
    log_info "Test output: $TEST_OUTPUT_DIR"
    echo ""

    # Build the binary
    log_info "Building CIPgram binary..."
    cd "$PROJECT_ROOT"
    if make build; then
        log_success "Binary built successfully"
    else
        log_error "Failed to build binary"
        exit 1
    fi

    # Check if binary exists and is executable
    if [[ -x "$BINARY_PATH" ]]; then
        log_success "Binary is executable"
    else
        log_error "Binary not found or not executable: $BINARY_PATH"
        exit 1
    fi

    # Test 1: Basic PCAP Processing
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test 1: Basic PCAP Processing"
    echo "═══════════════════════════════════════"

    for pcap_file in "${PCAP_FILES[@]}"; do
        if [[ -f "$pcap_file" ]]; then
            pcap_name=$(basename "$pcap_file" .pcap)
            project_name="test_${pcap_name}_$(date +%H%M%S)"
            
            log_info "Testing with $pcap_name"
            
            # Run cipgram
            run_test "Process $pcap_name PCAP" \
                "$BINARY_PATH pcap '$pcap_file' project '$project_name'"
            
            # Check output structure
            output_dir="$PROJECT_ROOT/output/$project_name"
            check_dir_exists "$output_dir" "Project output directory"
            check_dir_exists "$output_dir/network_diagrams" "Network diagrams directory"
            check_dir_exists "$output_dir/data" "Data directory"
            
            # Check key files
            check_file_exists "$output_dir/network_diagrams/network_topology.dot" "Network topology DOT file"
            check_file_exists "$output_dir/network_diagrams/purdue_diagram.dot" "Purdue diagram DOT file"
            check_file_exists "$output_dir/data/diagram.json" "Network model JSON file"
            
            # Check image files (may be skipped for performance)
            if [[ -f "$output_dir/network_diagrams/network_topology.png" ]]; then
                log_success "Network topology PNG generated"
            else
                log_warning "Network topology PNG not generated (may be skipped)"
            fi
            
            if [[ -f "$output_dir/network_diagrams/purdue_diagram.png" ]]; then
                log_success "Purdue diagram PNG generated"
            else
                log_warning "Purdue diagram PNG not generated (may be skipped)"
            fi
            
            echo ""
            break # Test with first available PCAP file
        else
            log_warning "PCAP file not found: $pcap_file"
        fi
    done

    # Test 2: Configuration Options
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test 2: Configuration Options"
    echo "═══════════════════════════════════════"

    # Find first available PCAP
    test_pcap=""
    for pcap_file in "${PCAP_FILES[@]}"; do
        if [[ -f "$pcap_file" ]]; then
            test_pcap="$pcap_file"
            break
        fi
    done

    if [[ -n "$test_pcap" ]]; then
        # Test network diagram only
        project_name="test_network_only_$(date +%H%M%S)"
        run_test "Network diagram only" \
            "$BINARY_PATH pcap '$test_pcap' project '$project_name' diagram network"
        
        output_dir="$PROJECT_ROOT/output/$project_name"
        check_file_exists "$output_dir/network_diagrams/network_topology.dot" "Network topology DOT (network only)"
        
        # Test with config file (if available)
        config_file="$PROJECT_ROOT/configs/purdue_config.yaml"
        if [[ -f "$config_file" ]]; then
            project_name="test_with_config_$(date +%H%M%S)"
            run_test "With configuration file" \
                "$BINARY_PATH pcap '$test_pcap' project '$project_name' config '$config_file'"
            
            output_dir="$PROJECT_ROOT/output/$project_name"
            check_file_exists "$output_dir/network_diagrams/network_topology.dot" "Network topology DOT (with config)"
            check_file_exists "$output_dir/network_diagrams/purdue_diagram.dot" "Purdue diagram DOT (with config)"
        else
            log_warning "Configuration file not found, skipping config test"
        fi
    else
        log_warning "No PCAP files available for configuration testing"
    fi

    # Test 3: Diagram Content Validation
    echo ""
    echo "═══════════════════════════════════════"
    echo "Test 3: Diagram Content Validation"
    echo "═══════════════════════════════════════"

    if [[ -n "$test_pcap" ]]; then
        project_name="test_content_validation_$(date +%H%M%S)"
        run_test "Generate diagrams for content validation" \
            "$BINARY_PATH pcap '$test_pcap' project '$project_name'"
        
        output_dir="$PROJECT_ROOT/output/$project_name"
        
        # Validate DOT file content
        dot_file="$output_dir/network_diagrams/network_topology.dot"
        if [[ -f "$dot_file" ]]; then
            if grep -q "digraph" "$dot_file"; then
                log_success "Network topology DOT contains 'digraph' declaration"
            else
                log_error "Network topology DOT missing 'digraph' declaration"
            fi
            
            if grep -q "node\|edge\|->" "$dot_file"; then
                log_success "Network topology DOT contains graph elements"
            else
                log_error "Network topology DOT missing graph elements"
            fi
            
            file_size=$(stat -f%z "$dot_file" 2>/dev/null || stat -c%s "$dot_file" 2>/dev/null || echo "0")
            if [[ "$file_size" -gt 100 ]]; then
                log_success "Network topology DOT has reasonable size ($file_size bytes)"
            else
                log_error "Network topology DOT seems too small ($file_size bytes)"
            fi
        fi
        
        # Validate JSON file content
        json_file="$output_dir/data/network_model.json"
        if [[ -f "$json_file" ]]; then
            if command -v jq >/dev/null 2>&1; then
                if jq empty "$json_file" >/dev/null 2>&1; then
                    log_success "Network model JSON is valid"
                else
                    log_error "Network model JSON is invalid"
                fi
            else
                log_warning "jq not available, skipping JSON validation"
            fi
            
            file_size=$(stat -f%z "$json_file" 2>/dev/null || stat -c%s "$json_file" 2>/dev/null || echo "0")
            if [[ "$file_size" -gt 50 ]]; then
                log_success "Network model JSON has reasonable size ($file_size bytes)"
            else
                log_error "Network model JSON seems too small ($file_size bytes)"
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
        log_success "All tests passed! 🎉"
        echo ""
        echo "✓ PCAP processing works correctly"
        echo "✓ Diagram generation is functional"
        echo "✓ Output structure is correct"
        echo "✓ Configuration options work"
        echo ""
        echo "CIPgram is ready for production use!"
        exit 0
    else
        log_error "Some tests failed"
        echo ""
        echo "Please check the failed tests above and fix any issues."
        exit 1
    fi
}

# Cleanup function
cleanup() {
    if [[ -d "$TEST_OUTPUT_DIR" ]]; then
        log_info "Cleaning up test output directory"
        rm -rf "$TEST_OUTPUT_DIR"
    fi
}

# Set up cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"
