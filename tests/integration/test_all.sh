#!/bin/bash

# CIPgram Complete Integration Test Suite
# Tests all major functionality including PCAP processing, diagram generation, and configuration options

set -e

echo "🧪 CIPgram Complete Integration Test Suite"
echo "==========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
PROJECT_ROOT="$(cd ../.. && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

run_test_suite() {
    local test_name="$1"
    local test_script="$2"
    
    echo ""
    echo "═══════════════════════════════════════"
    echo "Running: $test_name"
    echo "═══════════════════════════════════════"
    
    if [[ -x "$test_script" ]]; then
        if "$test_script"; then
            log_success "$test_name completed successfully"
            return 0
        else
            log_error "$test_name failed"
            return 1
        fi
    else
        log_warning "$test_name script not found or not executable: $test_script"
        return 1
    fi
}

main() {
    log_info "Starting Complete Integration Test Suite"
    log_info "Project root: $PROJECT_ROOT"
    log_info "Timestamp: $TIMESTAMP"
    echo ""

    # Change to project root
    cd "$PROJECT_ROOT"

    # Build the project first
    log_info "Building CIPgram..."
    if make build; then
        log_success "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi

    # Run unit tests first
    echo ""
    echo "═══════════════════════════════════════"
    echo "Running Unit Tests"
    echo "═══════════════════════════════════════"
    
    if make test; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        echo "Fix unit tests before running integration tests"
        exit 1
    fi

    # Run integration tests
    local tests_passed=0
    local tests_failed=0

    # Test 1: PCAP Processing Integration
    if run_test_suite "PCAP Processing Integration" "tests/integration/test_pcap_processing.sh"; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi

    # Test 2: Go Integration Tests (if available)
    if [[ -f "tests/integration/pcap_integration_test.go" ]]; then
        echo ""
        echo "═══════════════════════════════════════"
        echo "Running Go Integration Tests"
        echo "═══════════════════════════════════════"
        
        cd tests/integration
        if go test -v -timeout 10m .; then
            log_success "Go integration tests passed"
            ((tests_passed++))
        else
            log_error "Go integration tests failed"
            ((tests_failed++))
        fi
        cd "$PROJECT_ROOT"
    fi

    # Test 3: Existing Integration Scripts
    local existing_scripts=(
        "tests/integration/test_cipgram.sh"
        "tests/integration/test_network_diagram.sh"
    )

    for script in "${existing_scripts[@]}"; do
        if [[ -f "$script" ]]; then
            script_name=$(basename "$script" .sh)
            if run_test_suite "Legacy $script_name" "$script"; then
                ((tests_passed++))
            else
                ((tests_failed++))
            fi
        fi
    done

    # Final Summary
    echo ""
    echo "═══════════════════════════════════════"
    echo "Integration Test Suite Summary"
    echo "═══════════════════════════════════════"
    echo "Tests passed: $tests_passed"
    echo "Tests failed: $tests_failed"
    echo ""

    if [[ $tests_failed -eq 0 ]]; then
        log_success "🎉 All integration tests passed!"
        echo ""
        echo "✅ CIPgram is fully functional:"
        echo "   • PCAP processing works correctly"
        echo "   • Network diagrams are generated"
        echo "   • IEC62443 diagrams are created"
        echo "   • Configuration options work"
        echo "   • Output structure is correct"
        echo "   • File formats are valid"
        echo ""
        echo "🚀 CIPgram is ready for production use!"
        
        # Show sample output
        echo ""
        echo "📁 Sample output structure:"
        if [[ -d "output" ]]; then
            find output -type d -maxdepth 3 | head -10 | sort
        fi
        
        exit 0
    else
        log_error "❌ Some integration tests failed"
        echo ""
        echo "Please review the failed tests above and fix any issues."
        echo "Common issues:"
        echo "  • Missing PCAP files in pcaps/ directory"
        echo "  • Missing Graphviz installation"
        echo "  • Insufficient disk space for output"
        echo "  • Permission issues with output directory"
        exit 1
    fi
}

# Run main function
main "$@"
