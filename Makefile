# Makefile for CIPgram project

.PHONY: help build test lint clean fmt vet staticcheck install-tools

# Default target
help:
	@echo "Available targets:"
	@echo "  build            - Build the cipgram binary"
	@echo "  test             - Run unit tests"
	@echo "  integration-test - Run integration tests"
	@echo "  test-pcap        - Run PCAP processing tests only"
	@echo "  lint             - Run all linting checks"
	@echo "  fmt              - Format code with gofmt"
	@echo "  vet              - Run go vet"
	@echo "  staticcheck      - Run staticcheck"
	@echo "  check            - Run all quality checks"
	@echo "  validate         - Run full validation (unit + integration)"
	@echo "  clean            - Clean build artifacts"
	@echo "  install-tools    - Install required tools"

# Build the application
build:
	@echo "Building cipgram..."
	go build -o cipgram cmd/cipgram/main.go

# Run tests
test:
	@echo "Running tests..."
	go test ./tests/unit/... -v

# Format code
fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	goimports -w .

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Run staticcheck (if available)
staticcheck:
	@echo "Running staticcheck..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed. Run 'make install-tools' to install it."; \
	fi

# Run all linting checks
# Note: We use individual Go tools instead of golangci-lint due to version compatibility issues
lint: fmt vet staticcheck
	@echo "All linting checks completed."

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f cipgram
	go clean

# Install required tools
install-tools:
	@echo "Installing development tools..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	@echo "Tools installed successfully."

# Check if code is properly formatted
check-fmt:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "The following files are not properly formatted:"; \
		gofmt -l .; \
		exit 1; \
	else \
		echo "All files are properly formatted."; \
	fi

# Run integration tests
integration-test:
	@echo "Running integration tests..."
	@chmod +x tests/integration/test_all.sh
	@tests/integration/test_all.sh

# Run PCAP processing tests only
test-pcap:
	@echo "Running PCAP processing tests..."
	@chmod +x tests/integration/test_core_functionality.sh
	@tests/integration/test_core_functionality.sh

# Run a comprehensive check (used in CI)
check: check-fmt vet staticcheck test
	@echo "All checks passed!"

# Run full validation including integration tests
validate: check integration-test
	@echo "Full validation completed!"
