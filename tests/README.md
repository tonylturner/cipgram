# CIPgram Tests

This directory contains organized test files, sample configurations, and integration tests for CIPgram.

## Structure

```
tests/
├── configs/          # Sample firewall configurations
│   └── opnsense/     # OPNsense configuration files
├── pcaps/            # Sample PCAP files  
│   └── samples/      # Test PCAP captures
├── integration/      # Integration test suite
│   ├── opnsense_test.go
│   └── run_tests.sh
└── unit/             # Unit tests (future)
```

## Running Tests

### Integration Tests
```bash
cd tests/integration
./run_tests.sh
```

### Individual Tests
```bash
# Test OPNsense integration
cd tests/integration
go run opnsense_test.go

# Test with your own data
../../cipgram -firewall-config ../configs/opnsense/your_config.xml -project "my_test"
```

## Adding Test Data

### OPNsense Configurations
1. Export your OPNsense configuration (System > Configuration > Backups)
2. Sanitize sensitive information (IP addresses, passwords, etc.)
3. Place in `tests/configs/opnsense/`
4. Update test files to reference your config

### PCAP Files
1. Capture industrial network traffic using tcpdump, Wireshark, or similar
2. Sanitize or use representative data only
3. Place in `tests/pcaps/samples/`
4. Keep file sizes reasonable for testing

### Example Commands for Data Collection

#### PCAP Capture
```bash
# Capture on industrial network interface
sudo tcpdump -i eth1 -w industrial_baseline.pcap -s 65535

# Wireshark command line
tshark -i eth1 -w industrial_traffic.pcap -f "not ssh"
```

#### OPNsense Config Export
```bash
# Via web interface
# System > Configuration > Backups > Download configuration

# Via SSH/console
cp /conf/config.xml /tmp/test_config.xml
```

## Test Data Guidelines

### Sanitization
- **Remove sensitive information**: Real IP addresses, passwords, certificates
- **Use consistent test networks**: 192.168.100.0/24, 10.1.0.0/16, etc.
- **Anonymize hostnames**: device-001, plc-east, hmi-central, etc.

### Representative Data
- **Include diverse protocols**: EtherNet/IP, Modbus, S7, OPC-UA
- **Show different device types**: PLCs, HMIs, SCADA servers, engineering workstations
- **Capture normal operations**: Steady-state traffic, not just startup sequences

### File Organization
```
configs/opnsense/
├── basic_industrial.xml       # Simple OT network with 3 zones
├── complex_manufacturing.xml  # Large facility with multiple zones  
└── security_focused.xml       # High-security segmentation example

pcaps/samples/
├── ethernet_ip_baseline.pcap  # Allen-Bradley EtherNet/IP traffic
├── modbus_scada.pcap          # Modbus TCP SCADA operations
└── mixed_protocols.pcap       # Multi-vendor industrial environment
```

## Test Validation

Tests should validate:
- **Parsing accuracy**: Correct extraction of networks, rules, and devices
- **Classification correctness**: Proper Purdue/IEC 62443 zone assignment  
- **Output completeness**: All expected diagram types and data files generated
- **Performance**: Reasonable processing time for typical data sizes

## Contributing Test Data

When contributing test data:

1. **Sanitize thoroughly** - Remove all sensitive information
2. **Document the source** - Industrial environment type, vendor mix, etc.
3. **Provide context** - Network purpose, security posture, any known issues
4. **Test compatibility** - Ensure files work with current parsers

## Future Enhancements

Planned test improvements:
- **Unit test coverage** for individual parsers and analyzers
- **Performance benchmarking** with various data sizes
- **Regression testing** to ensure consistent analysis results
- **Mock data generators** for consistent test environments

For questions about testing or contributing test data, see the main project documentation.
