package validation_test

import (
	"testing"

	"cipgram/pkg/types"
	"cipgram/pkg/validation"
)

func TestValidateCIDR(t *testing.T) {
	validator := validation.NewConfigValidator()

	testCases := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"Valid IPv4 CIDR", "192.168.1.0/24", false},
		{"Valid IPv6 CIDR", "2001:db8::/64", false},
		{"Valid single host", "192.168.1.1/32", false},
		{"Valid any", "any", false},
		{"Valid 0.0.0.0/0", "0.0.0.0/0", false},
		{"Empty CIDR", "", true},
		{"Invalid format", "192.168.1", true},
		{"Invalid IP", "999.999.999.999/24", true},
		{"Too broad IPv4", "10.0.0.0/7", true},
		{"Too broad IPv6", "2001:db8::/63", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateCIDR(tc.cidr)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateCIDR(%s) error = %v, wantErr %v", tc.cidr, err, tc.wantErr)
			}
		})
	}
}

func TestValidatePurdueLevel(t *testing.T) {
	validator := validation.NewConfigValidator()

	testCases := []struct {
		name    string
		level   types.PurdueLevel
		wantErr bool
	}{
		{"Valid L0", types.L0, false},
		{"Valid L1", types.L1, false},
		{"Valid L2", types.L2, false},
		{"Valid L3", types.L3, false},
		{"Valid L3.5", types.L3_5, false},
		{"Valid L4", types.L4, false},
		{"Valid L5", types.L5, false},
		{"Valid Unknown", types.Unknown, false},
		{"Invalid level", types.PurdueLevel("Invalid"), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidatePurdueLevel(tc.level)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePurdueLevel(%s) error = %v, wantErr %v", tc.level, err, tc.wantErr)
			}
		})
	}
}

func TestValidateRole(t *testing.T) {
	validator := validation.NewConfigValidator()

	testCases := []struct {
		name    string
		role    string
		wantErr bool
	}{
		{"Valid simple role", "PLC", false},
		{"Valid role with spaces", "SCADA Server", false},
		{"Valid role with hyphens", "HMI-Station", false},
		{"Valid role with underscores", "Data_Historian", false},
		{"Empty role", "", true},
		{"Role with invalid chars", "PLC@Server", true},
		{"Too long role", string(make([]byte, 101)), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateRole(tc.role)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRole(%s) error = %v, wantErr %v", tc.role, err, tc.wantErr)
			}
		})
	}
}

func TestValidateProtocol(t *testing.T) {
	validator := validation.NewConfigValidator()

	testCases := []struct {
		name     string
		protocol types.Protocol
		wantErr  bool
	}{
		{"Valid Modbus", types.ProtoModbus, false},
		{"Valid EtherNet/IP", types.ProtoENIP_Explicit, false},
		{"Valid OPC-UA", types.ProtoOPCUA, false},
		{"Valid custom protocol", types.Protocol("Custom-Protocol"), false},
		{"Empty protocol", types.Protocol(""), true},
		{"Protocol with invalid chars", types.Protocol("Proto@col!"), true},
		{"Too long protocol", types.Protocol(string(make([]byte, 51))), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateProtocol(tc.protocol)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateProtocol(%s) error = %v, wantErr %v", tc.protocol, err, tc.wantErr)
			}
		})
	}
}

func TestValidateMAC(t *testing.T) {
	validator := validation.NewConfigValidator()

	testCases := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		{"Valid MAC colon format", "00:0c:29:12:34:56", false},
		{"Valid MAC hyphen format", "00-0c-29-12-34-56", false},
		{"Valid broadcast MAC", "ff:ff:ff:ff:ff:ff", false},
		{"Valid uppercase MAC", "AA:BB:CC:DD:EE:FF", false},
		{"Empty MAC", "", true},
		{"Invalid MAC format", "00:0c:29:12:34", true},
		{"Invalid MAC chars", "gg:hh:ii:jj:kk:ll", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateMAC(tc.mac)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateMAC(%s) error = %v, wantErr %v", tc.mac, err, tc.wantErr)
			}
		})
	}
}

func TestValidateAsset(t *testing.T) {
	validator := validation.NewConfigValidator()

	validAsset := &types.Asset{
		ID:           "192.168.1.10",
		IP:           "192.168.1.10",
		MAC:          "00:0c:29:12:34:56",
		Hostname:     "plc-001",
		PurdueLevel:  types.L2,
		IEC62443Zone: types.IndustrialZone,
		Protocols:    []types.Protocol{types.ProtoModbus},
		Roles:        []string{"PLC"},
	}

	testCases := []struct {
		name    string
		asset   *types.Asset
		wantErr bool
	}{
		{"Valid asset", validAsset, false},
		{"Nil asset", nil, true},
		{"Empty ID", &types.Asset{ID: ""}, true},
		{"Invalid IP", &types.Asset{ID: "test", IP: "invalid"}, true},
		{"Invalid MAC", &types.Asset{ID: "test", MAC: "invalid"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateAsset(tc.asset)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateAsset() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateSubnetMapping(t *testing.T) {
	validator := validation.NewConfigValidator()

	validMapping := &types.SubnetMapping{
		CIDR:  "192.168.1.0/24",
		Level: types.L2,
		Role:  "Production",
	}

	testCases := []struct {
		name    string
		mapping *types.SubnetMapping
		wantErr bool
	}{
		{"Valid mapping", validMapping, false},
		{"Nil mapping", nil, true},
		{"Invalid CIDR", &types.SubnetMapping{CIDR: "invalid", Level: types.L2}, true},
		{"Invalid level", &types.SubnetMapping{CIDR: "192.168.1.0/24", Level: types.PurdueLevel("invalid")}, true},
		{"Invalid role", &types.SubnetMapping{CIDR: "192.168.1.0/24", Level: types.L2, Role: "Role@Invalid"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateSubnetMapping(tc.mapping, 0)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSubnetMapping() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateMappingTable(t *testing.T) {
	validator := validation.NewConfigValidator()

	validTable := &types.MappingTable{
		Mappings: []types.SubnetMapping{
			{CIDR: "192.168.1.0/24", Level: types.L2, Role: "Production"},
			{CIDR: "192.168.2.0/24", Level: types.L3, Role: "SCADA"},
		},
	}

	duplicateTable := &types.MappingTable{
		Mappings: []types.SubnetMapping{
			{CIDR: "192.168.1.0/24", Level: types.L2, Role: "Production"},
			{CIDR: "192.168.1.0/24", Level: types.L3, Role: "SCADA"}, // Duplicate CIDR
		},
	}

	testCases := []struct {
		name    string
		table   *types.MappingTable
		wantErr bool
	}{
		{"Valid table", validTable, false},
		{"Nil table", nil, true},
		{"Empty table", &types.MappingTable{}, true},
		{"Duplicate CIDR", duplicateTable, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateMappingTable(tc.table)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateMappingTable() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	validator := validation.NewConfigValidator()

	testCases := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{"Valid hostname", "plc-001", false},
		{"Valid FQDN", "server.example.com", false},
		{"Empty hostname", "", false}, // Empty is allowed
		{"Hostname with numbers", "device123", false},
		{"Hostname starting with hyphen", "-invalid", true},
		{"Hostname ending with hyphen", "invalid-", true},
		{"Hostname with invalid chars", "device@server", true},
		{"Too long hostname", string(make([]byte, 254)), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateHostname(tc.hostname)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateHostname(%s) error = %v, wantErr %v", tc.hostname, err, tc.wantErr)
			}
		})
	}
}
