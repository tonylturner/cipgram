package validation

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"cipgram/pkg/errors"
	"cipgram/pkg/types"
)

// ConfigValidator provides validation for various configuration types
type ConfigValidator struct{}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// ValidateMappingTable validates a Purdue mapping table configuration
func (cv *ConfigValidator) ValidateMappingTable(table *types.MappingTable) error {
	if table == nil {
		return errors.ErrMissingRequiredField("mapping table")
	}

	if len(table.Mappings) == 0 {
		return errors.ErrInvalidConfiguration("mapping table", "must contain at least one mapping")
	}

	seenCIDRs := make(map[string]bool)

	for i, mapping := range table.Mappings {
		if err := cv.ValidateSubnetMapping(&mapping, i); err != nil {
			return errors.WrapValidation(err, errors.CodeInvalidConfig, "invalid mapping").
				WithContext("mapping_index", i)
		}

		// Check for duplicate CIDRs
		if seenCIDRs[mapping.CIDR] {
			return errors.NewValidationError(errors.CodeConfigConflict, "duplicate CIDR found").
				WithContext("cidr", mapping.CIDR).
				WithContext("mapping_index", i).
				WithDetails("Each CIDR can only appear once in the mapping table")
		}
		seenCIDRs[mapping.CIDR] = true
	}

	return nil
}

// ValidateSubnetMapping validates a single subnet mapping
func (cv *ConfigValidator) ValidateSubnetMapping(mapping *types.SubnetMapping, index int) error {
	if mapping == nil {
		return errors.ErrMissingRequiredField("subnet mapping")
	}

	// Validate CIDR
	if err := cv.ValidateCIDR(mapping.CIDR); err != nil {
		return errors.WrapValidation(err, errors.CodeInvalidCIDR, "invalid CIDR in subnet mapping").
			WithContext("mapping_index", index)
	}

	// Validate Purdue level
	if err := cv.ValidatePurdueLevel(mapping.Level); err != nil {
		return errors.WrapValidation(err, errors.CodeInvalidLevel, "invalid Purdue level in subnet mapping").
			WithContext("mapping_index", index)
	}

	// Validate role if provided
	if mapping.Role != "" {
		if err := cv.ValidateRole(mapping.Role); err != nil {
			return errors.WrapValidation(err, errors.CodeInvalidInput, "invalid role in subnet mapping").
				WithContext("mapping_index", index)
		}
	}

	return nil
}

// ValidateCIDR validates a CIDR notation string
func (cv *ConfigValidator) ValidateCIDR(cidr string) error {
	if cidr == "" {
		return errors.ErrMissingRequiredField("CIDR")
	}

	// Handle special cases
	if cidr == "any" || cidr == "0.0.0.0/0" {
		return nil // Valid but broad
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return errors.ErrInvalidCIDR(cidr, "invalid CIDR format").WithCause(err)
	}

	// Additional validation for reasonable subnet sizes
	ones, bits := network.Mask.Size()
	if bits == 32 { // IPv4
		if ones < 8 {
			return errors.ErrInvalidCIDR(cidr, "subnet mask too broad, minimum /8 recommended").
				WithContext("mask_bits", ones).
				WithContext("ip_version", "IPv4")
		}
	} else if bits == 128 { // IPv6
		if ones < 64 {
			return errors.ErrInvalidCIDR(cidr, "IPv6 subnet mask too broad, minimum /64 recommended").
				WithContext("mask_bits", ones).
				WithContext("ip_version", "IPv6")
		}
	}

	return nil
}

// ValidatePurdueLevel validates a Purdue model level
func (cv *ConfigValidator) ValidatePurdueLevel(level types.PurdueLevel) error {
	validLevels := map[types.PurdueLevel]bool{
		types.L0:      true,
		types.L1:      true,
		types.L2:      true,
		types.L3:      true,
		types.L3_5:    true,
		types.L4:      true,
		types.L5:      true,
		types.Unknown: true,
	}

	if !validLevels[level] {
		return errors.ErrInvalidPurdueLevel(string(level))
	}

	return nil
}

// ValidateRole validates a role string
func (cv *ConfigValidator) ValidateRole(role string) error {
	if role == "" {
		return fmt.Errorf("role cannot be empty")
	}

	// Role should be alphanumeric with spaces, hyphens, and underscores
	rolePattern := regexp.MustCompile(`^[a-zA-Z0-9\s\-_]+$`)
	if !rolePattern.MatchString(role) {
		return fmt.Errorf("role contains invalid characters: %s", role)
	}

	// Check length
	if len(role) > 100 {
		return fmt.Errorf("role too long (max 100 characters): %s", role)
	}

	return nil
}

// ValidateProtocol validates a protocol string
func (cv *ConfigValidator) ValidateProtocol(protocol types.Protocol) error {
	if protocol == "" {
		return fmt.Errorf("protocol cannot be empty")
	}

	// Check if it's a known protocol
	knownProtocols := map[types.Protocol]bool{
		types.ProtoUnknown:       true,
		types.ProtoENIP_Explicit: true,
		types.ProtoENIP_Implicit: true,
		types.ProtoModbus:        true,
		types.ProtoDNP3:          true,
		types.ProtoBACnet:        true,
		types.ProtoOPCClassic:    true,
		types.ProtoOPCUA:         true,
		types.ProtoS7Comm:        true,
		types.ProtoFins:          true,
		types.ProtoSlmp:          true,
		types.ProtoMelsecQ:       true,
		types.ProtoOmronTCP:      true,
		types.ProtoCCLink:        true,
		types.ProtoSINEC:         true,
		types.ProtoProfinetDCP:   true,
		types.ProtoProfinetRT:    true,
		types.ProtoProconOS:      true,
		types.ProtoEGD:           true,
		types.ProtoSRTP:          true,
		types.ProtoModbusRTU:     true,
		types.ProtoHTTP:          true,
		types.ProtoHTTPS:         true,
		types.ProtoSSH:           true,
		types.ProtoTelnet:        true,
		types.ProtoSNMP:          true,
		types.ProtoFTP:           true,
		types.ProtoSMTP:          true,
		types.ProtoDNS:           true,
		types.ProtoNTP:           true,
	}

	if !knownProtocols[protocol] {
		// Allow custom protocols but validate format
		protocolStr := string(protocol)
		if len(protocolStr) > 50 {
			return fmt.Errorf("protocol name too long (max 50 characters): %s", protocolStr)
		}

		// Protocol should be alphanumeric with hyphens, underscores, and forward slashes
		protocolPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_/]+$`)
		if !protocolPattern.MatchString(protocolStr) {
			return fmt.Errorf("protocol contains invalid characters: %s", protocolStr)
		}
	}

	return nil
}

// ValidateIEC62443Zone validates an IEC 62443 zone
func (cv *ConfigValidator) ValidateIEC62443Zone(zone types.IEC62443Zone) error {
	validZones := map[types.IEC62443Zone]bool{
		types.IndustrialZone:   true,
		types.DMZZone:          true,
		types.EnterpriseZone:   true,
		types.SafetyZone:       true,
		types.RemoteAccessZone: true,
	}

	if !validZones[zone] {
		return fmt.Errorf("invalid IEC 62443 zone: %s", zone)
	}

	return nil
}

// ValidateAsset validates an asset configuration
func (cv *ConfigValidator) ValidateAsset(asset *types.Asset) error {
	if asset == nil {
		return fmt.Errorf("asset cannot be nil")
	}

	// Validate ID
	if asset.ID == "" {
		return fmt.Errorf("asset ID cannot be empty")
	}

	// Validate IP if provided
	if asset.IP != "" {
		if net.ParseIP(asset.IP) == nil {
			return fmt.Errorf("invalid IP address: %s", asset.IP)
		}
	}

	// Validate MAC if provided
	if asset.MAC != "" {
		if err := cv.ValidateMAC(asset.MAC); err != nil {
			return fmt.Errorf("invalid MAC address: %w", err)
		}
	}

	// Validate Purdue level
	if err := cv.ValidatePurdueLevel(asset.PurdueLevel); err != nil {
		return err
	}

	// Validate IEC 62443 zone
	if err := cv.ValidateIEC62443Zone(asset.IEC62443Zone); err != nil {
		return err
	}

	// Validate protocols
	for _, protocol := range asset.Protocols {
		if err := cv.ValidateProtocol(protocol); err != nil {
			return fmt.Errorf("invalid protocol in asset: %w", err)
		}
	}

	// Validate roles
	for _, role := range asset.Roles {
		if err := cv.ValidateRole(role); err != nil {
			return fmt.Errorf("invalid role in asset: %w", err)
		}
	}

	return nil
}

// ValidateMAC validates a MAC address string
func (cv *ConfigValidator) ValidateMAC(mac string) error {
	if mac == "" {
		return errors.ErrMissingRequiredField("MAC address")
	}

	// Handle broadcast MAC
	if mac == "ff:ff:ff:ff:ff:ff" || mac == "FF:FF:FF:FF:FF:FF" {
		return nil
	}

	_, err := net.ParseMAC(mac)
	if err != nil {
		return errors.ErrInvalidMAC(mac).WithCause(err)
	}

	return nil
}

// ValidateNetworkModel validates an entire network model
func (cv *ConfigValidator) ValidateNetworkModel(model *types.NetworkModel) error {
	if model == nil {
		return fmt.Errorf("network model cannot be nil")
	}

	// Validate all assets
	for id, asset := range model.Assets {
		if err := cv.ValidateAsset(asset); err != nil {
			return fmt.Errorf("invalid asset %s: %w", id, err)
		}
	}

	// Validate flows reference existing assets
	for flowKey, flow := range model.Flows {
		if _, exists := model.Assets[flow.Source]; !exists {
			return fmt.Errorf("flow references non-existent source asset: %s", flow.Source)
		}
		if _, exists := model.Assets[flow.Destination]; !exists {
			return fmt.Errorf("flow references non-existent destination asset: %s", flow.Destination)
		}

		// Validate flow protocol
		if err := cv.ValidateProtocol(flow.Protocol); err != nil {
			return fmt.Errorf("invalid protocol in flow %v: %w", flowKey, err)
		}
	}

	return nil
}

// ValidatePortRange validates a port number is within valid range
func (cv *ConfigValidator) ValidatePortRange(port uint16) error {
	if port == 0 {
		return fmt.Errorf("port cannot be 0")
	}
	// Port 65535 is valid, so no upper bound check needed for uint16
	return nil
}

// ValidateHostname validates a hostname string
func (cv *ConfigValidator) ValidateHostname(hostname string) error {
	if hostname == "" {
		return nil // Empty hostname is allowed
	}

	// Basic hostname validation
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}

	// Hostname pattern: alphanumeric, hyphens, dots
	hostnamePattern := regexp.MustCompile(`^[a-zA-Z0-9\-\.]+$`)
	if !hostnamePattern.MatchString(hostname) {
		return fmt.Errorf("hostname contains invalid characters: %s", hostname)
	}

	// Cannot start or end with hyphen
	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return fmt.Errorf("hostname cannot start or end with hyphen: %s", hostname)
	}

	return nil
}
