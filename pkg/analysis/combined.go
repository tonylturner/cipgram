package analysis

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"cipgram/pkg/types"
)

// CombinedAnalyzer performs advanced analysis by combining multiple input sources
type CombinedAnalyzer struct {
	sources []types.InputSource
	models  []*types.NetworkModel
}

// NewCombinedAnalyzer creates a new combined analyzer
func NewCombinedAnalyzer(sources ...types.InputSource) *CombinedAnalyzer {
	return &CombinedAnalyzer{
		sources: sources,
		models:  make([]*types.NetworkModel, 0, len(sources)),
	}
}

// ParseAllSources parses all input sources and stores the models
func (c *CombinedAnalyzer) ParseAllSources() error {
	for i, source := range c.sources {
		log.Printf("Parsing source %d: %s (%s)", i+1, source.GetMetadata().Source, source.GetType())

		model, err := source.Parse()
		if err != nil {
			return fmt.Errorf("failed to parse source %d: %v", i+1, err)
		}

		c.models = append(c.models, model)
	}

	return nil
}

// GenerateCombinedModel creates a unified model from all sources
func (c *CombinedAnalyzer) GenerateCombinedModel() (*types.NetworkModel, error) {
	if len(c.models) == 0 {
		return nil, fmt.Errorf("no models to combine - call ParseAllSources first")
	}

	// Start with the first model as base
	combined := &types.NetworkModel{
		Assets:   make(map[string]*types.Asset),
		Networks: make(map[string]*types.NetworkSegment),
		Flows:    make(map[types.FlowKey]*types.Flow),
		Policies: []*types.SecurityPolicy{},
		Metadata: types.InputMetadata{
			Source:    "Combined Analysis",
			Type:      "combined",
			Timestamp: time.Now(),
		},
	}

	// Combine all models
	for _, model := range c.models {
		switch model.Metadata.Type {
		case types.InputTypePCAP:
			c.integratePCAPModel(combined, model)
		case types.InputTypeOPNsense:
			c.integrateFirewallModel(combined, model)
		default:
			log.Printf("Warning: Unknown model type: %s", model.Metadata.Type)
		}
	}

	// Post-processing: reconcile conflicts and enhance
	c.reconcileModels(combined)
	c.performAdvancedAnalysis(combined)

	return combined, nil
}

// integratePCAPModel integrates PCAP data into the combined model
func (c *CombinedAnalyzer) integratePCAPModel(combined *types.NetworkModel, pcapModel *types.NetworkModel) {
	log.Printf("Integrating PCAP model: %d assets, %d flows", len(pcapModel.Assets), len(pcapModel.Flows))

	// Merge assets (PCAP provides actual traffic data)
	for id, asset := range pcapModel.Assets {
		if existing, exists := combined.Assets[id]; exists {
			// Merge with existing asset (likely from firewall config)
			c.mergeAssets(existing, asset)
		} else {
			// Add new asset discovered in PCAP
			combined.Assets[id] = asset
		}
	}

	// Add all flows from PCAP (this is the actual traffic)
	for key, flow := range pcapModel.Flows {
		combined.Flows[key] = flow
	}

	// Merge inferred networks from PCAP
	for id, network := range pcapModel.Networks {
		if existing, exists := combined.Networks[id]; exists {
			// Merge network information
			c.mergeNetworks(existing, network)
		} else {
			// Add inferred network
			combined.Networks[id] = network
		}
	}
}

// integrateFirewallModel integrates firewall configuration data
func (c *CombinedAnalyzer) integrateFirewallModel(combined *types.NetworkModel, fwModel *types.NetworkModel) {
	log.Printf("Integrating firewall model: %d networks, %d policies", len(fwModel.Networks), len(fwModel.Policies))

	// Networks from firewall are authoritative for topology
	for id, network := range fwModel.Networks {
		if existing, exists := combined.Networks[id]; exists {
			// Firewall config overrides inferred data
			c.mergeNetworks(network, existing) // firewall first
		} else {
			combined.Networks[id] = network
		}
	}

	// Add all security policies
	combined.Policies = append(combined.Policies, fwModel.Policies...)

	// Create placeholder assets for networks defined in firewall but not seen in traffic
	for _, network := range fwModel.Networks {
		if network.CIDR != "" {
			// Create representative asset for this network if no traffic seen
			assetID := fmt.Sprintf("network_%s", network.ID)
			if _, exists := combined.Assets[assetID]; !exists {
				combined.Assets[assetID] = &types.Asset{
					ID:           assetID,
					IP:           c.extractNetworkIP(network.CIDR),
					DeviceName:   fmt.Sprintf("%s Gateway", network.Name),
					IEC62443Zone: network.Zone,
					Criticality:  c.mapRiskToCriticality(network.Risk),
					Exposure:     c.inferExposureFromZone(network.Zone),
					Protocols:    []types.Protocol{},
				}
			}
		}
	}
}

// reconcileModels resolves conflicts between data sources
func (c *CombinedAnalyzer) reconcileModels(combined *types.NetworkModel) {
	log.Printf("Reconciling combined model...")

	// Reconcile asset assignments to networks
	for _, asset := range combined.Assets {
		// Find which network this asset belongs to based on IP
		networkID := c.findNetworkForAsset(asset, combined.Networks)
		if networkID != "" {
			// Ensure asset is in the correct network's asset list
			if network, exists := combined.Networks[networkID]; exists {
				network.Assets = c.addAssetIfNotExists(network.Assets, asset)
			}
		}
	}

	// Validate flows against security policies
	c.validateFlowsAgainstPolicies(combined)
}

// validateFlowsAgainstPolicies marks flows as allowed/denied based on policies
func (c *CombinedAnalyzer) validateFlowsAgainstPolicies(model *types.NetworkModel) {
	for _, flow := range model.Flows {
		flow.Allowed = c.isFlowAllowedByPolicies(flow, model.Policies)
	}
}

// performAdvancedAnalysis performs analysis only possible with combined data
func (c *CombinedAnalyzer) performAdvancedAnalysis(combined *types.NetworkModel) {
	log.Printf("Performing advanced combined analysis...")

	// Identify policy violations
	violations := c.identifyPolicyViolations(combined)
	log.Printf("Found %d potential policy violations", len(violations))

	// Identify segmentation opportunities
	opportunities := c.identifySegmentationOpportunities(combined)
	log.Printf("Found %d segmentation opportunities", len(opportunities))

	// Assess actual vs configured security posture
	c.assessSecurityPosture(combined)

	// Store results in model for diagram generation
	combined.Metadata.Size = int64(len(violations) + len(opportunities))
}

// Advanced analysis functions

// identifyPolicyViolations finds traffic that violates firewall policies
func (c *CombinedAnalyzer) identifyPolicyViolations(model *types.NetworkModel) []PolicyViolation {
	violations := []PolicyViolation{}

	for _, flow := range model.Flows {
		allowed := c.isFlowAllowedByPolicies(flow, model.Policies)
		if !allowed {
			violations = append(violations, PolicyViolation{
				Flow:        flow,
				Description: fmt.Sprintf("Traffic from %s to %s not explicitly allowed", flow.Source, flow.Destination),
				Severity:    "High",
			})
		}
	}

	return violations
}

// identifySegmentationOpportunities finds areas for improved segmentation
func (c *CombinedAnalyzer) identifySegmentationOpportunities(model *types.NetworkModel) []SegmentationOpportunity {
	opportunities := []SegmentationOpportunity{}

	// Look for cross-zone traffic that might need better controls
	for _, flow := range model.Flows {
		srcAsset := model.Assets[flow.Source]
		dstAsset := model.Assets[flow.Destination]

		if srcAsset != nil && dstAsset != nil {
			if srcAsset.IEC62443Zone != dstAsset.IEC62443Zone {
				// Cross-zone traffic - potential segmentation opportunity
				opportunities = append(opportunities, SegmentationOpportunity{
					Type:        "Cross-Zone Traffic",
					Description: fmt.Sprintf("Traffic between %s and %s zones", srcAsset.IEC62443Zone, dstAsset.IEC62443Zone),
					SourceZone:  srcAsset.IEC62443Zone,
					DestZone:    dstAsset.IEC62443Zone,
					Protocol:    flow.Protocol,
					Priority:    c.calculatePriority(srcAsset, dstAsset),
				})
			}
		}
	}

	return opportunities
}

// assessSecurityPosture compares actual traffic with configured policies
func (c *CombinedAnalyzer) assessSecurityPosture(model *types.NetworkModel) SecurityPosture {
	posture := SecurityPosture{
		TotalFlows:      len(model.Flows),
		PolicyCount:     len(model.Policies),
		ComplianceScore: 0.0,
		RiskLevel:       types.MediumRisk,
	}

	// Calculate compliance score based on policy coverage
	allowedFlows := 0
	for _, flow := range model.Flows {
		if c.isFlowAllowedByPolicies(flow, model.Policies) {
			allowedFlows++
		}
	}

	if posture.TotalFlows > 0 {
		posture.ComplianceScore = float64(allowedFlows) / float64(posture.TotalFlows) * 100
	}

	// Assess overall risk
	if posture.ComplianceScore > 90 {
		posture.RiskLevel = types.LowRisk
	} else if posture.ComplianceScore < 70 {
		posture.RiskLevel = types.HighRisk
	}

	log.Printf("Security posture: %.1f%% compliance, %s risk", posture.ComplianceScore, posture.RiskLevel)
	return posture
}

// Helper functions

func (c *CombinedAnalyzer) mergeAssets(target, source *types.Asset) {
	// Merge protocols
	for _, proto := range source.Protocols {
		target.Protocols = c.addProtocolIfNotExists(target.Protocols, proto)
	}

	// Prefer PCAP data for actual device information
	if source.DeviceName != "" && target.DeviceName == "" {
		target.DeviceName = source.DeviceName
	}
	if source.MAC != "" && target.MAC == "" {
		target.MAC = source.MAC
	}

	// Keep the more specific classification
	if source.PurdueLevel != types.Unknown && target.PurdueLevel == types.Unknown {
		target.PurdueLevel = source.PurdueLevel
	}
}

func (c *CombinedAnalyzer) mergeNetworks(target, source *types.NetworkSegment) {
	// Merge assets
	for _, asset := range source.Assets {
		target.Assets = c.addAssetIfNotExists(target.Assets, asset)
	}

	// Prefer firewall config for authoritative network information
	if source.CIDR != "" && target.CIDR == "" {
		target.CIDR = source.CIDR
	}
	if source.Zone != "" && target.Zone == "" {
		target.Zone = source.Zone
	}
}

func (c *CombinedAnalyzer) addProtocolIfNotExists(protocols []types.Protocol, proto types.Protocol) []types.Protocol {
	for _, existing := range protocols {
		if existing == proto {
			return protocols
		}
	}
	return append(protocols, proto)
}

func (c *CombinedAnalyzer) addAssetIfNotExists(assets []*types.Asset, asset *types.Asset) []*types.Asset {
	for _, existing := range assets {
		if existing.ID == asset.ID {
			return assets
		}
	}
	return append(assets, asset)
}

func (c *CombinedAnalyzer) findNetworkForAsset(asset *types.Asset, networks map[string]*types.NetworkSegment) string {
	if asset.IP == "" {
		return ""
	}

	assetIP := net.ParseIP(asset.IP)
	if assetIP == nil {
		return ""
	}

	for id, network := range networks {
		if network.CIDR != "" {
			_, subnet, err := net.ParseCIDR(network.CIDR)
			if err == nil && subnet.Contains(assetIP) {
				return id
			}
		}
	}

	return ""
}

func (c *CombinedAnalyzer) isFlowAllowedByPolicies(flow *types.Flow, policies []*types.SecurityPolicy) bool {
	// Simplified policy checking - would be more complex in practice
	for _, policy := range policies {
		if policy.Action == types.Allow {
			// Check if this policy covers the flow
			if c.policyCoversFlow(policy, flow) {
				return true
			}
		}
	}
	return false
}

func (c *CombinedAnalyzer) policyCoversFlow(policy *types.SecurityPolicy, flow *types.Flow) bool {
	// Simplified policy matching
	return policy.Source.CIDR == "any" || policy.Destination.CIDR == "any" ||
		policy.Source.CIDR == flow.Source || policy.Destination.CIDR == flow.Destination
}

func (c *CombinedAnalyzer) extractNetworkIP(cidr string) string {
	if cidr == "" {
		return ""
	}
	// Extract network portion (simplified)
	parts := strings.Split(cidr, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func (c *CombinedAnalyzer) mapRiskToCriticality(risk types.RiskLevel) types.CriticalityLevel {
	switch risk {
	case types.HighRisk:
		return types.CriticalAsset
	case types.MediumRisk:
		return types.HighAsset
	default:
		return types.MediumAsset
	}
}

func (c *CombinedAnalyzer) inferExposureFromZone(zone types.IEC62443Zone) types.ExposureLevel {
	switch zone {
	case types.DMZZone:
		return types.InternetExposed
	case types.EnterpriseZone:
		return types.CorporateExposed
	default:
		return types.OTOnly
	}
}

func (c *CombinedAnalyzer) calculatePriority(srcAsset, dstAsset *types.Asset) string {
	// Calculate priority based on asset criticality
	if srcAsset.Criticality == types.CriticalAsset || dstAsset.Criticality == types.CriticalAsset {
		return "High"
	}
	if srcAsset.Criticality == types.HighAsset || dstAsset.Criticality == types.HighAsset {
		return "Medium"
	}
	return "Low"
}

// Data structures for analysis results

type PolicyViolation struct {
	Flow        *types.Flow
	Description string
	Severity    string
}

type SegmentationOpportunity struct {
	Type        string
	Description string
	SourceZone  types.IEC62443Zone
	DestZone    types.IEC62443Zone
	Protocol    types.Protocol
	Priority    string
}

type SecurityPosture struct {
	TotalFlows      int
	PolicyCount     int
	ComplianceScore float64
	RiskLevel       types.RiskLevel
}
