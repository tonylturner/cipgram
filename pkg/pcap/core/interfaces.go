package core

import (
	"cipgram/pkg/types"

	"github.com/google/gopacket"
)

// PacketProcessor defines the interface for processing individual packets
type PacketProcessor interface {
	ProcessPacket(packet gopacket.Packet, model *types.NetworkModel) error
}

// ProtocolDetector defines the interface for protocol detection
type ProtocolDetector interface {
	DetectProtocol(packet gopacket.Packet) *DetectionResult
	GetSupportedProtocols() []string
	GetDetectionStats() *DetectionStats
}

// DetectionResult contains the result of protocol detection
type DetectionResult struct {
	Protocol   string
	Confidence float32
	Method     DetectionMethod
	Details    map[string]interface{}
}

// DetectionMethod indicates how the protocol was detected
type DetectionMethod int

const (
	MethodUnknown   DetectionMethod = iota
	MethodPort                      // Port-based detection
	MethodDPI                       // Deep packet inspection
	MethodHeuristic                 // Heuristic analysis
	MethodSignature                 // Signature matching
)

// DetectionStats tracks detection performance
type DetectionStats struct {
	TotalPackets         int64
	SuccessfulDetections int64
	MethodBreakdown      map[DetectionMethod]int64
	ProtocolCounts       map[string]int64
}

// DPIAnalyzer defines the interface for deep packet inspection
type DPIAnalyzer interface {
	CanAnalyze(packet gopacket.Packet) bool
	Analyze(packet gopacket.Packet) *AnalysisResult
	GetProtocolName() string
	GetConfidenceThreshold() float32
}

// AnalysisResult contains detailed analysis results
type AnalysisResult struct {
	Protocol    string
	Subprotocol string
	Confidence  float32
	Details     map[string]interface{}
	Metadata    map[string]string
}

// DeviceFingerprinter defines the interface for device fingerprinting
type DeviceFingerprinter interface {
	FingerprintDevice(asset *types.Asset, packets []gopacket.Packet) *DeviceInfo
	GetDeviceTypes() []string
	UpdateSignatures(signatures map[string]*DeviceSignature) error
}

// DeviceInfo contains device fingerprinting results
type DeviceInfo struct {
	DeviceType   string
	Manufacturer string
	Model        string
	OS           string
	Version      string
	Confidence   float32
	Indicators   []string
}

// DeviceSignature defines a device detection signature
type DeviceSignature struct {
	Name         string
	DeviceType   string
	Manufacturer string
	Patterns     []SignaturePattern
	Confidence   float32
}

// SignaturePattern defines a pattern for device detection
type SignaturePattern struct {
	Type     PatternType
	Pattern  string
	Weight   float32
	Required bool
}

// PatternType indicates the type of signature pattern
type PatternType int

const (
	PatternMAC PatternType = iota
	PatternTTL
	PatternUserAgent
	PatternDHCPOption
	PatternProtocolUsage
	PatternPortPattern
	PatternPacketSize
)

// PerformanceOptimizer defines the interface for performance optimization
type PerformanceOptimizer interface {
	OptimizeDetection(packet gopacket.Packet) (cached bool, result *DetectionResult)
	CacheResult(packet gopacket.Packet, result *DetectionResult)
	GetCacheStats() *CacheStats
	ClearCache()
}

// CacheStats contains caching performance statistics
type CacheStats struct {
	HitRate     float32
	TotalHits   int64
	TotalMisses int64
	CacheSize   int
	MaxSize     int
}

// FlowAnalyzer defines the interface for flow analysis
type FlowAnalyzer interface {
	AnalyzeFlow(flow *types.Flow) *FlowAnalysis
	GetFlowPatterns() []FlowPattern
	DetectAnomalies(flows []*types.Flow) []FlowAnomaly
}

// FlowAnalysis contains flow analysis results
type FlowAnalysis struct {
	FlowType   string
	Pattern    string
	Confidence float32
	Metrics    map[string]float64
	Anomalies  []string
}

// FlowPattern defines a network flow pattern
type FlowPattern struct {
	Name        string
	Description string
	Indicators  []string
	Threshold   float32
}

// FlowAnomaly represents a detected flow anomaly
type FlowAnomaly struct {
	Type        string
	Description string
	Severity    AnomalySeverity
	FlowID      string
	Confidence  float32
}

// AnomalySeverity indicates the severity of an anomaly
type AnomalySeverity int

const (
	SeverityLow AnomalySeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ProtocolAnalyzer defines the interface for protocol analysis
type ProtocolAnalyzer interface {
	AnalyzeProtocols(model *types.NetworkModel) *ProtocolAnalysis
	GetProtocolStats() map[string]*ProtocolStats
	GenerateReport() *AnalysisReport
}

// ProtocolAnalysis contains comprehensive protocol analysis
type ProtocolAnalysis struct {
	TotalProtocols  int
	IdentifiedCount int
	UnknownCount    int
	CoveragePercent float32
	TopProtocols    []ProtocolStat
	DetectionGaps   []DetectionGap
}

// ProtocolStats contains statistics for a specific protocol
type ProtocolStats struct {
	Name        string
	FlowCount   int
	PacketCount int64
	ByteCount   int64
	FirstSeen   string
	LastSeen    string
	Assets      []string
	Ports       []int
}

// ProtocolStat is a simplified protocol statistic
type ProtocolStat struct {
	Name  string
	Count int
	Bytes int64
}

// DetectionGap represents a gap in protocol detection
type DetectionGap struct {
	Protocol   string
	Port       int
	FlowCount  int
	Suggestion string
	Priority   GapPriority
}

// GapPriority indicates the priority of addressing a detection gap
type GapPriority int

const (
	PriorityLow GapPriority = iota
	PriorityMedium
	PriorityHigh
	PriorityCritical
)

// AnalysisReport contains a comprehensive analysis report
type AnalysisReport struct {
	Summary          string
	ProtocolAnalysis *ProtocolAnalysis
	DeviceAnalysis   *DeviceAnalysis
	FlowAnalysis     *FlowAnalysisReport
	Recommendations  []string
	Timestamp        string
}

// DeviceAnalysis contains device analysis results
type DeviceAnalysis struct {
	TotalDevices    int
	IdentifiedCount int
	DeviceTypes     map[string]int
	Manufacturers   map[string]int
	OSDistribution  map[string]int
}

// FlowAnalysisReport contains flow analysis results
type FlowAnalysisReport struct {
	TotalFlows     int
	FlowTypes      map[string]int
	AnomalyCount   int
	PatternMatches []string
}

// ConfigManager defines the interface for configuration management
type ConfigManager interface {
	GetConfig() *Config
	UpdateConfig(config *Config) error
	ValidateConfig(config *Config) error
	GetDefaultConfig() *Config
}

// Config contains the main configuration
type Config struct {
	Detection      *DetectionConfig      `json:"detection"`
	DPI            *DPIConfig            `json:"dpi"`
	Fingerprinting *FingerprintingConfig `json:"fingerprinting"`
	Performance    *PerformanceConfig    `json:"performance"`
	Analysis       *AnalysisConfig       `json:"analysis"`
}

// DetectionConfig contains detection-specific configuration
type DetectionConfig struct {
	EnablePortBased     bool     `json:"enable_port_based"`
	EnableDPI           bool     `json:"enable_dpi"`
	EnableHeuristic     bool     `json:"enable_heuristic"`
	ConfidenceThreshold float32  `json:"confidence_threshold"`
	EnabledProtocols    []string `json:"enabled_protocols"`
}

// DPIConfig contains DPI-specific configuration
type DPIConfig struct {
	EnableHTTP       bool `json:"enable_http"`
	EnableTLS        bool `json:"enable_tls"`
	EnableDNS        bool `json:"enable_dns"`
	EnableIndustrial bool `json:"enable_industrial"`
	MaxPayloadSize   int  `json:"max_payload_size"`
	Timeout          int  `json:"timeout_ms"`
}

// FingerprintingConfig contains fingerprinting configuration
type FingerprintingConfig struct {
	EnableOSDetection     bool    `json:"enable_os_detection"`
	EnableDeviceDetection bool    `json:"enable_device_detection"`
	ConfidenceThreshold   float32 `json:"confidence_threshold"`
	MaxSignatures         int     `json:"max_signatures"`
}

// PerformanceConfig contains performance optimization configuration
type PerformanceConfig struct {
	EnableCaching   bool `json:"enable_caching"`
	CacheSize       int  `json:"cache_size"`
	EnableProfiling bool `json:"enable_profiling"`
	MaxMemoryMB     int  `json:"max_memory_mb"`
}

// AnalysisConfig contains analysis configuration
type AnalysisConfig struct {
	EnableFlowAnalysis     bool   `json:"enable_flow_analysis"`
	EnableAnomalyDetection bool   `json:"enable_anomaly_detection"`
	EnableReporting        bool   `json:"enable_reporting"`
	ReportFormat           string `json:"report_format"`
}
