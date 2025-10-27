package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"cipgram/pkg/types"
)

// Config holds all command-line configuration
// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Usage       string
	Flags       []Flag
}

// Flag represents a command-line flag
type Flag struct {
	Name        string
	Type        string
	Description string
	Default     interface{}
	Required    bool
}

// Config holds all command-line configuration
type Config struct {
	Command string // The command being executed

	// Input options
	PcapPath       string
	FirewallConfig string
	ConfigPath     string

	// Output options
	OutDOT      string
	OutJSON     string
	ProjectName string

	// Analysis options
	GenerateImages     bool
	SummaryMode        bool
	HideUnknown        bool
	MaxNodes           int
	ShowHostnames      bool
	EnableVendorLookup bool
	EnableDNSLookup    bool
	FastMode           bool
	DiagramType        string
	BothDiagrams       bool
}

// GetCommands returns all available commands
func GetCommands() []Command {
	return []Command{
		{
			Name:        "pcap",
			Description: "Analyze PCAP network traffic files",
			Usage:       "cipgram pcap <file.pcap> [options]",
			Flags: []Flag{
				{Name: "project", Type: "string", Description: "Project name for organized output (auto-generated if not specified)", Required: false},
				{Name: "config", Type: "string", Description: "Optional YAML with subnet→Purdue mappings", Required: false},
				{Name: "out", Type: "string", Description: "Output Graphviz DOT path (default: output/PROJECT/network_diagrams/diagram.dot)", Required: false},
				{Name: "json", Type: "string", Description: "Output JSON path (default: output/PROJECT/data/diagram.json)", Required: false},
				{Name: "images", Type: "bool", Description: "Generate PNG/SVG images from DOT file (requires Graphviz)", Default: true},
				{Name: "summary", Type: "bool", Description: "Generate simplified summary diagram (groups similar connections)", Default: false},
				{Name: "hide-unknown", Type: "bool", Description: "Hide devices with unknown Purdue levels", Default: false},
				{Name: "max-nodes", Type: "int", Description: "Maximum nodes to show (0 = unlimited, shows top communicators)", Default: 0},
				{Name: "hostnames", Type: "bool", Description: "Show device hostnames in diagrams (for display only)", Default: false},
				{Name: "vendor-lookup", Type: "bool", Description: "Enable MAC vendor lookup for device identification", Default: true},
				{Name: "dns-lookup", Type: "bool", Description: "Enable DNS hostname resolution (requires network access)", Default: false},
				{Name: "fast", Type: "bool", Description: "Fast mode: disable vendor and DNS lookups for maximum speed", Default: false},
				{Name: "diagram", Type: "string", Description: "Diagram type: 'purdue' for functional modeling, 'network' for segmentation planning, 'both' for both types", Default: "both"},
			},
		},
		{
			Name:        "config",
			Description: "Analyze firewall configuration files",
			Usage:       "cipgram config <file.xml|file.conf> [options]",
			Flags: []Flag{
				{Name: "project", Type: "string", Description: "Project name for organized output (auto-generated if not specified)", Required: false},
				{Name: "out", Type: "string", Description: "Output Graphviz DOT path (default: output/PROJECT/network_diagrams/diagram.dot)", Required: false},
				{Name: "json", Type: "string", Description: "Output JSON path (default: output/PROJECT/data/diagram.json)", Required: false},
				{Name: "images", Type: "bool", Description: "Generate PNG/SVG images from DOT file (requires Graphviz)", Default: true},
				{Name: "summary", Type: "bool", Description: "Generate simplified summary diagram (groups similar connections)", Default: false},
				{Name: "hide-unknown", Type: "bool", Description: "Hide devices with unknown Purdue levels", Default: false},
				{Name: "max-nodes", Type: "int", Description: "Maximum nodes to show (0 = unlimited, shows top communicators)", Default: 0},
				{Name: "diagram", Type: "string", Description: "Diagram type: 'purdue' for functional modeling, 'network' for segmentation planning, 'both' for both types", Default: "both"},
			},
		},
		{
			Name:        "combined",
			Description: "Analyze both PCAP and firewall configuration together",
			Usage:       "cipgram combined <file.pcap> <file.xml|file.conf> [options]",
			Flags: []Flag{
				{Name: "project", Type: "string", Description: "Project name for organized output (auto-generated if not specified)", Required: false},
				{Name: "purdue-config", Type: "string", Description: "Optional YAML with subnet→Purdue mappings", Required: false},
				{Name: "out", Type: "string", Description: "Output Graphviz DOT path (default: output/PROJECT/network_diagrams/diagram.dot)", Required: false},
				{Name: "json", Type: "string", Description: "Output JSON path (default: output/PROJECT/data/diagram.json)", Required: false},
				{Name: "images", Type: "bool", Description: "Generate PNG/SVG images from DOT file (requires Graphviz)", Default: true},
				{Name: "summary", Type: "bool", Description: "Generate simplified summary diagram (groups similar connections)", Default: false},
				{Name: "hide-unknown", Type: "bool", Description: "Hide devices with unknown Purdue levels", Default: false},
				{Name: "max-nodes", Type: "int", Description: "Maximum nodes to show (0 = unlimited, shows top communicators)", Default: 0},
				{Name: "hostnames", Type: "bool", Description: "Show device hostnames in diagrams (for display only)", Default: false},
				{Name: "vendor-lookup", Type: "bool", Description: "Enable MAC vendor lookup for device identification", Default: true},
				{Name: "dns-lookup", Type: "bool", Description: "Enable DNS hostname resolution (requires network access)", Default: false},
				{Name: "fast", Type: "bool", Description: "Fast mode: disable vendor and DNS lookups for maximum speed", Default: false},
				{Name: "diagram", Type: "string", Description: "Diagram type: 'purdue' for functional modeling, 'network' for segmentation planning, 'both' for both types", Default: "both"},
			},
		},
		{
			Name:        "install",
			Description: "Install cipgram to system PATH with tab completion",
			Usage:       "cipgram install [options]",
			Flags: []Flag{
				{Name: "path", Type: "string", Description: "Installation path (default: /usr/local/bin)", Default: "/usr/local/bin"},
				{Name: "completion", Type: "bool", Description: "Install bash/zsh tab completion", Default: true},
			},
		},
		{
			Name:        "uninstall",
			Description: "Remove cipgram from system PATH and clean up tab completion",
			Usage:       "cipgram uninstall [options]",
			Flags: []Flag{
				{Name: "path", Type: "string", Description: "Installation path to remove from (default: /usr/local/bin)", Default: "/usr/local/bin"},
			},
		},
		{
			Name:        "help",
			Description: "Show help information",
			Usage:       "cipgram help [command]",
			Flags:       []Flag{},
		},
		{
			Name:        "version",
			Description: "Show version information",
			Usage:       "cipgram version",
			Flags:       []Flag{},
		},
	}
}

// ParseArgs parses command-line arguments and returns configuration
func ParseArgs(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command provided. Use 'cipgram help' for usage information")
	}

	config := &Config{
		// Set defaults
		GenerateImages:     true,
		EnableVendorLookup: true,
		EnableDNSLookup:    false,
		DiagramType:        "both",
	}

	command := args[0]
	config.Command = command

	// Handle help command
	if command == "help" {
		if len(args) > 1 {
			return &Config{Command: "help", ProjectName: args[1]}, nil // Use ProjectName to store help target
		}
		return &Config{Command: "help"}, nil
	}

	// Handle version command
	if command == "version" {
		return &Config{Command: "version"}, nil
	}

	// Handle install command
	if command == "install" {
		return parseInstallCommand(args[1:], config)
	}

	// Handle uninstall command
	if command == "uninstall" {
		return parseUninstallCommand(args[1:], config)
	}

	// Handle pcap command
	if command == "pcap" {
		if len(args) < 2 {
			return nil, fmt.Errorf("pcap command requires a file argument. Usage: cipgram pcap <file.pcap>")
		}
		config.PcapPath = args[1]
		return parsePcapCommand(args[2:], config)
	}

	// Handle config command
	if command == "config" {
		if len(args) < 2 {
			return nil, fmt.Errorf("config command requires a file argument. Usage: cipgram config <file.xml|file.conf>")
		}
		config.FirewallConfig = args[1]
		return parseConfigCommand(args[2:], config)
	}

	// Handle combined command
	if command == "combined" {
		if len(args) < 3 {
			return nil, fmt.Errorf("combined command requires two file arguments. Usage: cipgram combined <file.pcap> <file.xml|file.conf>")
		}
		config.PcapPath = args[1]
		config.FirewallConfig = args[2]
		return parseCombinedCommand(args[3:], config)
	}

	return nil, fmt.Errorf("unknown command: %s. Use 'cipgram help' for available commands", command)
}

// parsePcapCommand parses arguments for the pcap command
func parsePcapCommand(args []string, config *Config) (*Config, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		cleanArg := strings.TrimLeft(arg, "-")

		switch {
		case cleanArg == "project" && i+1 < len(args):
			config.ProjectName = args[i+1]
			i++
		case cleanArg == "config" && i+1 < len(args):
			config.ConfigPath = args[i+1]
			i++
		case cleanArg == "out" && i+1 < len(args):
			config.OutDOT = args[i+1]
			i++
		case cleanArg == "json" && i+1 < len(args):
			config.OutJSON = args[i+1]
			i++
		case cleanArg == "diagram" && i+1 < len(args):
			config.DiagramType = args[i+1]
			i++
		case cleanArg == "max-nodes" && i+1 < len(args):
			if _, err := fmt.Sscanf(args[i+1], "%d", &config.MaxNodes); err != nil {
				return nil, fmt.Errorf("invalid value for max-nodes: %s", args[i+1])
			}
			i++
		case cleanArg == "images":
			config.GenerateImages = true
		case cleanArg == "no-images":
			config.GenerateImages = false
		case cleanArg == "summary":
			config.SummaryMode = true
		case cleanArg == "hide-unknown":
			config.HideUnknown = true
		case cleanArg == "hostnames":
			config.ShowHostnames = true
		case cleanArg == "vendor-lookup":
			config.EnableVendorLookup = true
		case cleanArg == "no-vendor-lookup":
			config.EnableVendorLookup = false
		case cleanArg == "dns-lookup":
			config.EnableDNSLookup = true
		case cleanArg == "fast":
			config.FastMode = true
		case cleanArg == "help":
			ShowHelp("pcap")
			return nil, fmt.Errorf("help displayed")
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// parseConfigCommand parses arguments for the config command
func parseConfigCommand(args []string, config *Config) (*Config, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		cleanArg := strings.TrimLeft(arg, "-")

		switch {
		case cleanArg == "project" && i+1 < len(args):
			config.ProjectName = args[i+1]
			i++
		case cleanArg == "out" && i+1 < len(args):
			config.OutDOT = args[i+1]
			i++
		case cleanArg == "json" && i+1 < len(args):
			config.OutJSON = args[i+1]
			i++
		case cleanArg == "diagram" && i+1 < len(args):
			config.DiagramType = args[i+1]
			i++
		case cleanArg == "max-nodes" && i+1 < len(args):
			if _, err := fmt.Sscanf(args[i+1], "%d", &config.MaxNodes); err != nil {
				return nil, fmt.Errorf("invalid value for max-nodes: %s", args[i+1])
			}
			i++
		case cleanArg == "images":
			config.GenerateImages = true
		case cleanArg == "no-images":
			config.GenerateImages = false
		case cleanArg == "summary":
			config.SummaryMode = true
		case cleanArg == "hide-unknown":
			config.HideUnknown = true
		case cleanArg == "help":
			ShowHelp("config")
			return nil, fmt.Errorf("help displayed")
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// parseCombinedCommand parses arguments for the combined command
func parseCombinedCommand(args []string, config *Config) (*Config, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		cleanArg := strings.TrimLeft(arg, "-")

		switch {
		case cleanArg == "project" && i+1 < len(args):
			config.ProjectName = args[i+1]
			i++
		case cleanArg == "purdue-config" && i+1 < len(args):
			config.ConfigPath = args[i+1]
			i++
		case cleanArg == "out" && i+1 < len(args):
			config.OutDOT = args[i+1]
			i++
		case cleanArg == "json" && i+1 < len(args):
			config.OutJSON = args[i+1]
			i++
		case cleanArg == "diagram" && i+1 < len(args):
			config.DiagramType = args[i+1]
			i++
		case cleanArg == "max-nodes" && i+1 < len(args):
			if _, err := fmt.Sscanf(args[i+1], "%d", &config.MaxNodes); err != nil {
				return nil, fmt.Errorf("invalid value for max-nodes: %s", args[i+1])
			}
			i++
		case cleanArg == "images":
			config.GenerateImages = true
		case cleanArg == "no-images":
			config.GenerateImages = false
		case cleanArg == "summary":
			config.SummaryMode = true
		case cleanArg == "hide-unknown":
			config.HideUnknown = true
		case cleanArg == "hostnames":
			config.ShowHostnames = true
		case cleanArg == "vendor-lookup":
			config.EnableVendorLookup = true
		case cleanArg == "no-vendor-lookup":
			config.EnableVendorLookup = false
		case cleanArg == "dns-lookup":
			config.EnableDNSLookup = true
		case cleanArg == "fast":
			config.FastMode = true
		case cleanArg == "help":
			ShowHelp("combined")
			return nil, fmt.Errorf("help displayed")
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// parseInstallCommand parses arguments for the install command
func parseInstallCommand(args []string, config *Config) (*Config, error) {
	installPath := "/usr/local/bin"
	enableCompletion := true

	for i := 0; i < len(args); i++ {
		arg := args[i]
		cleanArg := strings.TrimLeft(arg, "-")

		switch {
		case cleanArg == "path" && i+1 < len(args):
			installPath = args[i+1]
			i++
		case cleanArg == "completion":
			enableCompletion = true
		case cleanArg == "no-completion":
			enableCompletion = false
		case cleanArg == "help":
			ShowHelp("install")
			return nil, fmt.Errorf("help displayed")
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	// Store install options in config (reuse existing fields)
	config.OutDOT = installPath              // Reuse for install path
	config.GenerateImages = enableCompletion // Reuse for completion flag

	return config, nil
}

// parseUninstallCommand parses arguments for the uninstall command
func parseUninstallCommand(args []string, config *Config) (*Config, error) {
	installPath := "/usr/local/bin"

	for i := 0; i < len(args); i++ {
		arg := args[i]
		cleanArg := strings.TrimLeft(arg, "-")

		switch {
		case cleanArg == "path" && i+1 < len(args):
			installPath = args[i+1]
			i++
		case cleanArg == "help":
			ShowHelp("uninstall")
			return nil, fmt.Errorf("help displayed")
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	config.Command = "uninstall"
	config.OutDOT = installPath // Reuse for install path
	return config, nil
}

// ShowHelp displays help information
func ShowHelp(commandName string) {
	commands := GetCommands()

	if commandName == "" {
		// Show general help
		fmt.Println("CIPgram - OT Network Segmentation Analysis Tool")
		fmt.Println()
		fmt.Println("USAGE:")
		fmt.Println("  cipgram <command> [options]")
		fmt.Println()
		fmt.Println("COMMANDS:")
		for _, cmd := range commands {
			fmt.Printf("  %-12s %s\n", cmd.Name, cmd.Description)
		}
		fmt.Println()
		fmt.Println("Use 'cipgram help <command>' for detailed information about a command.")
		return
	}

	// Show command-specific help
	for _, cmd := range commands {
		if cmd.Name == commandName {
			fmt.Printf("CIPgram %s - %s\n\n", cmd.Name, cmd.Description)
			fmt.Printf("USAGE:\n  %s\n\n", cmd.Usage)

			if len(cmd.Flags) > 0 {
				fmt.Println("OPTIONS:")
				for _, flag := range cmd.Flags {
					flagName := flag.Name
					if flag.Type != "bool" {
						flagName += " <" + flag.Type + ">"
					}

					defaultStr := ""
					if flag.Default != nil {
						defaultStr = fmt.Sprintf(" (default: %v)", flag.Default)
					}

					fmt.Printf("  %-25s %s%s\n", flagName, flag.Description, defaultStr)
				}
				fmt.Println()
				fmt.Println("NOTE: Flags can be used with or without dashes (e.g., 'pcap file.pcap' or '-pcap file.pcap')")
			}

			if cmd.Name == "pcap" {
				fmt.Println("EXAMPLES:")
				fmt.Println("  cipgram pcap network.pcap")
				fmt.Println("  cipgram pcap traffic.pcap project MyProject")
				fmt.Println("  cipgram pcap capture.pcap fast no-images")
				fmt.Println("  cipgram pcap data.pcap config purdue_mappings.yaml")
			} else if cmd.Name == "config" {
				fmt.Println("EXAMPLES:")
				fmt.Println("  cipgram config firewall.xml")
				fmt.Println("  cipgram config opnsense.xml project SecurityAudit")
				fmt.Println("  cipgram config pfsense.conf no-images")
				fmt.Println("  cipgram config router.conf summary")
			} else if cmd.Name == "combined" {
				fmt.Println("EXAMPLES:")
				fmt.Println("  cipgram combined network.pcap firewall.xml")
				fmt.Println("  cipgram combined traffic.pcap config.xml project FullAnalysis")
				fmt.Println("  cipgram combined data.pcap router.conf fast")
			} else if cmd.Name == "install" {
				fmt.Println("EXAMPLES:")
				fmt.Println("  sudo cipgram install")
				fmt.Println("  sudo cipgram install path /opt/bin")
				fmt.Println("  sudo cipgram install no-completion")
			}
			return
		}
	}

	fmt.Printf("Unknown command: %s\n", commandName)
	fmt.Println("Use 'cipgram help' to see available commands.")
}

// ShowVersion displays version information
func ShowVersion() {
	fmt.Println("CIPgram v0.0.1")
	fmt.Println("OT Network Segmentation Analysis Tool")
	fmt.Println("Built for industrial network security training and analysis")
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Skip validation for special commands
	if c.Command == "help" || c.Command == "version" || c.Command == "install" {
		return nil
	}

	// For pcap command, must have pcap file
	if c.Command == "pcap" && c.PcapPath == "" {
		return fmt.Errorf("pcap command requires a PCAP file")
	}

	// For config command, must have firewall config
	if c.Command == "config" && c.FirewallConfig == "" {
		return fmt.Errorf("config command requires a firewall configuration file")
	}

	// For combined command, must have both files
	if c.Command == "combined" && (c.PcapPath == "" || c.FirewallConfig == "") {
		return fmt.Errorf("combined command requires both PCAP and firewall configuration files")
	}

	// Comprehensive input validation with security checks
	if c.PcapPath != "" {
		if err := validateFilePath(c.PcapPath, "PCAP"); err != nil {
			return err
		}
	}

	if c.FirewallConfig != "" {
		if err := validateFilePath(c.FirewallConfig, "config"); err != nil {
			return err
		}
	}

	if c.ConfigPath != "" {
		if err := validateFilePath(c.ConfigPath, "YAML"); err != nil {
			return err
		}
	}

	// Validate project name for filesystem safety
	if err := validateProjectName(c.ProjectName); err != nil {
		return err
	}

	// Validate output paths if specified
	if c.OutDOT != "" {
		if err := validateOutputPath(filepath.Dir(c.OutDOT)); err != nil {
			return fmt.Errorf("invalid DOT output path: %v", err)
		}
	}

	if c.OutJSON != "" {
		if err := validateOutputPath(filepath.Dir(c.OutJSON)); err != nil {
			return fmt.Errorf("invalid JSON output path: %v", err)
		}
	}

	return nil
}

// SetDefaults sets default values for unspecified options
func (c *Config) SetDefaults() {
	// Auto-generate project name if not specified
	if c.ProjectName == "" {
		if c.PcapPath != "" {
			base := filepath.Base(c.PcapPath)
			c.ProjectName = strings.TrimSuffix(base, filepath.Ext(base))
		} else if c.FirewallConfig != "" {
			base := filepath.Base(c.FirewallConfig)
			c.ProjectName = strings.TrimSuffix(base, filepath.Ext(base)) + "_firewall"
		} else {
			c.ProjectName = "analysis_" + fmt.Sprintf("%d", time.Now().Unix())
		}
	}

	// Handle both diagrams option
	if c.BothDiagrams || c.DiagramType == "both" || c.DiagramType == "" {
		c.DiagramType = "both"
	}

	// Fast mode overrides: disable lookups for maximum speed
	if c.FastMode {
		c.EnableVendorLookup = false
		c.EnableDNSLookup = false
	}
}

// GetAnalysisType determines what type of analysis to perform
func (c *Config) GetAnalysisType() types.AnalysisType {
	if c.PcapPath != "" && c.FirewallConfig != "" {
		return types.AnalysisTypeCombined
	} else if c.FirewallConfig != "" {
		return types.AnalysisTypeFirewall
	} else {
		return types.AnalysisTypePCAP
	}
}

// PrintUsageExamples prints helpful usage examples
func PrintUsageExamples() {
	fmt.Printf("Examples:\n")
	fmt.Printf("   PCAP analysis:     cipgram pcap traffic.pcap project demo\n")
	fmt.Printf("   Firewall analysis: cipgram config firewall.xml project security_audit\n")
	fmt.Printf("   Combined analysis: cipgram combined traffic.pcap firewall.xml project full_analysis\n")
}
