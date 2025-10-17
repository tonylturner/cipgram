package cli

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cipgram/internal/output"
	"cipgram/internal/writers"
	"cipgram/pkg/firewall"
	"cipgram/pkg/types"
)

// App represents the main CLI application
type App struct {
	config *Config
}

// NewApp creates a new CLI application instance
func NewApp() (*App, error) {
	config, err := ParseArgs(os.Args[1:])
	if err != nil {
		return nil, err
	}

	return &App{
		config: config,
	}, nil
}

// Run executes the main application logic
func (a *App) Run() error {
	// Handle special commands first
	switch a.config.Command {
	case "help":
		ShowHelp(a.config.ProjectName) // ProjectName stores the help target command
		return nil
	case "version":
		ShowVersion()
		return nil
	case "install":
		return a.runInstall()
	case "uninstall":
		return a.runUninstall()
	case "pcap":
		return a.runPCAPAnalysis()
	case "config":
		return a.runConfigAnalysis()
	case "combined":
		return a.runCombinedAnalysis()
	default:
		return fmt.Errorf("unknown command: %s", a.config.Command)
	}
}

// runInstall installs cipgram to system PATH
func (a *App) runInstall() error {
	installPath := a.config.OutDOT              // Reused field for install path
	enableCompletion := a.config.GenerateImages // Reused field for completion

	fmt.Printf("Installing CIPgram to %s...\n", installPath)

	// Check if sudo is needed and handle elevation
	if needsSudo, err := a.handleSudoExecution(installPath, enableCompletion); err != nil {
		return err
	} else if needsSudo {
		return nil // Execution was handed off to sudo
	}

	// Install the binary
	if err := a.installBinary(installPath); err != nil {
		return err
	}

	// Setup tab completion if requested
	if enableCompletion {
		a.setupTabCompletion()
	}

	// Verify installation
	a.verifyInstallation()

	fmt.Printf("Installation complete.\n")
	return nil
}

// runUninstall removes cipgram from system PATH and cleans up tab completion
func (a *App) runUninstall() error {
	installPath := a.config.OutDOT // Reused field for install path

	fmt.Printf("Removing CIPgram from %s...\n", installPath)

	// Target installation path
	targetPath := filepath.Join(installPath, "cipgram")

	// Check if binary exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		fmt.Printf("CIPgram binary not found at %s\n", targetPath)
	} else {
		// Check if we need sudo permissions to remove
		if err := checkWritePermission(installPath); err != nil {
			// Check if we're already running as root/sudo
			if os.Geteuid() == 0 {
				return fmt.Errorf("running as root but still no write permission to %s", installPath)
			}

			fmt.Printf("Elevated permissions required. Re-running with sudo...\n")

			// Get current executable path
			currentExe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to get current executable path: %v", err)
			}

			// Build the sudo command
			args := []string{currentExe, "uninstall"}
			if installPath != "/usr/local/bin" {
				args = append(args, "path", installPath)
			}

			// Execute with sudo
			cmd := exec.Command("sudo", args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			return cmd.Run()
		}

		// Remove the binary
		if err := os.Remove(targetPath); err != nil {
			return fmt.Errorf("failed to remove binary: %v", err)
		}
		fmt.Printf("Binary removed successfully.\n")
	}

	// Remove tab completion
	if err := a.removeTabCompletion(); err != nil {
		fmt.Printf("Warning: Tab completion removal failed: %v\n", err)
	} else {
		fmt.Printf("Tab completion removed.\n")
		fmt.Printf("To fully remove tab completion, run: source ~/.zshrc\n")
	}

	fmt.Printf("Uninstall complete.\n")
	return nil
}

// runPCAPAnalysis executes PCAP-only analysis
func (a *App) runPCAPAnalysis() error {
	// Create output manager and paths
	outputManager := output.NewOutputManager(a.config.ProjectName)
	paths, err := outputManager.CreateProjectStructure()
	if err != nil {
		return fmt.Errorf("failed to create output paths: %v", err)
	}

	fmt.Printf("🎯 CIPgram PCAP Analysis - Project: %s\n", a.config.ProjectName)
	fmt.Printf("📁 Output directory: %s\n", paths.ProjectRoot)

	// Check Graphviz installation if images are requested
	if a.config.GenerateImages {
		checkGraphvizInstallation()
	}

	return a.runPCAPAnalysisWithPaths(paths)
}

// runConfigAnalysis executes firewall config-only analysis
func (a *App) runConfigAnalysis() error {
	// Create output manager and paths
	outputManager := output.NewOutputManager(a.config.ProjectName)
	paths, err := outputManager.CreateProjectStructure()
	if err != nil {
		return fmt.Errorf("failed to create output paths: %v", err)
	}

	fmt.Printf("🎯 CIPgram Config Analysis - Project: %s\n", a.config.ProjectName)
	fmt.Printf("📁 Output directory: %s\n", paths.ProjectRoot)

	// Check Graphviz installation if images are requested
	if a.config.GenerateImages {
		checkGraphvizInstallation()
	}

	return a.runFirewallAnalysis(paths)
}

// runCombinedAnalysis executes combined PCAP and firewall analysis
func (a *App) runCombinedAnalysis() error {
	// Create output manager and paths
	outputManager := output.NewOutputManager(a.config.ProjectName)
	paths, err := outputManager.CreateProjectStructure()
	if err != nil {
		return fmt.Errorf("failed to create output paths: %v", err)
	}

	fmt.Printf("🎯 CIPgram Combined Analysis - Project: %s\n", a.config.ProjectName)
	fmt.Printf("📁 Output directory: %s\n", paths.ProjectRoot)
	fmt.Printf("📊 PCAP file: %s\n", a.config.PcapPath)
	fmt.Printf("🔧 Config file: %s\n", a.config.FirewallConfig)

	// Check Graphviz installation if images are requested
	if a.config.GenerateImages {
		checkGraphvizInstallation()
	}

	// Combined analysis implementation plan:
	// 1. Parse PCAP file to discover actual network traffic and devices
	// 2. Parse firewall config to understand intended security policies
	// 3. Cross-correlate to identify:
	//    - Policy violations (traffic not covered by rules)
	//    - Unused/redundant firewall rules
	//    - Security gaps and recommendations
	//    - Asset validation against firewall configuration
	// 4. Generate enhanced reports with compliance scoring

	fmt.Printf("⚠️  Combined analysis feature under development!\n")
	fmt.Printf("💡 Use separate 'pcap' and 'config' commands for now\n")
	fmt.Printf("🔬 This feature will cross-correlate traffic patterns with firewall policies\n")

	return nil
}

// runFirewallAnalysis performs firewall-only analysis
func (a *App) runFirewallAnalysis(paths *output.OutputPaths) error {
	log.Printf("🔧 Firewall Configuration Analysis")
	log.Printf("📊 Config file: %s", a.config.FirewallConfig)

	// Create parser factory and detect/parse firewall config
	factory := &firewall.ParserFactory{}

	// For now, assume OPNsense - TODO: implement auto-detection
	parser, err := factory.NewParser(a.config.FirewallConfig, types.InputTypeOPNsense)
	if err != nil {
		return fmt.Errorf("failed to create firewall parser: %v", err)
	}

	// Validate configuration
	if err := parser.Validate(); err != nil {
		return fmt.Errorf("invalid firewall configuration: %v", err)
	}

	log.Printf("🔧 Parsing firewall configuration...")

	// Parse the configuration
	model, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse firewall config: %v", err)
	}

	log.Printf("✅ Parsed configuration: %d networks, %d policies", len(model.Networks), len(model.Policies))

	// Create firewall diagram generator
	generator := writers.NewFirewallDiagramGenerator(model)

	// Generate network topology diagram
	topologyPath := filepath.Join(paths.FirewallAnalysis, "network_topology.dot")
	log.Printf("🌐 Generating network topology diagram...")
	if err := generator.GenerateNetworkTopologyDiagram(topologyPath); err != nil {
		log.Printf("Warning: Failed to generate topology diagram: %v", err)
	} else {
		log.Printf("✅ Network topology: %s", topologyPath)

		// Generate image if requested
		if a.config.GenerateImages {
			if err := a.generateImageEmbedded(topologyPath); err != nil {
				log.Printf("Image generation warning: %v", err)
			}
		}
	}

	// Generate firewall rules summary
	rulesPath := filepath.Join(paths.FirewallAnalysis, "firewall_rules.txt")
	log.Printf("📋 Generating firewall rules summary...")
	if err := generator.GenerateFirewallRulesSummary(rulesPath); err != nil {
		log.Printf("Warning: Failed to generate rules summary: %v", err)
	} else {
		log.Printf("✅ Firewall rules: %s", rulesPath)
	}

	// Generate IEC 62443 zone diagram
	zonePath := filepath.Join(paths.IEC62443Diagrams, "iec62443_zones.dot")
	log.Printf("🏭 Generating IEC 62443 zone diagram...")
	if err := generator.GenerateIEC62443ZoneDiagram(zonePath); err != nil {
		log.Printf("Warning: Failed to generate zone diagram: %v", err)
	} else {
		log.Printf("✅ IEC 62443 zones: %s", zonePath)

		// Generate image if requested
		if a.config.GenerateImages {
			if err := a.generateImageEmbedded(zonePath); err != nil {
				log.Printf("Image generation warning: %v", err)
			}
		}
	}

	// Display analysis summary
	a.displayFirewallSummary(model)

	return nil
}

// runPCAPAnalysis performs PCAP-only analysis
// runPCAPAnalysisWithPaths performs PCAP-only analysis with provided paths
func (a *App) runPCAPAnalysisWithPaths(paths *output.OutputPaths) error {
	// Configure analysis settings and display info
	a.configurePCAPAnalysis(paths)

	// Parse the PCAP file
	model, err := a.parsePCAPFile()
	if err != nil {
		return err
	}

	// Generate all PCAP diagrams
	if err := a.generatePCAPDiagrams(model, paths); err != nil {
		return err
	}

	// Export results and cleanup
	a.exportPCAPResults(model, paths)

	return nil
}

// displayFirewallSummary displays a summary of the firewall analysis
func (a *App) displayFirewallSummary(model *types.NetworkModel) {
	log.Printf("\n🎓 Firewall Analysis Summary:")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(model.Networks) > 0 {
		log.Printf("📊 Network Segments:")
		for _, network := range model.Networks {
			log.Printf("  • %s (%s) → %s zone, %s risk",
				network.ID, network.CIDR, network.Zone, network.Risk)
		}
	}

	if len(model.Policies) > 0 {
		log.Printf("🔒 Security Policies:")
		for i, policy := range model.Policies {
			if i < 5 { // Show first 5 policies
				log.Printf("  • %s → %s (%s)",
					policy.Source.CIDR, policy.Destination.CIDR, policy.Action)
			}
		}
		if len(model.Policies) > 5 {
			log.Printf("  ... and %d more policies", len(model.Policies)-5)
		}
	}

	log.Printf("\n🎯 Analysis complete! Check the output directory for detailed results.")
}

// displayPCAPSummary displays a summary of the PCAP analysis
func (a *App) displayPCAPSummary(model *types.NetworkModel) {
	log.Printf("\n🎓 PCAP Analysis Summary:")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(model.Assets) > 0 {
		log.Printf("📊 Discovered Assets:")
		vendorCount := 0
		hostnameCount := 0

		for _, asset := range model.Assets {
			// Show first 5 assets with details
			if vendorCount < 5 {
				vendor := asset.Vendor
				if vendor == "" {
					vendor = "Unknown"
				}
				hostname := asset.Hostname
				if hostname == "" {
					hostname = "No hostname"
				}

				log.Printf("  • %s [%s] - %s (%s)",
					asset.IP, asset.MAC[:8]+"...", vendor, hostname)
			}

			if asset.Vendor != "" {
				vendorCount++
			}
			if asset.Hostname != "" {
				hostnameCount++
			}
		}

		if len(model.Assets) > 5 {
			log.Printf("  ... and %d more assets", len(model.Assets)-5)
		}

		log.Printf("📈 Statistics:")
		log.Printf("  • Total assets: %d", len(model.Assets))
		log.Printf("  • Vendor identified: %d", vendorCount)
		log.Printf("  • Hostnames resolved: %d", hostnameCount)
	}

	if len(model.Flows) > 0 {
		log.Printf("🔄 Communication Flows:")
		protocolStats := make(map[types.Protocol]int)

		for _, flow := range model.Flows {
			protocolStats[flow.Protocol]++
		}

		log.Printf("  • Total flows: %d", len(model.Flows))
		for proto, count := range protocolStats {
			if count > 0 {
				log.Printf("  • %s: %d flows", proto, count)
			}
		}
	}

	log.Printf("\n🎯 Analysis complete! Check the output directory for detailed results.")
}

// checkWritePermission checks if we can write to the target directory
func checkWritePermission(dir string) error {
	// Try to create a test file
	testFile := filepath.Join(dir, ".cipgram_install_test")
	file, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("no write permission to %s", dir)
	}
	file.Close()
	os.Remove(testFile)
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy file contents
	if _, err := destFile.ReadFrom(sourceFile); err != nil {
		return err
	}

	return nil
}

// installTabCompletion installs bash/zsh tab completion
func (a *App) installTabCompletion() error {
	// Get the original user's shell (preserve through sudo)
	userShell := os.Getenv("SHELL")
	var homeDir string

	if userShell == "" || userShell == "/bin/sh" {
		// When running with sudo, try to get the original user's shell
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			// Try macOS dscl first (more reliable on macOS)
			cmd := exec.Command("dscl", ".", "-read", "/Users/"+sudoUser, "UserShell")
			if output, err := cmd.Output(); err == nil {
				// Parse "UserShell: /bin/zsh" format
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "UserShell: ") {
						userShell = strings.TrimPrefix(line, "UserShell: ")
						break
					}
				}
			}

			// Fallback to getent if dscl didn't work
			if userShell == "" || userShell == "/bin/sh" {
				cmd := exec.Command("getent", "passwd", sudoUser)
				if output, err := cmd.Output(); err == nil {
					fields := strings.Split(strings.TrimSpace(string(output)), ":")
					if len(fields) >= 7 {
						userShell = fields[6]
					}
				}
			}

			// Get home directory using dscl
			if homeDir == "" {
				cmd := exec.Command("dscl", ".", "-read", "/Users/"+sudoUser, "NFSHomeDirectory")
				if output, err := cmd.Output(); err == nil {
					// Parse "NFSHomeDirectory: /Users/username" format
					lines := strings.Split(strings.TrimSpace(string(output)), "\n")
					for _, line := range lines {
						if strings.HasPrefix(line, "NFSHomeDirectory: ") {
							homeDir = strings.TrimPrefix(line, "NFSHomeDirectory: ")
							break
						}
					}
				}
			}

			// Fallback home directory
			if homeDir == "" {
				homeDir = "/Users/" + sudoUser
			}
		}
		// Fallback to bash if we still can't determine
		if userShell == "" || userShell == "/bin/sh" {
			userShell = "/bin/bash"
		}
	}

	// Get home directory if not already set
	if homeDir == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			// Fallback for macOS
			homeDir = "/Users/" + sudoUser
		} else {
			// Normal execution
			var err error
			homeDir, err = os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %v", err)
			}
		}
	}

	// Generate completion script
	var completionScript string

	if strings.Contains(userShell, "bash") {
		// Install bash completion
		bashrcPath := filepath.Join(homeDir, ".bashrc")
		completionScript = a.generateCompletionScriptForShell("bash")
		return a.addCompletionToFile(bashrcPath, completionScript)
	} else if strings.Contains(userShell, "zsh") {
		// Install zsh completion
		zshrcPath := filepath.Join(homeDir, ".zshrc")
		completionScript = a.generateCompletionScriptForShell("zsh")
		return a.addCompletionToFile(zshrcPath, completionScript)
	}

	return fmt.Errorf("unsupported shell: %s", userShell)
}

// removeTabCompletion removes tab completion from shell config files
func (a *App) removeTabCompletion() error {
	// Get the original user's shell (preserve through sudo)
	userShell := os.Getenv("SHELL")
	if userShell == "" || userShell == "/bin/sh" {
		// When running with sudo, try to get the original user's shell
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			// Try to get the user's shell from /etc/passwd
			cmd := exec.Command("getent", "passwd", sudoUser)
			if output, err := cmd.Output(); err == nil {
				fields := strings.Split(strings.TrimSpace(string(output)), ":")
				if len(fields) >= 7 {
					userShell = fields[6]
				}
			}
		}
		// Fallback to bash if we still can't determine
		if userShell == "" || userShell == "/bin/sh" {
			userShell = "/bin/bash"
		}
	}

	// Determine config file based on shell
	var homeDir string

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// Running with sudo, get the original user's home directory
		cmd := exec.Command("getent", "passwd", sudoUser)
		if output, err := cmd.Output(); err == nil {
			fields := strings.Split(strings.TrimSpace(string(output)), ":")
			if len(fields) >= 6 {
				homeDir = fields[5]
			}
		}
	} else {
		// Normal execution
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %v", err)
		}
	}

	var configFiles []string
	if strings.Contains(userShell, "zsh") {
		configFiles = append(configFiles, filepath.Join(homeDir, ".zshrc"))
	} else {
		configFiles = append(configFiles, filepath.Join(homeDir, ".bashrc"))
	}

	// Remove completion from all config files
	for _, configFile := range configFiles {
		if err := a.removeCompletionFromFile(configFile); err != nil {
			// Don't fail if file doesn't exist
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove completion from %s: %v", configFile, err)
			}
		}
	}

	return nil
}

// removeCompletionFromFile removes completion script from shell config file
func (a *App) removeCompletionFromFile(configFile string) error {
	marker := "# CIPgram"

	// Read existing file content
	content, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	existingContent := string(content)

	// Check if completion is installed
	if !strings.Contains(existingContent, marker) {
		// No completion found, nothing to remove
		return nil
	}

	// Remove completion block
	lines := strings.Split(existingContent, "\n")
	var newLines []string
	skipBlock := false

	for _, line := range lines {
		if strings.Contains(line, marker) {
			skipBlock = true
			continue
		}
		if skipBlock && (strings.Contains(line, "compdef _cipgram cipgram") || strings.Contains(line, "complete -F _cipgram cipgram")) {
			skipBlock = false
			continue
		}
		if !skipBlock {
			newLines = append(newLines, line)
		}
	}

	// Write back the cleaned content
	newContent := strings.Join(newLines, "\n")
	return os.WriteFile(configFile, []byte(newContent), 0644)
}

// generateCompletionScriptForShell generates a completion script for a specific shell
func (a *App) generateCompletionScriptForShell(shell string) string {
	if shell == "zsh" {
		// Zsh completion script
		return `
# CIPgram zsh completion
_cipgram() {
    local context curcontext="$curcontext" state line
    typeset -A opt_args

    _arguments -C \
        '1: :->command' \
        '2: :->arg1' \
        '3: :->arg2' \
        '*: :->args' && return 0

    case $state in
        command)
            _values 'cipgram commands' \
                'pcap[Analyze PCAP network traffic files]' \
                'config[Analyze firewall configuration files]' \
                'combined[Analyze both PCAP and firewall configuration together]' \
                'install[Install cipgram to system PATH with tab completion]' \
                'uninstall[Remove cipgram from system PATH and clean up tab completion]' \
                'help[Show help information]' \
                'version[Show version information]'
            ;;
        arg1)
            case $words[2] in
                pcap)
                    _files -g "*.pcap *.pcapng"
                    ;;
                config)
                    _files -g "*.xml *.conf"
                    ;;
                combined)
                    _files -g "*.pcap *.pcapng"
                    ;;
                help)
                    _values 'help topics' pcap config combined install uninstall help version
                    ;;
                install)
                    _values 'install options' 'path[Installation path]' 'no-completion[Skip tab completion]'
                    ;;
            esac
            ;;
        arg2)
            case $words[2] in
                combined)
                    _files -g "*.xml *.conf"
                    ;;
            esac
            ;;
    esac
}

compdef _cipgram cipgram
`
	} else {
		// Bash completion script
		return `
# CIPgram bash completion
_cipgram() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="pcap config combined install uninstall help version"
    
    case ${COMP_CWORD} in
        1)
            COMPREPLY=($(compgen -W "${commands}" -- ${cur}))
            ;;
        2)
            case ${prev} in
                pcap|config)
                    COMPREPLY=($(compgen -f -X "!*.@(pcap|pcapng|xml|conf)" -- ${cur}))
                    ;;
                combined)
                    COMPREPLY=($(compgen -f -X "!*.@(pcap|pcapng)" -- ${cur}))
                    ;;
                help)
                    COMPREPLY=($(compgen -W "${commands}" -- ${cur}))
                    ;;
            esac
            ;;
        3)
            case ${COMP_WORDS[1]} in
                combined)
                    COMPREPLY=($(compgen -f -X "!*.@(xml|conf)" -- ${cur}))
                    ;;
            esac
            ;;
    esac
}

complete -F _cipgram cipgram
`
	}
}

// addCompletionToFile adds completion script to shell config file
func (a *App) addCompletionToFile(configFile, script string) error {
	marker := "# CIPgram"

	// Read existing file content
	var existingContent string
	if content, err := os.ReadFile(configFile); err == nil {
		existingContent = string(content)

		// Check if completion is already installed and remove old version
		if strings.Contains(existingContent, marker) {
			fmt.Printf("Updating existing tab completion in %s\n", filepath.Base(configFile))

			// Remove old completion block
			lines := strings.Split(existingContent, "\n")
			var newLines []string
			skipBlock := false

			for _, line := range lines {
				if strings.Contains(line, marker) {
					skipBlock = true
					continue
				}
				if skipBlock && (strings.Contains(line, "compdef _cipgram cipgram") || strings.Contains(line, "complete -F _cipgram cipgram")) {
					skipBlock = false
					continue
				}
				if !skipBlock {
					newLines = append(newLines, line)
				}
			}
			existingContent = strings.Join(newLines, "\n")
		}
	}

	// Write updated content with new completion
	file, err := os.Create(configFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write existing content (without old completion)
	if existingContent != "" {
		if _, err := file.WriteString(existingContent); err != nil {
			return err
		}
	}

	// Add new completion script
	if _, err := file.WriteString("\n" + script + "\n"); err != nil {
		return err
	}

	fmt.Printf("Tab completion added to %s\n", filepath.Base(configFile))
	return nil
}

// convertNetworkModelToGraph converts a NetworkModel (from PCAP) to a Graph for diagram generation
func (a *App) convertNetworkModelToGraph(model *types.NetworkModel) *types.Graph {
	graph := &types.Graph{
		Hosts: make(map[string]*types.Host),
		Edges: make(map[types.FlowKey]*types.Edge),
	}

	// Convert Assets to Hosts
	for _, asset := range model.Assets {
		host := &types.Host{
			IP:                    asset.IP,
			MAC:                   asset.MAC,
			Hostname:              asset.Hostname,
			DeviceName:            asset.DeviceName,
			Vendor:                asset.Vendor,
			InferredLevel:         asset.PurdueLevel,
			Roles:                 asset.Roles,
			PortsSeen:             make(map[uint16]bool),
			PeersByProtoInitiated: make(map[types.Protocol]map[string]bool),
			PeersByProtoReceived:  make(map[types.Protocol]map[string]bool),
			InitiatedCounts:       make(map[types.Protocol]int),
			ReceivedCounts:        make(map[types.Protocol]int),
		}

		// Initialize protocol maps
		for _, proto := range asset.Protocols {
			host.PeersByProtoInitiated[proto] = make(map[string]bool)
			host.PeersByProtoReceived[proto] = make(map[string]bool)
		}

		graph.Hosts[asset.ID] = host
	}

	// Convert Flows to Edges
	for flowKey, flow := range model.Flows {
		edge := &types.Edge{
			Src:       flow.Source,
			Dst:       flow.Destination,
			Protocol:  flow.Protocol,
			Packets:   int(flow.Packets),
			Bytes:     flow.Bytes,
			FirstSeen: flow.FirstSeen,
			LastSeen:  flow.LastSeen,
		}

		// Infer Purdue level from source host if available
		if srcHost, exists := graph.Hosts[flow.Source]; exists {
			edge.InferredLevel = srcHost.InferredLevel
		}

		graph.Edges[flowKey] = edge
	}

	return graph
}

// generatePurdueModelDiagrams creates traditional Purdue model with horizontal bars per level
func (a *App) generatePurdueModelDiagrams(graph *types.Graph, basePath string, model *types.NetworkModel) error {
	// Generate DOT file with traditional Purdue layout
	dotPath := basePath + ".dot"
	if err := a.generateTraditionalPurdueDOT(graph, dotPath); err != nil {
		return fmt.Errorf("failed to generate Purdue DOT: %v", err)
	}

	// Generate JSON file with graph data
	jsonPath := basePath + ".json"
	if err := a.generateGraphJSON(graph, model, jsonPath); err != nil {
		return fmt.Errorf("failed to generate Purdue JSON: %v", err)
	}

	// Generate images if requested
	if a.config.GenerateImages {
		// Generate SVG
		svgPath := basePath + ".svg"
		if err := a.generateSVGFromDOT(dotPath, svgPath); err != nil {
			log.Printf("SVG generation warning: %v", err)
		}

		// Generate PNG from SVG
		pngPath := basePath + ".png"
		if err := a.generatePNGFromSVG(svgPath, pngPath); err != nil {
			log.Printf("PNG generation warning: %v", err)
		}
	}

	return nil
}

// generateNetworkTopologyDiagrams creates traditional network diagram with router/firewall center
func (a *App) generateNetworkTopologyDiagrams(graph *types.Graph, basePath string, model *types.NetworkModel) error {
	// Generate DOT file with traditional network topology layout
	dotPath := basePath + ".dot"
	if err := a.generateTraditionalNetworkDOT(graph, dotPath, model); err != nil {
		return fmt.Errorf("failed to generate network DOT: %v", err)
	}

	// Generate JSON file with graph data
	jsonPath := basePath + ".json"
	if err := a.generateGraphJSON(graph, model, jsonPath); err != nil {
		return fmt.Errorf("failed to generate network JSON: %v", err)
	}

	// Generate images if requested
	if a.config.GenerateImages {
		// Generate SVG
		svgPath := basePath + ".svg"
		if err := a.generateSVGFromDOT(dotPath, svgPath); err != nil {
			log.Printf("SVG generation warning: %v", err)
		}

		// Generate PNG from SVG
		pngPath := basePath + ".png"
		if err := a.generatePNGFromSVG(svgPath, pngPath); err != nil {
			log.Printf("PNG generation warning: %v", err)
		}
	}

	return nil
}
