package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cipgram/internal/output"
	"cipgram/pkg/pcap"
	"cipgram/pkg/types"
	"cipgram/pkg/vendor"
)

// handleSudoExecution checks if sudo is needed and re-executes with elevation if required
func (a *App) handleSudoExecution(installPath string, enableCompletion bool) (bool, error) {
	if err := checkWritePermission(installPath); err != nil {
		// Check if we're already running as root/sudo
		if os.Geteuid() == 0 {
			return false, fmt.Errorf("running as root but still no write permission to %s", installPath)
		}

		fmt.Printf("Elevated permissions required. Re-running with sudo...\n")

		// Get current executable path
		currentExe, err := os.Executable()
		if err != nil {
			return false, fmt.Errorf("failed to get current executable path: %v", err)
		}

		// Build the sudo command with all current arguments
		args := []string{currentExe, "install"}
		if installPath != "/usr/local/bin" {
			args = append(args, "path", installPath)
		}
		if !enableCompletion {
			args = append(args, "no-completion")
		}

		// Execute with sudo
		cmd := exec.Command("sudo", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		err = cmd.Run()
		return true, err // Return true to indicate sudo was used
	}
	return false, nil // No sudo needed
}

// installBinary copies and sets up the cipgram binary
func (a *App) installBinary(installPath string) error {
	// Get current executable path
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %v", err)
	}

	// Target installation path
	targetPath := filepath.Join(installPath, "cipgram")

	// Create install directory if it doesn't exist
	if err := os.MkdirAll(installPath, 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %v", err)
	}

	// Copy the binary
	if err := copyFile(currentExe, targetPath); err != nil {
		return fmt.Errorf("failed to copy binary: %v", err)
	}

	// Make it executable
	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %v", err)
	}

	fmt.Printf("Binary installed successfully.\n")
	return nil
}

// setupTabCompletion installs tab completion and provides user instructions
func (a *App) setupTabCompletion() {
	if err := a.installTabCompletion(); err != nil {
		fmt.Printf("Warning: Tab completion installation failed: %v\n", err)
		return
	}

	fmt.Printf("Tab completion installed.\n")

	// Detect user's shell and provide appropriate instructions
	userShell := a.detectUserShell()
	if strings.Contains(userShell, "zsh") {
		fmt.Printf("To activate tab completion, run: source ~/.zshrc\n")
	} else if strings.Contains(userShell, "bash") {
		fmt.Printf("To activate tab completion, run: source ~/.bashrc\n")
	} else {
		fmt.Printf("To activate tab completion, run: source ~/.bashrc\n")
	}
}

// detectUserShell attempts to determine the user's shell, handling sudo cases
func (a *App) detectUserShell() string {
	userShell := os.Getenv("SHELL")
	if userShell != "" && userShell != "/bin/sh" {
		return userShell
	}

	// When running with sudo, try to get the original user's shell
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// Try macOS dscl first (more reliable on macOS)
		cmd := exec.Command("dscl", ".", "-read", "/Users/"+sudoUser, "UserShell")
		if output, err := cmd.Output(); err == nil {
			// Parse "UserShell: /bin/zsh" format
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "UserShell: ") {
					return strings.TrimPrefix(line, "UserShell: ")
				}
			}
		}
	}

	return "/bin/bash" // Default fallback
}

// verifyInstallation checks that cipgram is properly installed and accessible
func (a *App) verifyInstallation() {
	if err := exec.Command("which", "cipgram").Run(); err != nil {
		fmt.Printf("Warning: cipgram not found in PATH. You may need to restart your shell.\n")
	} else {
		fmt.Printf("Installation verified - cipgram is now available system-wide.\n")
	}
}

// configurePCAPAnalysis sets up configuration and displays analysis info
func (a *App) configurePCAPAnalysis(paths *output.OutputPaths) {
	log.Printf("PCAP Traffic Analysis")
	log.Printf("PCAP file: %s", a.config.PcapPath)
	log.Printf("JSON file: %s", a.config.OutJSON)

	// Set default output paths if not specified
	if a.config.OutDOT == "" {
		a.config.OutDOT = fmt.Sprintf("%s/network_diagrams/diagram.dot", paths.ProjectRoot)
	}
	if a.config.OutJSON == "" {
		a.config.OutJSON = fmt.Sprintf("%s/data/diagram.json", paths.ProjectRoot)
	}

	// Show configuration info
	if a.config.EnableVendorLookup {
		log.Printf("Vendor lookup: enabled (MAC addresses will be resolved to manufacturers)")
	} else {
		log.Printf("Vendor lookup: disabled (use -vendor-lookup=true to enable)")
	}

	if a.config.EnableDNSLookup {
		log.Printf("DNS lookup: enabled (IP addresses will be resolved to hostnames)")
	} else {
		log.Printf("DNS lookup: disabled (use -dns-lookup=true to enable)")
	}
}

// parsePCAPFile creates parser and parses the PCAP file
func (a *App) parsePCAPFile() (*types.NetworkModel, error) {
	// Create PCAP parser with configuration
	pcapConfig := &pcap.PCAPConfig{
		ShowHostnames:      a.config.ShowHostnames,
		EnableVendorLookup: a.config.EnableVendorLookup,
		EnableDNSLookup:    a.config.EnableDNSLookup,
		FastMode:           a.config.FastMode,
		HideUnknown:        a.config.HideUnknown,
		MaxNodes:           a.config.MaxNodes,
		ConfigPath:         a.config.ConfigPath,
	}

	parser := pcap.NewPCAPParser(a.config.PcapPath, pcapConfig)
	log.Printf("Parsing PCAP file...")

	// Parse the PCAP file
	model, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse PCAP file %s: %w", a.config.PcapPath, err)
	}

	log.Printf("Parsed PCAP: %d assets, %d flows", len(model.Assets), len(model.Flows))
	return model, nil
}

// generatePCAPDiagrams creates all PCAP-related diagrams
func (a *App) generatePCAPDiagrams(model *types.NetworkModel, paths *output.OutputPaths) error {
	// Convert NetworkModel to Graph for proper PCAP diagram generation
	originalGraph := a.convertNetworkModelToGraph(model)

	log.Printf("Generating PCAP network diagrams...")
	log.Printf("Output directory: %s", paths.NetworkDiagrams)

	// Initialize performance optimizer
	optimizer := NewDiagramPerformanceOptimizer()

	// Enable fast mode for large networks
	nodeCount := len(originalGraph.Hosts)
	edgeCount := len(originalGraph.Edges)

	if nodeCount > 100 || edgeCount > 200 {
		optimizer.SetFastMode(true)
		log.Printf("Large network detected (%d nodes, %d edges) - enabling fast mode", nodeCount, edgeCount)
	}

	// Check if we should skip diagram generation entirely
	if optimizer.ShouldSkipDiagramGeneration(nodeCount, edgeCount) {
		log.Printf("WARNING: Diagram generation skipped due to size - generating DOT files only")
		return nil
	}

	// Optimize graph for diagram generation
	graph := optimizer.OptimizeGraphForDiagram(originalGraph, model)

	// Generate Purdue model diagram (traditional Purdue with horizontal bars)
	purdueBasePath := filepath.Join(paths.NetworkDiagrams, "purdue_diagram")
	log.Printf("Generating traditional Purdue model diagram...")
	if err := a.generatePurdueModelDiagrams(graph, purdueBasePath, model); err != nil {
		log.Printf("Warning: Failed to generate Purdue diagrams: %v", err)
	} else {
		log.Printf("Purdue model diagrams: %s.{dot,json,svg,png}", purdueBasePath)
	}

	// Generate network topology diagram (traditional network with router/firewall center)
	networkBasePath := filepath.Join(paths.NetworkDiagrams, "network_topology")
	log.Printf("Generating traditional network topology diagram...")
	if err := a.generateNetworkTopologyDiagrams(graph, networkBasePath, model); err != nil {
		log.Printf("Warning: Failed to generate network diagrams: %v", err)
	} else {
		log.Printf("Network topology diagrams: %s.{dot,json,svg,png}", networkBasePath)
	}

	return nil
}

// exportPCAPResults handles data export, CSV generation, and cleanup
func (a *App) exportPCAPResults(model *types.NetworkModel, paths *output.OutputPaths) {
	// Generate CSV conversation analysis
	log.Printf("Generating conversation analysis CSV...")
	if err := a.generateConversationCSV(model, paths); err != nil {
		log.Printf("Warning: Failed to generate conversation CSV: %v", err)
	} else {
		log.Printf("Conversation analysis: %s/data/conversations.csv", paths.ProjectRoot)
	}

	// Save JSON output if requested
	if a.config.OutJSON != "" {
		log.Printf("Saving analysis data...")

		// Convert flows map to slice for JSON serialization
		type SerializableModel struct {
			Assets   map[string]*types.Asset          `json:"assets"`
			Networks map[string]*types.NetworkSegment `json:"networks"`
			Flows    []*types.Flow                    `json:"flows"`
			Policies []*types.SecurityPolicy          `json:"policies"`
			Metadata types.InputMetadata              `json:"metadata"`
		}

		flows := make([]*types.Flow, 0, len(model.Flows))
		for _, flow := range model.Flows {
			flows = append(flows, flow)
		}

		serializableModel := SerializableModel{
			Assets:   model.Assets,
			Networks: model.Networks,
			Flows:    flows,
			Policies: model.Policies,
			Metadata: model.Metadata,
		}

		jsonData, err := json.MarshalIndent(serializableModel, "", "  ")
		if err != nil {
			log.Printf("Warning: Failed to marshal JSON: %v", err)
		} else if err := os.WriteFile(a.config.OutJSON, jsonData, 0644); err != nil {
			log.Printf("Warning: Failed to save JSON: %v", err)
		} else {
			log.Printf("Analysis data: %s", a.config.OutJSON)
		}
	}

	// Display analysis summary
	a.displayPCAPSummary(model)

	// Save OUI cache if vendor lookup was used
	if a.config.EnableVendorLookup {
		vendor.SaveOUICache()
	}
}
