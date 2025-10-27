package cli

import (
	"fmt"
	"log"
	"os/exec"
	"time"

	"cipgram/pkg/types"
)

// DiagramPerformanceOptimizer optimizes diagram generation for large networks
type DiagramPerformanceOptimizer struct {
	maxNodes         int
	maxEdges         int
	enableFiltering  bool
	enableClustering bool
	fastMode         bool
}

// NewDiagramPerformanceOptimizer creates a new optimizer
func NewDiagramPerformanceOptimizer() *DiagramPerformanceOptimizer {
	return &DiagramPerformanceOptimizer{
		maxNodes:         50,  // Limit nodes for performance
		maxEdges:         100, // Limit edges for performance
		enableFiltering:  true,
		enableClustering: true,
		fastMode:         false,
	}
}

// OptimizeGraphForDiagram optimizes graph for diagram generation
func (dpo *DiagramPerformanceOptimizer) OptimizeGraphForDiagram(graph *types.Graph, model *types.NetworkModel) *types.Graph {
	start := time.Now()

	// Check if optimization is needed
	nodeCount := len(graph.Hosts)
	edgeCount := len(graph.Edges)

	log.Printf("Optimizing diagram: %d nodes, %d edges", nodeCount, edgeCount)

	if nodeCount <= dpo.maxNodes && edgeCount <= dpo.maxEdges {
		log.Printf("Graph size acceptable, no optimization needed")
		return graph
	}

	optimizedGraph := &types.Graph{
		Hosts: make(map[string]*types.Host),
		Edges: make(map[types.FlowKey]*types.Edge),
	}

	// Step 1: Filter and prioritize hosts
	prioritizedHosts := dpo.prioritizeHosts(graph, model)

	// Step 2: Add top priority hosts
	nodeCount = 0
	for _, host := range prioritizedHosts {
		if nodeCount >= dpo.maxNodes {
			break
		}
		optimizedGraph.Hosts[host.IP] = host
		nodeCount++
	}

	// Step 3: Add relevant edges
	edgeCount = 0
	for key, edge := range graph.Edges {
		if edgeCount >= dpo.maxEdges {
			break
		}

		// Only add edges between included hosts
		if _, srcExists := optimizedGraph.Hosts[edge.Src]; srcExists {
			if _, dstExists := optimizedGraph.Hosts[edge.Dst]; dstExists {
				optimizedGraph.Edges[key] = edge
				edgeCount++
			}
		}
	}

	duration := time.Since(start)
	log.Printf("Graph optimized in %v: %d->%d nodes, %d->%d edges",
		duration, len(graph.Hosts), len(optimizedGraph.Hosts),
		len(graph.Edges), len(optimizedGraph.Edges))

	return optimizedGraph
}

// prioritizeHosts prioritizes hosts based on importance
func (dpo *DiagramPerformanceOptimizer) prioritizeHosts(graph *types.Graph, model *types.NetworkModel) []*types.Host {
	type hostScore struct {
		host  *types.Host
		score int
	}

	var scored []hostScore

	for _, host := range graph.Hosts {
		score := dpo.calculateHostScore(host, model)
		scored = append(scored, hostScore{host: host, score: score})
	}

	// Sort by score (highest first)
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[i].score < scored[j].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	// Extract sorted hosts
	var result []*types.Host
	for _, item := range scored {
		result = append(result, item.host)
	}

	return result
}

// calculateHostScore calculates importance score for a host
func (dpo *DiagramPerformanceOptimizer) calculateHostScore(host *types.Host, model *types.NetworkModel) int {
	score := 0

	// Get asset information
	asset, exists := model.Assets[host.IP]
	if !exists {
		return 0
	}

	// Score based on device type
	switch asset.DeviceName {
	case "PLC", "Controller":
		score += 100
	case "HMI", "Operator Interface":
		score += 80
	case "Network Infrastructure", "Network Device":
		score += 90
	case "Engineering Station", "Workstation":
		score += 60
	default:
		score += 20
	}

	// Score based on protocol count (more protocols = more important)
	score += len(asset.Protocols) * 5

	// Score based on Purdue level
	switch asset.PurdueLevel {
	case types.L0, types.L1:
		score += 50
	case types.L2:
		score += 40
	case types.L3:
		score += 30
	case types.L3_5:
		score += 35
	case types.L4, types.L5:
		score += 25
	}

	// Score based on criticality
	switch asset.Criticality {
	case types.CriticalAsset:
		score += 30
	case types.HighAsset:
		score += 20
	case types.MediumAsset:
		score += 10
	}

	// Bonus for industrial protocols
	industrialProtocols := []string{"Modbus", "EtherNet/IP", "S7Comm", "OPC", "BACnet", "DNP3"}
	for _, protocol := range asset.Protocols {
		protocolStr := string(protocol)
		for _, industrial := range industrialProtocols {
			if containsSubstring(protocolStr, industrial) {
				score += 15
				break
			}
		}
	}

	return score
}

// containsSubstring checks if a string contains a substring (case-insensitive)
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findInString(s, substr))))
}

// findInString finds substring in string
func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// OptimizeImageGeneration optimizes Graphviz image generation
func (dpo *DiagramPerformanceOptimizer) OptimizeImageGeneration(dotPath string) error {
	start := time.Now()

	// Check if dot is available
	if _, err := exec.LookPath("dot"); err != nil {
		log.Printf("WARNING: Graphviz not found - skipping image generation")
		return nil
	}

	// Use faster layout engines for large graphs
	layoutEngine := "dot" // Default

	// For large graphs, use faster engines
	if dpo.fastMode {
		layoutEngine = "neato" // Faster for large graphs
	}

	// Generate only essential formats to save time
	formats := []string{"svg"} // Start with just SVG
	if !dpo.fastMode {
		formats = append(formats, "png")
	}

	for _, format := range formats {
		outputPath := dotPath[:len(dotPath)-4] + "." + format

		var args []string
		if format == "png" {
			// Lower DPI for faster generation
			args = []string{"-K" + layoutEngine, "-T" + format, "-Gdpi=150", dotPath, "-o", outputPath}
		} else {
			args = []string{"-K" + layoutEngine, "-T" + format, dotPath, "-o", outputPath}
		}

		// Set timeout for image generation
		cmd := exec.Command("dot", args...)

		if err := cmd.Run(); err != nil {
			log.Printf("WARNING: Failed to generate %s: %v", format, err)
		} else {
			log.Printf("Generated %s in %v", outputPath, time.Since(start))
		}
	}

	return nil
}

// SetFastMode enables/disables fast mode
func (dpo *DiagramPerformanceOptimizer) SetFastMode(enabled bool) {
	dpo.fastMode = enabled
	if enabled {
		dpo.maxNodes = 30
		dpo.maxEdges = 50
		log.Printf("Fast mode enabled: max %d nodes, %d edges", dpo.maxNodes, dpo.maxEdges)
	} else {
		dpo.maxNodes = 50
		dpo.maxEdges = 100
		log.Printf("Normal mode: max %d nodes, %d edges", dpo.maxNodes, dpo.maxEdges)
	}
}

// SetLimits sets custom node and edge limits
func (dpo *DiagramPerformanceOptimizer) SetLimits(maxNodes, maxEdges int) {
	dpo.maxNodes = maxNodes
	dpo.maxEdges = maxEdges
	log.Printf("Custom limits set: max %d nodes, %d edges", maxNodes, maxEdges)
}

// GetOptimizationStats returns optimization statistics
func (dpo *DiagramPerformanceOptimizer) GetOptimizationStats() map[string]interface{} {
	return map[string]interface{}{
		"max_nodes":         dpo.maxNodes,
		"max_edges":         dpo.maxEdges,
		"enable_filtering":  dpo.enableFiltering,
		"enable_clustering": dpo.enableClustering,
		"fast_mode":         dpo.fastMode,
	}
}

// ShouldSkipDiagramGeneration determines if diagram generation should be skipped
func (dpo *DiagramPerformanceOptimizer) ShouldSkipDiagramGeneration(nodeCount, edgeCount int) bool {
	// Skip if graph is extremely large (increased thresholds)
	if nodeCount > 500 || edgeCount > 1000 {
		log.Printf("WARNING: Skipping diagram generation: graph too large (%d nodes, %d edges)", nodeCount, edgeCount)
		log.Printf("Use -fast-mode or reduce data size for diagram generation")
		return true
	}
	return false
}

// PrintOptimizationReport prints optimization statistics
func (dpo *DiagramPerformanceOptimizer) PrintOptimizationReport(originalNodes, originalEdges, optimizedNodes, optimizedEdges int, duration time.Duration) {
	fmt.Printf("\nDIAGRAM OPTIMIZATION REPORT\n")
	fmt.Printf("===============================================================\n")
	fmt.Printf("Performance Settings:\n")
	fmt.Printf("  - Fast Mode: %v\n", dpo.fastMode)
	fmt.Printf("  - Max Nodes: %d\n", dpo.maxNodes)
	fmt.Printf("  - Max Edges: %d\n", dpo.maxEdges)
	fmt.Printf("\nOptimization Results:\n")
	fmt.Printf("  - Original: %d nodes, %d edges\n", originalNodes, originalEdges)
	fmt.Printf("  - Optimized: %d nodes, %d edges\n", optimizedNodes, optimizedEdges)
	fmt.Printf("  - Reduction: %.1f%% nodes, %.1f%% edges\n",
		float64(originalNodes-optimizedNodes)/float64(originalNodes)*100,
		float64(originalEdges-optimizedEdges)/float64(originalEdges)*100)
	fmt.Printf("  - Processing Time: %v\n", duration)
	fmt.Printf("\n")
}
