package main

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// ConnectionData represents a connection between two hosts for the diagram
type ConnectionData struct {
	SrcIP    string
	DstIP    string
	Protocol string
	SrcLevel string
	DstLevel string
}

// generatePurdueSVG creates a professional Purdue model diagram using pure SVG
func generatePurdueSVG(g *Graph, outputDir string) (string, error) {
	// Separate hosts by Purdue level
	var operationsHosts, supervisoryHosts, processHosts []*Host

	for _, host := range g.Hosts {
		level := determinePurdueLevel(host)
		switch level {
		case "Operations":
			operationsHosts = append(operationsHosts, host)
		case "Supervisory":
			supervisoryHosts = append(supervisoryHosts, host)
		default: // ProcessControl
			processHosts = append(processHosts, host)
		}
	}

	// Build connection data for inter-level connections
	var connections []ConnectionData
	for _, edge := range g.Edges {
		srcLevel := ""
		dstLevel := ""

		// Find source and destination levels
		for _, host := range g.Hosts {
			if host.IP == edge.Src {
				srcLevel = determinePurdueLevel(host)
			}
			if host.IP == edge.Dst {
				dstLevel = determinePurdueLevel(host)
			}
		}

		// Only include inter-level connections
		if srcLevel != "" && dstLevel != "" && srcLevel != dstLevel {
			connections = append(connections, ConnectionData{
				SrcIP:    edge.Src,
				DstIP:    edge.Dst,
				Protocol: string(edge.Protocol),
				SrcLevel: srcLevel,
				DstLevel: dstLevel,
			})
		}
	}

	// Generate SVG content
	svg := generatePurdueSVGContent(operationsHosts, supervisoryHosts, processHosts, connections)

	// Write SVG file
	svgPath := filepath.Join(outputDir, "purdue_diagram.svg")
	err := os.WriteFile(svgPath, []byte(svg), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write SVG: %v", err)
	}

	return svgPath, nil
}

// generatePurdueSVGContent creates the SVG markup for the Purdue diagram
func generatePurdueSVGContent(operations, supervisory, process []*Host, connections []ConnectionData) string {
	const width = 1600
	const margin = 50
	const levelHeight = 280
	const levelSpacing = 40

	// Calculate how many levels we have and total height needed
	levelCount := 0
	if len(operations) > 0 {
		levelCount++
	}
	if len(supervisory) > 0 {
		levelCount++
	}
	if len(process) > 0 {
		levelCount++
	}

	totalHeight := 120 + (levelCount * levelHeight) + ((levelCount - 1) * levelSpacing) + 100 // Title + levels + spacing + bottom margin

	svg := strings.Builder{}

	// SVG header
	svg.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">`, width, totalHeight))
	svg.WriteString("\n")
	svg.WriteString(`<defs>`)
	svg.WriteString("\n")
	
	// Define gradients and styles
	svg.WriteString(`
		<linearGradient id="operationsGrad" x1="0%" y1="0%" x2="0%" y2="100%">
			<stop offset="0%" style="stop-color:#e6f3ff"/>
			<stop offset="100%" style="stop-color:#cce7ff"/>
		</linearGradient>
		<linearGradient id="supervisoryGrad" x1="0%" y1="0%" x2="0%" y2="100%">
			<stop offset="0%" style="stop-color:#fff2e6"/>
			<stop offset="100%" style="stop-color:#ffe5cc"/>
		</linearGradient>
		<linearGradient id="processGrad" x1="0%" y1="0%" x2="0%" y2="100%">
			<stop offset="0%" style="stop-color:#e8f6e8"/>
			<stop offset="100%" style="stop-color:#d4f4d4"/>
		</linearGradient>
		<filter id="shadow" x="-50%" y="-50%" width="200%" height="200%">
			<feDropShadow dx="2" dy="4" stdDeviation="4" flood-opacity="0.2"/>
		</filter>
	`)
	svg.WriteString("</defs>")
	svg.WriteString("\n")
	
	// Background
	svg.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="white"/>`, width, totalHeight))
	svg.WriteString("\n")
	
	// Title
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="40" text-anchor="middle" font-family="Arial, sans-serif" font-size="28" font-weight="bold" fill="#333">%s</text>`, 
		width/2, html.EscapeString("Purdue Model - Industrial Control System Architecture")))
	svg.WriteString("\n")

	// Calculate dynamic positioning for each level
	currentY := 80

	var levelsToGenerate []struct {
		hosts    []*Host
		id       string
		title    string
		subtitle string
		gradient string
		border   string
	}

	if len(operations) > 0 {
		levelsToGenerate = append(levelsToGenerate, struct {
			hosts    []*Host
			id       string
			title    string
			subtitle string
			gradient string
			border   string
		}{operations, "operations", "Level 3: Operations Systems", "MES | Scheduling | OEE | Quality Management", "url(#operationsGrad)", "#0066cc"})
	}

	if len(supervisory) > 0 {
		levelsToGenerate = append(levelsToGenerate, struct {
			hosts    []*Host
			id       string
			title    string
			subtitle string
			gradient string
			border   string
		}{supervisory, "supervisory", "Level 2: Supervisory Control", "SCADA | HMI | Alarming | Reporting | Trending", "url(#supervisoryGrad)", "#ff8800"})
	}

	if len(process) > 0 {
		levelsToGenerate = append(levelsToGenerate, struct {
			hosts    []*Host
			id       string
			title    string
			subtitle string
			gradient string
			border   string
		}{process, "process", "Level 1: Process Control", "PLCs | RTUs | Basic Control & I/O", "url(#processGrad)", "#00aa44"})
	}

	// Generate each level with proper spacing
	for _, level := range levelsToGenerate {
		svg.WriteString(drawPurdueLevel(level.id, level.title, level.subtitle, 
			level.hosts, margin, currentY, width-2*margin, levelHeight, level.gradient, level.border))
		svg.WriteString("\n")
		currentY += levelHeight + levelSpacing
	}

	// Draw connections (simplified for now)
	svg.WriteString(drawConnections(connections, operations, supervisory, process))
	svg.WriteString("\n")

	svg.WriteString("</svg>")
	svg.WriteString("\n")
	return svg.String()
}

// drawPurdueLevel creates SVG for a single Purdue level
func drawPurdueLevel(levelId, title, subtitle string, hosts []*Host, x, y, w, h int, fill, borderColor string) string {
	svg := strings.Builder{}

	// Level background with rounded corners
	svg.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" rx="15" fill="%s" stroke="%s" stroke-width="3" filter="url(#shadow)"/>`, 
		x, y, w, h, fill, borderColor))
	svg.WriteString("\n")

	// Level title
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-family="Arial, sans-serif" font-size="22" font-weight="bold" fill="%s">%s</text>`, 
		x+20, y+35, borderColor, html.EscapeString(title)))
	svg.WriteString("\n")
	
	// Level subtitle
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-family="Arial, sans-serif" font-size="14" font-style="italic" fill="%s" opacity="0.8">%s</text>`, 
		x+20, y+55, borderColor, html.EscapeString(subtitle)))
	svg.WriteString("\n")

	// Draw hosts in a grid
	const cardWidth = 260
	const cardHeight = 90
	const cardSpacing = 20
	const cardsPerRow = 5

	startX := x + 30
	startY := y + 80

	for i, host := range hosts {
		row := i / cardsPerRow
		col := i % cardsPerRow

		cardX := startX + col*(cardWidth+cardSpacing)
		cardY := startY + row*(cardHeight+cardSpacing)

		// Ensure card fits within level bounds
		if cardX+cardWidth > x+w-30 {
			continue // Skip if it would overflow
		}

		svg.WriteString(drawHostCard(host, cardX, cardY, cardWidth, cardHeight))
	}

	return svg.String()
}

// drawHostCard creates SVG for a single host device card
func drawHostCard(host *Host, x, y, w, h int) string {
	svg := strings.Builder{}

	// Card background
	svg.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" rx="8" fill="white" stroke="#ddd" stroke-width="1" filter="url(#shadow)"/>`, 
		x, y, w, h))
	svg.WriteString("\n")

	// Device icon
	iconColor := getHostIconColor(host)
	iconText := getHostIconText(host)
	
	// Icon background
	svg.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="40" height="25" rx="4" fill="%s"/>`, 
		x+10, y+10, iconColor))
	svg.WriteString("\n")

	// Icon text
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="white">%s</text>`, 
		x+30, y+27, html.EscapeString(iconText)))
	svg.WriteString("\n")
	
	// Host name
	displayName := getDisplayName(host)
	if len(displayName) > 25 {
		displayName = displayName[:22] + "..."
	}
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-family="Arial, sans-serif" font-size="13" font-weight="600" fill="#2c3e50">%s</text>`, 
		x+10, y+50, html.EscapeString(displayName)))
	svg.WriteString("\n")
	
	// IP address  
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-family="Courier New, monospace" font-size="14" font-weight="bold" fill="#3498db">%s</text>`, 
		x+10, y+68, html.EscapeString(host.IP)))
	svg.WriteString("\n")
	
	// Vendor
	vendor := host.Vendor
	if vendor == "" {
		vendor = "Unknown Vendor"
	}
	if len(vendor) > 30 {
		vendor = vendor[:27] + "..."
	}
	svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-family="Arial, sans-serif" font-size="11" fill="#7f8c8d">%s</text>`, 
		x+10, y+82, html.EscapeString(vendor)))
	svg.WriteString("\n")

	return svg.String()
}

// drawConnections creates SVG for inter-level connections (simplified)
func drawConnections(connections []ConnectionData, operations, supervisory, process []*Host) string {
	svg := strings.Builder{}

	// For now, just add a note about connections
	if len(connections) > 0 {
		svg.WriteString(fmt.Sprintf(`<text x="50" y="1150" font-family="Arial, sans-serif" font-size="12" fill="#666">%d inter-level connections detected</text>`,
			len(connections)))
	}

	return svg.String()
}

// Helper functions
func getDisplayName(host *Host) string {
	if host.Hostname != "" {
		return host.Hostname
	}
	if host.DeviceName != "" {
		return host.DeviceName
	}
	return "Unknown Device"
}

func getHostIconColor(host *Host) string {
	class := getHostIconClass(host)
	switch class {
	case "icon-db":
		return "#4A90E2"
	case "icon-hmi":
		return "#F39C12"
	case "icon-srv":
		return "#27AE60"
	case "icon-plc":
		return "#8E44AD"
	case "icon-gw":
		return "#E74C3C"
	default:
		return "#95A5A6"
	}
}

// getHostIconClass returns the CSS class for the host icon
func getHostIconClass(host *Host) string {
	vendor := strings.ToLower(host.Vendor)
	deviceName := strings.ToLower(host.DeviceName)
	hostname := strings.ToLower(host.Hostname)

	if strings.Contains(vendor, "sql") || strings.Contains(deviceName, "database") ||
		strings.Contains(hostname, "db") || strings.Contains(hostname, "sql") {
		return "icon-db"
	}
	if strings.Contains(vendor, "vmware") || strings.Contains(deviceName, "client") ||
		strings.Contains(hostname, "hmi") || strings.Contains(hostname, "client") {
		return "icon-hmi"
	}
	if strings.Contains(vendor, "server") || strings.Contains(deviceName, "server") ||
		strings.Contains(hostname, "server") || strings.Contains(vendor, "lantronix") {
		return "icon-srv"
	}
	if strings.Contains(vendor, "rockwell") || strings.Contains(deviceName, "plc") ||
		strings.Contains(hostname, "plc") || host.ICSScore > 50 {
		return "icon-plc"
	}
	if strings.Contains(vendor, "cisco") || strings.Contains(deviceName, "router") ||
		strings.Contains(hostname, "gateway") || strings.Contains(hostname, "router") {
		return "icon-gw"
	}
	return "icon-io"
}

// getHostIconText returns the text for the host icon
func getHostIconText(host *Host) string {
	class := getHostIconClass(host)
	switch class {
	case "icon-db":
		return "DB"
	case "icon-hmi":
		return "HMI"
	case "icon-srv":
		return "SRV"
	case "icon-plc":
		return "PLC"
	case "icon-gw":
		return "GW"
	default:
		return "I/O"
	}
}

// generatePurdueWithGG replaces the old function name for compatibility
func generatePurdueWithGG(g *Graph, outputDir string) (string, error) {
	return generatePurdueSVG(g, outputDir)
}
