package main

import (
	"fmt"
	"html"
	"os"
	"os/exec"
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

	// Convert SVG to PNG
	pngPath := filepath.Join(outputDir, "purdue_diagram.png")
	err = convertSVGToPNG(svgPath, pngPath)
	if err != nil {
		// If conversion fails, still return the SVG path and log the warning
		fmt.Printf("Warning: Could not convert SVG to PNG: %v\n", err)
		return svgPath, nil
	}

	return pngPath, nil // Return PNG path as primary output
}

// generatePurdueSVGContent creates the SVG markup for the Purdue diagram
func generatePurdueSVGContent(operations, supervisory, process []*Host, connections []ConnectionData) string {
	const width = 1600
	const margin = 50
	const baseHeight = 180 // Base height for level header/title
	const cardHeight = 90
	const cardSpacing = 20
	const cardsPerRow = 5
	const levelSpacing = 40

	// Calculate dynamic height for each level based on device count
	calcLevelHeight := func(hostCount int) int {
		if hostCount == 0 {
			return 0
		}
		rows := (hostCount + cardsPerRow - 1) / cardsPerRow // Ceiling division
		contentHeight := rows*cardHeight + (rows-1)*cardSpacing
		return baseHeight + contentHeight + 40 // Extra padding
	}

	// Calculate individual level heights
	operationsHeight := calcLevelHeight(len(operations))
	supervisoryHeight := calcLevelHeight(len(supervisory))
	processHeight := calcLevelHeight(len(process))

	// Calculate total height
	levelCount := 0
	if operationsHeight > 0 {
		levelCount++
	}
	if supervisoryHeight > 0 {
		levelCount++
	}
	if processHeight > 0 {
		levelCount++
	}

	totalHeight := 120 + operationsHeight + supervisoryHeight + processHeight + ((levelCount - 1) * levelSpacing) + 100

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
		height   int
	}

	if len(operations) > 0 {
		levelsToGenerate = append(levelsToGenerate, struct {
			hosts    []*Host
			id       string
			title    string
			subtitle string
			gradient string
			border   string
			height   int
		}{operations, "operations", "Level 3: Operations Systems", "MES | Scheduling | OEE | Quality Management", "url(#operationsGrad)", "#0066cc", operationsHeight})
	}

	if len(supervisory) > 0 {
		levelsToGenerate = append(levelsToGenerate, struct {
			hosts    []*Host
			id       string
			title    string
			subtitle string
			gradient string
			border   string
			height   int
		}{supervisory, "supervisory", "Level 2: Supervisory Control", "SCADA | HMI | Alarming | Reporting | Trending", "url(#supervisoryGrad)", "#ff8800", supervisoryHeight})
	}

	if len(process) > 0 {
		levelsToGenerate = append(levelsToGenerate, struct {
			hosts    []*Host
			id       string
			title    string
			subtitle string
			gradient string
			border   string
			height   int
		}{process, "process", "Level 1: Process Control", "PLCs | RTUs | Basic Control & I/O", "url(#processGrad)", "#00aa44", processHeight})
	}

	// Generate each level with proper spacing
	for _, level := range levelsToGenerate {
		svg.WriteString(drawPurdueLevel(level.id, level.title, level.subtitle,
			level.hosts, margin, currentY, width-2*margin, level.height, level.gradient, level.border))
		svg.WriteString("\n")
		currentY += level.height + levelSpacing
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

// Helper function for level height calculation
func calcLevelHeight(hostCount int) int {
	if hostCount == 0 {
		return 0
	}
	rows := (hostCount + 5 - 1) / 5 // 5 cards per row
	return 180 + rows*90 + (rows-1)*20 + 40
}

// DevicePosition represents the position of a device card in the diagram
type DevicePosition struct {
	IP      string
	CenterX int
	CenterY int
	Level   string
}

// drawConnections creates SVG for inter-level connections with lines connecting actual devices
func drawConnections(connections []ConnectionData, operations, supervisory, process []*Host) string {
	if len(connections) == 0 {
		return ""
	}

	svg := strings.Builder{}
	svg.WriteString("<!-- Inter-level connections -->\n")

	// Create device position map by calculating actual card positions
	devicePositions := calculateDevicePositions(operations, supervisory, process)

	// Draw connections between actual devices
	connectionCount := 0
	drawnConnections := make(map[string]bool) // Prevent duplicates

	for _, conn := range connections {
		srcPos, srcExists := devicePositions[conn.SrcIP]
		dstPos, dstExists := devicePositions[conn.DstIP]

		if srcExists && dstExists && srcPos.Level != dstPos.Level {
			// Create unique connection key (bidirectional)
			key1 := fmt.Sprintf("%s-%s", conn.SrcIP, conn.DstIP)
			key2 := fmt.Sprintf("%s-%s", conn.DstIP, conn.SrcIP)

			if !drawnConnections[key1] && !drawnConnections[key2] {
				// Route connection around levels from device to device
				connectionPath := createDeviceToDeviceConnection(srcPos, dstPos, connectionCount)

				// Draw the curved path
				svg.WriteString(fmt.Sprintf(`<path d="%s" stroke="#2980b9" stroke-width="2.5" fill="none" opacity="0.8" stroke-linecap="round"/>`, connectionPath))
				svg.WriteString("\n")

				// Add protocol label if available
				if conn.Protocol != "" && conn.Protocol != "Unknown" {
					labelPos := getPathMidpoint(connectionPath)
					svg.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="60" height="18" rx="4" fill="white" stroke="#2980b9" stroke-width="1" opacity="0.9"/>`,
						labelPos.X-30, labelPos.Y-9))
					svg.WriteString("\n")
					svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" font-weight="600" fill="#2c3e50">%s</text>`,
						labelPos.X, labelPos.Y+3, html.EscapeString(conn.Protocol)))
					svg.WriteString("\n")
				}

				drawnConnections[key1] = true
				drawnConnections[key2] = true
				connectionCount++

				if connectionCount > 12 { // Limit to prevent overcrowding
					break
				}
			}
		}
	}

	return svg.String()
}

// calculateDevicePositions calculates the actual screen positions of device cards
func calculateDevicePositions(operations, supervisory, process []*Host) map[string]DevicePosition {
	positions := make(map[string]DevicePosition)

	const cardWidth = 260
	const cardHeight = 90
	const cardSpacing = 20
	const cardsPerRow = 5
	const startX = 80

	currentY := 80

	// Operations level positions
	if len(operations) > 0 {
		levelStartY := currentY + 80 // Account for level header
		for i, host := range operations {
			row := i / cardsPerRow
			col := i % cardsPerRow

			cardX := startX + col*(cardWidth+cardSpacing)
			cardY := levelStartY + row*(cardHeight+cardSpacing)

			positions[host.IP] = DevicePosition{
				IP:      host.IP,
				CenterX: cardX + cardWidth/2,
				CenterY: cardY + cardHeight/2,
				Level:   "Operations",
			}
		}
		currentY += calcLevelHeight(len(operations)) + 40
	}

	// Supervisory level positions
	if len(supervisory) > 0 {
		levelStartY := currentY + 80
		for i, host := range supervisory {
			row := i / cardsPerRow
			col := i % cardsPerRow

			cardX := startX + col*(cardWidth+cardSpacing)
			cardY := levelStartY + row*(cardHeight+cardSpacing)

			positions[host.IP] = DevicePosition{
				IP:      host.IP,
				CenterX: cardX + cardWidth/2,
				CenterY: cardY + cardHeight/2,
				Level:   "Supervisory",
			}
		}
		currentY += calcLevelHeight(len(supervisory)) + 40
	}

	// Process level positions
	if len(process) > 0 {
		levelStartY := currentY + 80
		for i, host := range process {
			row := i / cardsPerRow
			col := i % cardsPerRow

			cardX := startX + col*(cardWidth+cardSpacing)
			cardY := levelStartY + row*(cardHeight+cardSpacing)

			positions[host.IP] = DevicePosition{
				IP:      host.IP,
				CenterX: cardX + cardWidth/2,
				CenterY: cardY + cardHeight/2,
				Level:   "ProcessControl",
			}
		}
	}

	return positions
}

// createDeviceToDeviceConnection creates a smooth path between two specific devices
func createDeviceToDeviceConnection(srcPos, dstPos DevicePosition, connectionIndex int) string {
	// Determine routing side based on connection index to spread them out
	routeRight := connectionIndex%2 == 0

	// Start and end at device centers
	startX := srcPos.CenterX
	startY := srcPos.CenterY
	endX := dstPos.CenterX
	endY := dstPos.CenterY

	// Create routing points that go around the levels
	var routingPoints []Point

	if routeRight {
		// Route around the right side
		routingX := 1550 // Right edge with margin

		routingPoints = []Point{
			{startX, startY},
			{startX + 100, startY}, // Move out from device
			{routingX, startY},     // Move to routing edge
			{routingX, endY},       // Travel along edge
			{endX + 100, endY},     // Move in toward device
			{endX, endY},
		}
	} else {
		// Route around the left side
		routingX := 50 // Left edge with margin

		routingPoints = []Point{
			{startX, startY},
			{startX - 100, startY}, // Move out from device
			{routingX, startY},     // Move to routing edge
			{routingX, endY},       // Travel along edge
			{endX - 100, endY},     // Move in toward device
			{endX, endY},
		}
	}

	// Convert points to smooth SVG path
	return createSmoothSVGPath(routingPoints)
}

// getPathMidpoint calculates a good position for labels (simplified)
func getPathMidpoint(pathData string) Point {
	// For now, return a position along the routing edge
	return Point{X: 800, Y: 400}
}

// createSmoothSVGPath creates a smooth SVG path through the routing points
func createSmoothSVGPath(points []Point) string {
	if len(points) < 2 {
		return ""
	}

	path := fmt.Sprintf("M%d,%d", points[0].X, points[0].Y)

	// Create smooth curves between points
	for i := 1; i < len(points); i++ {
		if i == len(points)-1 {
			// Last segment - straight line
			path += fmt.Sprintf(" L%d,%d", points[i].X, points[i].Y)
		} else {
			// Curved segment using quadratic Bezier
			curr := points[i]
			next := points[i+1]

			// Control point is the current point, end point is halfway to next
			endX := (curr.X + next.X) / 2
			endY := (curr.Y + next.Y) / 2

			path += fmt.Sprintf(" Q%d,%d %d,%d", curr.X, curr.Y, endX, endY)
		}
	}

	return path
}

type Point struct {
	X, Y int
}

// Helper function for absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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

// convertSVGToPNG converts an SVG file to PNG using rsvg-convert or inkscape
func convertSVGToPNG(svgPath, pngPath string) error {
	// Try rsvg-convert first (commonly available on macOS)
	if _, err := exec.LookPath("rsvg-convert"); err == nil {
		// Generate high-resolution PNG maintaining aspect ratio: 2400px height at 200 DPI
		cmd := exec.Command("rsvg-convert", "-h", "2400", "--dpi-x", "200", "--dpi-y", "200", "-o", pngPath, svgPath)
		return cmd.Run()
	}

	// Try inkscape as fallback
	if _, err := exec.LookPath("inkscape"); err == nil {
		cmd := exec.Command("inkscape", "--export-type=png", "--export-height=2400",
			"--export-dpi=200", "--export-filename="+pngPath, svgPath)
		return cmd.Run()
	}

	return fmt.Errorf("neither rsvg-convert nor inkscape found - install one of them for PNG conversion")
}

// generatePurdueWithGG replaces the old function name for compatibility
func generatePurdueWithGG(g *Graph, outputDir string) (string, error) {
	return generatePurdueSVG(g, outputDir)
}
