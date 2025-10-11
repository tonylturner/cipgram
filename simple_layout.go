package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

func writeSimpleDOT(g *Graph, path string) error {
	levels := map[PurdueLevel][]string{}
	for ip, h := range g.Hosts {
		levels[h.InferredLevel] = append(levels[h.InferredLevel], ip)
	}
	for k := range levels {
		sort.Strings(levels[k])
	}

	var b strings.Builder
	w := bufio.NewWriter(&b)

	// Simple, clear Purdue diagram
	fmt.Fprintln(w, "digraph PurdueNetwork {")
	fmt.Fprintln(w, `  rankdir=TB;`)
	fmt.Fprintln(w, `  bgcolor=white;`)
	fmt.Fprintln(w, `  node [shape=box, style="rounded,filled", fontname="Arial", fontsize=10];`)
	fmt.Fprintln(w, `  edge [fontname="Arial", fontsize=8];`)
	fmt.Fprintln(w, "")

	// Create clear hierarchy: L3 → L2 → L1
	order := []PurdueLevel{L3, L2, L1}

	for _, lvl := range order {
		if len(levels[lvl]) == 0 {
			continue
		}

		levelName := map[PurdueLevel]string{
			L3: "Level 3 - Management",
			L2: "Level 2 - Control",
			L1: "Level 1 - Field",
		}[lvl]

		levelColor := map[PurdueLevel]string{
			L3: "#e6f3ff", // Light blue
			L2: "#fff7e6", // Light orange
			L1: "#e8f6e8", // Light green
		}[lvl]

		borderColor := map[PurdueLevel]string{
			L3: "#0066cc", // Blue
			L2: "#ff8800", // Orange
			L1: "#00aa44", // Green
		}[lvl]

		fmt.Fprintf(w, "  subgraph cluster_%s {\n", string(lvl))
		fmt.Fprintf(w, "    label=\"%s\";\n", levelName)
		fmt.Fprintf(w, "    style=filled;\n")
		fmt.Fprintf(w, "    bgcolor=\"%s\";\n", levelColor)
		fmt.Fprintf(w, "    color=\"%s\";\n", borderColor)
		fmt.Fprintf(w, "    penwidth=2;\n")
		fmt.Fprintf(w, "    fontsize=14;\n")
		fmt.Fprintf(w, "    fontname=\"Arial Bold\";\n")

		for _, ip := range levels[lvl] {
			host := g.Hosts[ip]

			// Simple, clear label
			label := ip
			if strings.HasPrefix(ip, "192.168.") {
				label = strings.TrimPrefix(ip, "192.168.")
			}

			if host.Hostname != "" {
				label = host.Hostname + "\\n" + label
			}

			if len(host.Roles) > 0 {
				role := host.Roles[0]
				if strings.Contains(role, "PLC") {
					label += "\\n[PLC]"
				} else if strings.Contains(role, "HMI") {
					label += "\\n[HMI]"
				} else if strings.Contains(role, "Server") {
					label += "\\n[Server]"
				}
			}

			if host.Vendor != "" {
				vendor := host.Vendor
				if len(vendor) > 8 {
					vendor = vendor[:8]
				}
				label += "\\n(" + vendor + ")"
			}

			nodeColor := levelColor
			if strings.Contains(strings.ToLower(label), "plc") {
				nodeColor = "#ccffcc" // Light green for PLCs
			} else if strings.Contains(strings.ToLower(label), "hmi") {
				nodeColor = "#ffffcc" // Light yellow for HMIs
			}

			fmt.Fprintf(w, "    \"%s\" [label=\"%s\", fillcolor=\"%s\"];\n",
				ip, label, nodeColor)
		}
		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w, "")
	}

	// Only show industrial protocol connections
	for _, e := range g.Edges {
		srcHost := g.Hosts[e.Src]
		dstHost := g.Hosts[e.Dst]

		// Skip unknown devices
		if srcHost.InferredLevel == Unknown || dstHost.InferredLevel == Unknown {
			continue
		}

		// Only show EtherNet/IP and Modbus for clarity
		protocolName := string(e.Protocol)
		if strings.Contains(protocolName, "ENIP") {
			fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"EtherNet/IP\", color=\"#00aa44\"];\n",
				e.Src, e.Dst)
		} else if strings.Contains(protocolName, "Modbus") {
			fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"Modbus\", color=\"#ff8800\"];\n",
				e.Src, e.Dst)
		}
	}

	fmt.Fprintln(w, "}")
	w.Flush()
	return os.WriteFile(path, []byte(b.String()), 0644)
}
