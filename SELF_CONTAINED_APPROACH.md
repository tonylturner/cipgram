# Self-Contained Project Dependencies

Perfect approach for training workshops! Instead of eliminating external tools, let's **embed them in the project**.

## 🎯 Goal: Zero External Installation Requirements

### Current Problem:
- Workshop attendees need to install Graphviz separately
- Different versions cause inconsistent results  
- Installation failures block workshop progress

### ✅ Solution: Embed Everything in Go Binary

## Implementation Options

### Option 1: Embed Graphviz Binary (Recommended)
```go
//go:embed assets/graphviz/dot
var dotBinary []byte

//go:embed assets/graphviz/dot.exe  
var dotBinaryWindows []byte

// Extract and use embedded binary at runtime
func getEmbeddedDot() string {
    // Extract binary to temp location and return path
}
```

### Option 2: Embed Web Assets for Interactive Diagrams
```go
//go:embed web/diagram.html
var diagramHTML string

//go:embed web/d3.min.js
var d3JS string

//go:embed web/viz.js
var vizJS string

// Generate interactive HTML diagrams
func generateInteractiveDiagram(g *Graph) string {
    // Return complete HTML with embedded JS
}
```

### Option 3: Hybrid Approach (Best for Workshops)
- **Graphviz binary** embedded for consistent rendering
- **Web assets** embedded for interactive exploration
- **Fonts** embedded for consistent typography
- **Templates** embedded for customizable output

## Workshop Benefits

### ✅ Attendee Experience:
- Download single binary
- Run immediately - no setup required
- Identical results on all platforms
- Works offline (no internet required)

### ✅ Instructor Benefits:
- No troubleshooting installation issues
- Focus on OT segmentation concepts
- Consistent demo results
- Portable workshop materials

## File Structure
```
cipgram/
├── assets/
│   ├── graphviz/
│   │   ├── dot           # Linux/Mac binary
│   │   └── dot.exe       # Windows binary
│   ├── fonts/
│   │   └── arial.ttf     # Embedded fonts
│   └── templates/
│       ├── purdue.html   # Interactive templates
│       └── network.html
├── web/
│   ├── js/
│   │   ├── d3.min.js     # Visualization library
│   │   └── viz.js        # Graphviz in JS
│   └── css/
│       └── diagrams.css  # Styling
└── main.go               # Embeds everything above
```

Should I implement this self-contained approach with embedded binaries and web assets?
