# Pure Go Graphics Dependencies Upgrade

## Current External Dependencies to Eliminate

### ❌ External Tools Currently Used:
1. **Graphviz `dot` command** - for network diagram PNG/SVG generation
2. **rsvg-convert** - for SVG to PNG conversion
3. **inkscape** - as fallback for SVG to PNG conversion

## ✅ Pure Go Solution

Instead of external dependencies, let's use pure Go libraries for all diagram generation:

### Add to go.mod:
```go
require (
    github.com/google/gopacket v1.1.19
    gopkg.in/yaml.v3 v3.0.1
    github.com/fogleman/gg v1.3.0        // 2D graphics library
    github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a1  // Font rendering
    golang.org/x/image v0.15.0           // Image processing
)
```

### Benefits for Training Workshop:
- ✅ **Zero external dependencies** - works on any machine with Go
- ✅ **Consistent rendering** - same output everywhere
- ✅ **Faster deployment** - no need to install Graphviz/inkscape
- ✅ **Better control** - customizable fonts, colors, layouts
- ✅ **Cross-platform** - works on Windows/Mac/Linux identically

## Implementation Plan

### 1. Network Diagrams → Pure Go
Replace DOT generation with direct image generation using `github.com/fogleman/gg`

### 2. SVG to PNG → Pure Go  
Replace external conversion with `golang.org/x/image` libraries

### 3. Font Embedding
Embed fonts in the binary so no system font dependencies

Would you like me to implement this pure Go graphics solution?
