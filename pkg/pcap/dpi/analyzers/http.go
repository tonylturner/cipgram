package analyzers

import (
	"cipgram/pkg/pcap/core"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HTTPAnalyzer implements DPI for HTTP protocol
type HTTPAnalyzer struct {
	methodRegex    *regexp.Regexp
	responseRegex  *regexp.Regexp
	headerRegex    *regexp.Regexp
	userAgentRegex *regexp.Regexp
}

// NewHTTPAnalyzer creates a new HTTP analyzer
func NewHTTPAnalyzer() *HTTPAnalyzer {
	return &HTTPAnalyzer{
		methodRegex:    regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+`),
		responseRegex:  regexp.MustCompile(`^HTTP/(\d+\.\d+)\s+(\d+)\s+(.+)`),
		headerRegex:    regexp.MustCompile(`([^:]+):\s*(.+)`),
		userAgentRegex: regexp.MustCompile(`User-Agent:\s*(.+)`),
	}
}

// CanAnalyze determines if this analyzer can process the packet
func (h *HTTPAnalyzer) CanAnalyze(packet gopacket.Packet) bool {
	// Only analyze TCP packets
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)

	// Check common HTTP ports
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	httpPorts := []uint16{80, 8080, 8000, 8008, 3000, 4200, 5000, 9000}

	for _, port := range httpPorts {
		if srcPort == port || dstPort == port {
			return true
		}
	}

	// Also check if payload looks like HTTP
	payload := tcp.Payload
	if len(payload) > 10 {
		payloadStr := string(payload[:min(len(payload), 100)])
		return h.looksLikeHTTP(payloadStr)
	}

	return false
}

// Analyze performs HTTP protocol analysis
func (h *HTTPAnalyzer) Analyze(packet gopacket.Packet) *core.AnalysisResult {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) == 0 {
		return nil
	}

	payloadStr := string(payload)

	// Try to parse as HTTP request
	if request := h.parseHTTPRequest(payloadStr); request != nil {
		return &core.AnalysisResult{
			Protocol:    "HTTP",
			Subprotocol: request.Method + " Request",
			Confidence:  0.95,
			Details:     request.Details,
			Metadata:    request.Metadata,
		}
	}

	// Try to parse as HTTP response
	if response := h.parseHTTPResponse(payloadStr); response != nil {
		return &core.AnalysisResult{
			Protocol:    "HTTP",
			Subprotocol: "Response",
			Confidence:  0.95,
			Details:     response.Details,
			Metadata:    response.Metadata,
		}
	}

	// Check if it looks like HTTP but couldn't parse fully
	if h.looksLikeHTTP(payloadStr) {
		return &core.AnalysisResult{
			Protocol:    "HTTP",
			Subprotocol: "Partial",
			Confidence:  0.7,
			Details: map[string]interface{}{
				"reason": "looks_like_http_but_incomplete",
			},
			Metadata: map[string]string{
				"analysis": "heuristic",
			},
		}
	}

	return nil
}

// GetProtocolName returns the protocol name
func (h *HTTPAnalyzer) GetProtocolName() string {
	return "HTTP"
}

// GetConfidenceThreshold returns the minimum confidence threshold
func (h *HTTPAnalyzer) GetConfidenceThreshold() float32 {
	return 0.7
}

// HTTPRequest represents a parsed HTTP request
type HTTPRequest struct {
	Method   string
	URI      string
	Version  string
	Headers  map[string]string
	Details  map[string]interface{}
	Metadata map[string]string
}

// HTTPResponse represents a parsed HTTP response
type HTTPResponse struct {
	Version    string
	StatusCode int
	StatusText string
	Headers    map[string]string
	Details    map[string]interface{}
	Metadata   map[string]string
}

// parseHTTPRequest parses an HTTP request
func (h *HTTPAnalyzer) parseHTTPRequest(payload string) *HTTPRequest {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse request line
	requestLine := lines[0]
	if !h.methodRegex.MatchString(requestLine) {
		return nil
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return nil
	}

	request := &HTTPRequest{
		Method:   parts[0],
		URI:      parts[1],
		Version:  parts[2],
		Headers:  make(map[string]string),
		Details:  make(map[string]interface{}),
		Metadata: make(map[string]string),
	}

	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break // End of headers
		}

		if matches := h.headerRegex.FindStringSubmatch(line); matches != nil {
			headerName := strings.TrimSpace(matches[1])
			headerValue := strings.TrimSpace(matches[2])
			request.Headers[headerName] = headerValue
		}
	}

	// Extract interesting details
	request.Details["method"] = request.Method
	request.Details["uri"] = request.URI
	request.Details["version"] = request.Version
	request.Details["header_count"] = len(request.Headers)

	// Extract specific headers of interest
	if host, exists := request.Headers["Host"]; exists {
		request.Details["host"] = host
		request.Metadata["host"] = host
	}

	if userAgent, exists := request.Headers["User-Agent"]; exists {
		request.Details["user_agent"] = userAgent
		request.Metadata["user_agent"] = h.categorizeUserAgent(userAgent)
	}

	if contentType, exists := request.Headers["Content-Type"]; exists {
		request.Details["content_type"] = contentType
	}

	if contentLength, exists := request.Headers["Content-Length"]; exists {
		if length, err := strconv.Atoi(contentLength); err == nil {
			request.Details["content_length"] = length
		}
	}

	// Categorize request type
	request.Metadata["request_type"] = h.categorizeRequest(request)

	return request
}

// parseHTTPResponse parses an HTTP response
func (h *HTTPAnalyzer) parseHTTPResponse(payload string) *HTTPResponse {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse status line
	statusLine := lines[0]
	matches := h.responseRegex.FindStringSubmatch(statusLine)
	if matches == nil {
		return nil
	}

	statusCode, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil
	}

	response := &HTTPResponse{
		Version:    matches[1],
		StatusCode: statusCode,
		StatusText: matches[3],
		Headers:    make(map[string]string),
		Details:    make(map[string]interface{}),
		Metadata:   make(map[string]string),
	}

	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break // End of headers
		}

		if matches := h.headerRegex.FindStringSubmatch(line); matches != nil {
			headerName := strings.TrimSpace(matches[1])
			headerValue := strings.TrimSpace(matches[2])
			response.Headers[headerName] = headerValue
		}
	}

	// Extract interesting details
	response.Details["version"] = response.Version
	response.Details["status_code"] = response.StatusCode
	response.Details["status_text"] = response.StatusText
	response.Details["header_count"] = len(response.Headers)

	// Extract specific headers of interest
	if server, exists := response.Headers["Server"]; exists {
		response.Details["server"] = server
		response.Metadata["server"] = h.categorizeServer(server)
	}

	if contentType, exists := response.Headers["Content-Type"]; exists {
		response.Details["content_type"] = contentType
		response.Metadata["content_type"] = h.categorizeContentType(contentType)
	}

	if contentLength, exists := response.Headers["Content-Length"]; exists {
		if length, err := strconv.Atoi(contentLength); err == nil {
			response.Details["content_length"] = length
		}
	}

	// Categorize response
	response.Metadata["status_category"] = h.categorizeStatusCode(response.StatusCode)

	return response
}

// looksLikeHTTP performs heuristic check for HTTP-like content
func (h *HTTPAnalyzer) looksLikeHTTP(payload string) bool {
	// Check for HTTP methods
	if h.methodRegex.MatchString(payload) {
		return true
	}

	// Check for HTTP response
	if h.responseRegex.MatchString(payload) {
		return true
	}

	// Check for common HTTP headers
	httpHeaders := []string{"Host:", "User-Agent:", "Accept:", "Content-Type:", "Content-Length:"}
	for _, header := range httpHeaders {
		if strings.Contains(payload, header) {
			return true
		}
	}

	return false
}

// categorizeUserAgent categorizes user agent strings
func (h *HTTPAnalyzer) categorizeUserAgent(userAgent string) string {
	userAgent = strings.ToLower(userAgent)

	if strings.Contains(userAgent, "chrome") {
		return "Chrome Browser"
	}
	if strings.Contains(userAgent, "firefox") {
		return "Firefox Browser"
	}
	if strings.Contains(userAgent, "safari") && !strings.Contains(userAgent, "chrome") {
		return "Safari Browser"
	}
	if strings.Contains(userAgent, "edge") {
		return "Edge Browser"
	}
	if strings.Contains(userAgent, "curl") {
		return "cURL Tool"
	}
	if strings.Contains(userAgent, "wget") {
		return "wget Tool"
	}
	if strings.Contains(userAgent, "python") {
		return "Python Script"
	}
	if strings.Contains(userAgent, "java") {
		return "Java Application"
	}
	if strings.Contains(userAgent, "bot") || strings.Contains(userAgent, "crawler") {
		return "Web Crawler/Bot"
	}

	return "Unknown"
}

// categorizeServer categorizes server strings
func (h *HTTPAnalyzer) categorizeServer(server string) string {
	server = strings.ToLower(server)

	if strings.Contains(server, "apache") {
		return "Apache"
	}
	if strings.Contains(server, "nginx") {
		return "Nginx"
	}
	if strings.Contains(server, "iis") {
		return "IIS"
	}
	if strings.Contains(server, "tomcat") {
		return "Tomcat"
	}
	if strings.Contains(server, "jetty") {
		return "Jetty"
	}
	if strings.Contains(server, "node") {
		return "Node.js"
	}
	if strings.Contains(server, "express") {
		return "Express.js"
	}

	return "Unknown"
}

// categorizeContentType categorizes content types
func (h *HTTPAnalyzer) categorizeContentType(contentType string) string {
	contentType = strings.ToLower(contentType)

	if strings.Contains(contentType, "text/html") {
		return "HTML Page"
	}
	if strings.Contains(contentType, "application/json") {
		return "JSON API"
	}
	if strings.Contains(contentType, "application/xml") {
		return "XML Data"
	}
	if strings.Contains(contentType, "text/css") {
		return "CSS Stylesheet"
	}
	if strings.Contains(contentType, "application/javascript") || strings.Contains(contentType, "text/javascript") {
		return "JavaScript"
	}
	if strings.Contains(contentType, "image/") {
		return "Image"
	}
	if strings.Contains(contentType, "video/") {
		return "Video"
	}
	if strings.Contains(contentType, "application/pdf") {
		return "PDF Document"
	}

	return "Unknown"
}

// categorizeRequest categorizes HTTP requests
func (h *HTTPAnalyzer) categorizeRequest(request *HTTPRequest) string {
	// Check for API patterns
	if strings.Contains(request.URI, "/api/") {
		return "API Request"
	}

	// Check for static resources
	staticExtensions := []string{".css", ".js", ".png", ".jpg", ".gif", ".ico", ".woff"}
	for _, ext := range staticExtensions {
		if strings.HasSuffix(request.URI, ext) {
			return "Static Resource"
		}
	}

	// Check method types
	switch request.Method {
	case "GET":
		if strings.Contains(request.URI, "?") {
			return "GET with Parameters"
		}
		return "GET Request"
	case "POST":
		return "POST Request"
	case "PUT":
		return "PUT Request"
	case "DELETE":
		return "DELETE Request"
	case "HEAD":
		return "HEAD Request"
	case "OPTIONS":
		return "OPTIONS Request"
	}

	return "Unknown Request"
}

// categorizeStatusCode categorizes HTTP status codes
func (h *HTTPAnalyzer) categorizeStatusCode(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "Success"
	case statusCode >= 300 && statusCode < 400:
		return "Redirection"
	case statusCode >= 400 && statusCode < 500:
		return "Client Error"
	case statusCode >= 500 && statusCode < 600:
		return "Server Error"
	default:
		return "Unknown"
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
