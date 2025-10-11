package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Online OUI lookup services
type OUILookupService struct {
	cache    map[string]string
	cacheMu  sync.RWMutex
	cacheDir string
}

var ouiService *OUILookupService
var ouiOnce sync.Once

// Initialize OUI service singleton
func getOUIService() *OUILookupService {
	ouiOnce.Do(func() {
		cacheDir := filepath.Join(".", ".oui_cache")
		os.MkdirAll(cacheDir, 0755)

		ouiService = &OUILookupService{
			cache:    make(map[string]string),
			cacheDir: cacheDir,
		}

		// Load cached OUI database on startup
		ouiService.loadCachedOUI()
	})
	return ouiService
}

// lookupOUI returns vendor name from MAC address using multiple online sources
func lookupOUI(mac string) string {
	if len(mac) < 8 {
		return ""
	}

	// Extract first 3 bytes (OUI)
	oui := strings.ToUpper(mac[:8])
	oui = strings.ReplaceAll(oui, ":", "")

	service := getOUIService()

	// Check cache first
	if vendor := service.getCached(oui); vendor != "" {
		return vendor
	}

	// Try online lookups
	vendor := service.lookupOnline(oui)
	if vendor != "" {
		service.setCached(oui, vendor)
		return vendor
	}

	// Fallback to critical industrial vendors (minimal list)
	return service.getFallbackVendor(oui)
}

// getCached retrieves vendor from local cache
func (s *OUILookupService) getCached(oui string) string {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.cache[oui]
}

// setCached stores vendor in local cache
func (s *OUILookupService) setCached(oui, vendor string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache[oui] = vendor
}

// lookupOnline tries multiple online OUI databases
func (s *OUILookupService) lookupOnline(oui string) string {
	// Try multiple services in order of preference
	services := []func(string) string{
		s.lookupMacVendors,
		s.lookupIEEE,
		s.lookupWireshark,
	}

	for _, lookup := range services {
		if vendor := lookup(oui); vendor != "" {
			return vendor
		}
	}

	return ""
}

// lookupMacVendors uses macvendors.com API (with rate limiting)
func (s *OUILookupService) lookupMacVendors(oui string) string {
	client := &http.Client{Timeout: 3 * time.Second} // Reduced timeout

	// Format MAC for API (need full MAC, use zeros for last 3 bytes)
	macForAPI := fmt.Sprintf("%s:%s:%s:00:00:00", oui[:2], oui[2:4], oui[4:6])

	url := fmt.Sprintf("https://api.macvendors.com/%s", macForAPI)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 { // Rate limited
		return ""
	}
	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	vendor := strings.TrimSpace(string(body))
	if vendor == "Not Found" || vendor == "" {
		return ""
	}

	return s.cleanVendorName(vendor)
}

// lookupIEEE downloads and parses IEEE OUI registry
func (s *OUILookupService) lookupIEEE(oui string) string {
	// Try to load from cached IEEE database
	ieeeFile := filepath.Join(s.cacheDir, "ieee_oui.txt")

	// Download IEEE database if not cached or old
	if s.shouldUpdateIEEEDatabase(ieeeFile) {
		s.downloadIEEEDatabase(ieeeFile)
	}

	return s.searchIEEEDatabase(ieeeFile, oui)
}

// lookupWireshark uses Wireshark's manuf database format (cached)
func (s *OUILookupService) lookupWireshark(oui string) string {
	// Use cached Wireshark database instead of downloading every time
	wiresharkFile := filepath.Join(s.cacheDir, "wireshark_manuf.txt")

	// Download if not cached or old (weekly refresh)
	if s.shouldUpdateDatabase(wiresharkFile, 7*24*time.Hour) {
		s.downloadWiresharkDatabase(wiresharkFile)
	}

	return s.searchWiresharkDatabase(wiresharkFile, oui)
}

// downloadIEEEDatabase downloads the official IEEE OUI registry
func (s *OUILookupService) downloadIEEEDatabase(filename string) {
	client := &http.Client{Timeout: 30 * time.Second}

	url := "http://standards-oui.ieee.org/oui/oui.txt"
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	io.Copy(file, resp.Body)
}

// searchIEEEDatabase searches the downloaded IEEE database
func (s *OUILookupService) searchIEEEDatabase(filename, oui string) string {
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ouiPattern := regexp.MustCompile(`([A-F0-9]{2}-[A-F0-9]{2}-[A-F0-9]{2})\s+\(hex\)\s+(.+)`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := ouiPattern.FindStringSubmatch(line)
		if len(matches) == 3 {
			dbOUI := strings.ReplaceAll(matches[1], "-", "")
			if dbOUI == oui {
				return s.cleanVendorName(matches[2])
			}
		}
	}

	return ""
}

// shouldUpdateDatabase checks if database needs updating (generic)
func (s *OUILookupService) shouldUpdateDatabase(filename string, maxAge time.Duration) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return true // File doesn't exist
	}
	return time.Since(info.ModTime()) > maxAge
}

// shouldUpdateIEEEDatabase checks if IEEE database needs updating
func (s *OUILookupService) shouldUpdateIEEEDatabase(filename string) bool {
	return s.shouldUpdateDatabase(filename, 7*24*time.Hour)
}

// downloadWiresharkDatabase downloads Wireshark's manuf database
func (s *OUILookupService) downloadWiresharkDatabase(filename string) {
	client := &http.Client{Timeout: 15 * time.Second}

	url := "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	io.Copy(file, resp.Body)
}

// searchWiresharkDatabase searches the cached Wireshark database
func (s *OUILookupService) searchWiresharkDatabase(filename, oui string) string {
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			dbOUI := strings.ReplaceAll(strings.ToUpper(parts[0]), ":", "")
			if strings.HasPrefix(dbOUI, oui) {
				return s.cleanVendorName(strings.Join(parts[1:], " "))
			}
		}
	}

	return ""
}

// loadCachedOUI loads previously cached OUI lookups
func (s *OUILookupService) loadCachedOUI() {
	cacheFile := filepath.Join(s.cacheDir, "oui_cache.json")

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return
	}

	var cache map[string]string
	if err := json.Unmarshal(data, &cache); err != nil {
		return
	}

	s.cacheMu.Lock()
	s.cache = cache
	s.cacheMu.Unlock()
}

// saveCachedOUI saves OUI cache to disk
func (s *OUILookupService) saveCachedOUI() {
	cacheFile := filepath.Join(s.cacheDir, "oui_cache.json")

	s.cacheMu.RLock()
	data, err := json.MarshalIndent(s.cache, "", "  ")
	s.cacheMu.RUnlock()

	if err != nil {
		return
	}

	os.WriteFile(cacheFile, data, 0644)
}

// cleanVendorName standardizes vendor names
func (s *OUILookupService) cleanVendorName(vendor string) string {
	vendor = strings.TrimSpace(vendor)

	// Common cleanups
	vendor = strings.ReplaceAll(vendor, "Inc.", "")
	vendor = strings.ReplaceAll(vendor, "Corp.", "")
	vendor = strings.ReplaceAll(vendor, "Corporation", "")
	vendor = strings.ReplaceAll(vendor, "Company", "Co.")
	vendor = strings.ReplaceAll(vendor, "Limited", "Ltd.")
	vendor = strings.TrimSpace(vendor)

	// Standardize industrial vendors
	if strings.Contains(strings.ToLower(vendor), "rockwell") ||
		strings.Contains(strings.ToLower(vendor), "allen") {
		return "Rockwell Automation"
	}
	if strings.Contains(strings.ToLower(vendor), "schneider") {
		return "Schneider Electric"
	}
	if strings.Contains(strings.ToLower(vendor), "mitsubishi") {
		return "Mitsubishi Electric"
	}

	return vendor
}

// getFallbackVendor provides critical industrial vendors as fallback
func (s *OUILookupService) getFallbackVendor(oui string) string {
	// Minimal critical industrial OUI list for offline fallback
	fallbacks := map[string]string{
		"000E8C": "Rockwell Automation", // Allen-Bradley
		"0000BC": "Allen-Bradley",
		"080006": "Siemens",
		"001B1B": "Siemens",
		"00507F": "Schneider Electric",
		"000C7C": "Omron",
		"00037F": "Mitsubishi Electric",
		"006065": "ABB",
		"000E0C": "Beckhoff",
	}

	return fallbacks[oui]
}

// SaveOUICache saves the current cache (call this on program exit)
func SaveOUICache() {
	if ouiService != nil {
		ouiService.saveCachedOUI()
	}
}

// resolveHostname attempts to resolve IP to hostname
func resolveHostname(ip string) string {
	if parsedIP := net.ParseIP(ip); parsedIP != nil {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			hostname := names[0]
			// Clean up hostname (remove trailing dot, shorten long names)
			hostname = strings.TrimSuffix(hostname, ".")
			if strings.Contains(hostname, ".") {
				parts := strings.Split(hostname, ".")
				hostname = parts[0] // Use just the host part
			}
			// Limit length for display
			if len(hostname) > 15 {
				hostname = hostname[:12] + "..."
			}
			return hostname
		}
	}
	return ""
}

// detectDeviceName attempts to identify device from vendor, protocols, and roles
func detectDeviceName(host *Host) string {
	// Start with vendor-specific naming
	vendor := host.Vendor
	if vendor == "" {
		vendor = "Industrial"
	}

	// Determine device type from protocols and communication patterns
	deviceType := ""

	// Check for specific protocol patterns that indicate device types
	if host.ReceivedCounts[ProtoENIP_Explicit] > 0 && host.InitiatedCounts[ProtoENIP_Implicit] > 0 {
		deviceType = "PLC"
	} else if host.InitiatedCounts[ProtoENIP_Explicit] > 2 && host.ITScore > 0 {
		deviceType = "HMI"
	} else if host.ReceivedCounts[ProtoModbus] > host.InitiatedCounts[ProtoModbus] {
		deviceType = "PLC"
	} else if host.InitiatedCounts[ProtoModbus] > host.ReceivedCounts[ProtoModbus] {
		deviceType = "HMI/SCADA"
	} else if host.ReceivedCounts[ProtoS7Comm] > 0 {
		deviceType = "PLC"
	} else if host.PortsSeen[2222] && host.MulticastPeer {
		deviceType = "I/O Device"
	} else if host.ITScore > host.ICSScore && host.ITScore > 0 {
		deviceType = "Server"
	} else if host.ICSScore > 0 {
		deviceType = "Device"
	}

	// Combine vendor and device type
	if deviceType != "" {
		if vendor != "Industrial" {
			return vendor + " " + deviceType
		} else {
			return deviceType
		}
	}

	// Fallback to vendor only
	if vendor != "Industrial" {
		return vendor + " Device"
	}

	return ""
}

func isMulticastIP(ip net.IP) bool {
	return ip != nil && ip.IsMulticast()
}

// isPrivateIP checks if an IP is in a private/internal range
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// RFC 1918 private networks
	private10 := net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	private172 := net.IPNet{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)}
	private192 := net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)}

	return private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip)
}
