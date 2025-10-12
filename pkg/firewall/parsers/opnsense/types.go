package opnsense

// OPNsenseConfig represents the root structure of an OPNsense configuration XML
type OPNsenseConfig struct {
	XMLName    struct{}   `xml:"opnsense"`
	Interfaces Interfaces `xml:"interfaces"`
	Filter     Filter     `xml:"filter"`
	System     System     `xml:"system"`
	Aliases    Aliases    `xml:"aliases"`
}

// Interfaces contains all network interface configurations
// OPNsense uses named interfaces, not a slice
type Interfaces struct {
	WAN       *Interface `xml:"wan"`
	LAN       *Interface `xml:"lan"`
	OPT1      *Interface `xml:"opt1"`
	OPT2      *Interface `xml:"opt2"`
	OPT3      *Interface `xml:"opt3"`
	OPT4      *Interface `xml:"opt4"`
	OPT5      *Interface `xml:"opt5"`
	Loopback  *Interface `xml:"lo0"`
	WireGuard *Interface `xml:"wireguard"`
}

// Interface represents a single network interface configuration
type Interface struct {
	Enable      string `xml:"enable"`
	If          string `xml:"if"`               // Physical interface name (igb0, igb1, etc.)
	Descr       string `xml:"descr"`            // Description
	IPAddr      string `xml:"ipaddr"`           // IP address or "dhcp"
	Subnet      string `xml:"subnet"`           // Subnet mask in CIDR notation
	IPAddrV6    string `xml:"ipaddrv6"`         // IPv6 address
	SubnetV6    string `xml:"subnetv6"`         // IPv6 subnet
	Gateway     string `xml:"gateway"`          // Gateway
	BlockBogons string `xml:"blockbogons"`      // Block bogon networks
	Type        string `xml:"type"`             // Interface type
	Virtual     string `xml:"virtual"`          // Virtual interface flag
	Internal    string `xml:"internal_dynamic"` // Internal dynamic flag
	MTU         string `xml:"mtu"`              // MTU size
	Lock        string `xml:"lock"`             // Interface lock status
}

// Filter contains firewall filtering rules directly (not nested in Rules)
type Filter struct {
	Rules []Rule `xml:"rule"`
}

// Rule represents a single firewall rule with UUID
type Rule struct {
	UUID        string      `xml:"uuid,attr"`   // Rule UUID
	Type        string      `xml:"type"`        // pass, block, reject
	Interface   string      `xml:"interface"`   // Interface name
	IPProtocol  string      `xml:"ipprotocol"`  // inet, inet6
	StateType   string      `xml:"statetype"`   // keep state, etc.
	Direction   string      `xml:"direction"`   // in, out
	Floating    string      `xml:"floating"`    // yes/no for floating rules
	Quick       string      `xml:"quick"`       // 1 for quick rules
	Gateway     string      `xml:"gateway"`     // Gateway name
	Tagged      string      `xml:"tagged"`      // Tag name
	Source      RuleTarget  `xml:"source"`      // Source specification
	Destination RuleTarget  `xml:"destination"` // Destination specification
	Protocol    string      `xml:"protocol"`    // tcp, udp, icmp, any
	SrcPort     string      `xml:"srcport"`     // Source port(s)
	DstPort     string      `xml:"dstport"`     // Destination port(s)
	Descr       string      `xml:"descr"`       // Rule description
	Updated     RuleHistory `xml:"updated"`     // Last update info
	Created     RuleHistory `xml:"created"`     // Creation info
}

// RuleTarget represents source or destination in a firewall rule
type RuleTarget struct {
	Any     string `xml:"any"`     // 1 for "any"
	Network string `xml:"network"` // Network identifier (lan, wan, opt1, opt5ip, etc.)
	Not     string `xml:"not"`     // 1 for negation
}

// RuleHistory tracks rule modification history
type RuleHistory struct {
	Username    string `xml:"username"`
	Time        string `xml:"time"`
	Description string `xml:"description"`
}

// System contains system-wide configuration
type System struct {
	Hostname  string   `xml:"hostname"`
	Domain    string   `xml:"domain"`
	DNSServer []string `xml:"dnsserver"`
	Timezone  string   `xml:"timezone"`
}

// Aliases contains network, host, and port aliases
type Aliases struct {
	Alias []Alias `xml:"alias"`
}

// Alias represents a single alias definition
type Alias struct {
	Name    string `xml:"name"`
	Type    string `xml:"type"`    // network, host, port
	Address string `xml:"address"` // The actual value(s)
	Descr   string `xml:"descr"`   // Description
}

// Helper method to get all interfaces as a slice for easier iteration
func (i *Interfaces) GetAllInterfaces() map[string]*Interface {
	result := make(map[string]*Interface)

	if i.WAN != nil {
		result["wan"] = i.WAN
	}
	if i.LAN != nil {
		result["lan"] = i.LAN
	}
	if i.OPT1 != nil {
		result["opt1"] = i.OPT1
	}
	if i.OPT2 != nil {
		result["opt2"] = i.OPT2
	}
	if i.OPT3 != nil {
		result["opt3"] = i.OPT3
	}
	if i.OPT4 != nil {
		result["opt4"] = i.OPT4
	}
	if i.OPT5 != nil {
		result["opt5"] = i.OPT5
	}
	if i.Loopback != nil {
		result["lo0"] = i.Loopback
	}
	if i.WireGuard != nil {
		result["wireguard"] = i.WireGuard
	}

	return result
}

// Additional helper structures for parsing complex rule elements

// PortRange represents a port range specification
type PortRange struct {
	From uint16
	To   uint16
}

// NetworkAddress represents various network address formats
type NetworkAddress struct {
	Type    string // "single", "network", "range", "alias"
	Address string
	Mask    string
}

// RuleTracker helps track rule relationships and dependencies
type RuleTracker struct {
	RuleID       string
	Interfaces   []string
	Dependencies []string
	Aliases      []string
}
