package models

import "time"

// ProtocolType represents the type of proxy protocol
type ProtocolType string

const (
	ProtocolVMess      ProtocolType = "vmess"
	ProtocolVLESS      ProtocolType = "vless"
	ProtocolTrojan     ProtocolType = "trojan"
	ProtocolShadowsocks ProtocolType = "shadowsocks"
	ProtocolHysteria2  ProtocolType = "hysteria2"
	ProtocolTUIC       ProtocolType = "tuic"
	ProtocolSingBox    ProtocolType = "singbox"
)

// Protocol represents a parsed proxy configuration
type Protocol struct {
	Type     ProtocolType       `json:"type"`
	Name     string             `json:"name"`
	Server   string             `json:"server"`
	Port     int                `json:"port"`
	UUID     string             `json:"uuid,omitempty"`
	Password string             `json:"password,omitempty"`
	Network  string             `json:"network,omitempty"`
	TLS      bool               `json:"tls"`
	SNI      string             `json:"sni,omitempty"`
	Raw      string             `json:"raw"` // Original URL
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// TestResult contains all test results for a protocol
type TestResult struct {
	Protocol      *Protocol           `json:"protocol"`
	Timestamp     time.Time           `json:"timestamp"`
	Success       bool                `json:"success"`
	Error         string              `json:"error,omitempty"`
	Connectivity  *ConnectivityResult `json:"connectivity,omitempty"`
	Performance   *PerformanceResult  `json:"performance,omitempty"`
	GeoAccess     *GeoAccessResult    `json:"geo_access,omitempty"`
	DNS           *DNSResult          `json:"dns,omitempty"`
	Privacy       *PrivacyResult      `json:"privacy,omitempty"`
}

// ConnectivityResult represents basic connectivity test
type ConnectivityResult struct {
	Connected    bool          `json:"connected"`
	ResponseTime time.Duration `json:"response_time"`
	Error        string        `json:"error,omitempty"`
}

// PerformanceResult represents speed and latency tests
type PerformanceResult struct {
	Latency       time.Duration `json:"latency"`
	DownloadSpeed float64       `json:"download_speed_mbps"`
	UploadSpeed   float64       `json:"upload_speed_mbps"`
	Jitter        time.Duration `json:"jitter,omitempty"`
}

// GeoAccessResult represents geo-blocking tests
type GeoAccessResult struct {
	RU      map[string]AccessStatus `json:"ru"`
	CN      map[string]AccessStatus `json:"cn"`
	IR      map[string]AccessStatus `json:"ir"`
	US      map[string]AccessStatus `json:"us"`
	Custom  map[string]AccessStatus `json:"custom,omitempty"`
	Summary GeoAccessSummary        `json:"summary"`
}

// AccessStatus represents access status for a domain
type AccessStatus struct {
	Accessible bool          `json:"accessible"`
	StatusCode int           `json:"status_code,omitempty"`
	Latency    time.Duration `json:"latency"`
	Error      string        `json:"error,omitempty"`
}

// GeoAccessSummary provides a summary of geo-access results
type GeoAccessSummary struct {
	TotalTested      int `json:"total_tested"`
	TotalAccessible  int `json:"total_accessible"`
	TotalBlocked     int `json:"total_blocked"`
	AccessPercentage float64 `json:"access_percentage"`
}

// DNSResult represents DNS leak and blocking tests
type DNSResult struct {
	LeakDetection *DNSLeakResult    `json:"leak_detection"`
	Blocking      *DNSBlockingResult `json:"blocking"`
}

// DNSLeakResult represents DNS leak detection
type DNSLeakResult struct {
	IsLeaking       bool     `json:"is_leaking"`
	ExpectedCountry string   `json:"expected_country"`
	DetectedDNS     []string `json:"detected_dns"`
	LeakDetails     []string `json:"leak_details,omitempty"`
}

// DNSBlockingResult represents DNS blocking tests
type DNSBlockingResult struct {
	Ads      map[string]BlockStatus `json:"ads"`
	Tracking map[string]BlockStatus `json:"tracking"`
	Malware  map[string]BlockStatus `json:"malware,omitempty"`
	Summary  DNSBlockingSummary     `json:"summary"`
}

// BlockStatus represents whether a domain is blocked
type BlockStatus struct {
	Domain      string `json:"domain"`
	IsBlocked   bool   `json:"is_blocked"`
	BlockType   string `json:"block_type,omitempty"` // DNS, HTTP, HTTPS, None
	DNSResponse string `json:"dns_response,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
}

// DNSBlockingSummary provides summary of DNS blocking
type DNSBlockingSummary struct {
	TotalTested    int     `json:"total_tested"`
	TotalBlocked   int     `json:"total_blocked"`
	BlockPercentage float64 `json:"block_percentage"`
}

// PrivacyResult represents privacy and security tests
type PrivacyResult struct {
	DNSLeak    bool   `json:"dns_leak"`
	WebRTCLeak bool   `json:"webrtc_leak"`
	IPv6Leak   bool   `json:"ipv6_leak"`
	RealIP     string `json:"real_ip,omitempty"`
	ProxyIP    string `json:"proxy_ip,omitempty"`
	Exposed    []string `json:"exposed,omitempty"`
	Score      int    `json:"security_score"` // 0-100
}

// Subscription represents a parsed subscription
type Subscription struct {
	URL       string      `json:"url"`
	Protocols []*Protocol `json:"protocols"`
	ParsedAt  time.Time   `json:"parsed_at"`
}
