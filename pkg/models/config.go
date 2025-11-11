package models

import "time"

// Config represents the application configuration
type Config struct {
	TestConfig    TestConfig    `yaml:"test_config" json:"test_config"`
	DomainLists   DomainLists   `yaml:"domain_lists" json:"domain_lists"`
	APIEndpoints  APIEndpoints  `yaml:"api_endpoints" json:"api_endpoints"`
	OutputConfig  OutputConfig  `yaml:"output_config" json:"output_config"`
}

// TestConfig contains test execution settings
type TestConfig struct {
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`
	Concurrency     int           `yaml:"concurrency" json:"concurrency"`
	RetryAttempts   int           `yaml:"retry_attempts" json:"retry_attempts"`
	EnableSpeedTest bool          `yaml:"enable_speed_test" json:"enable_speed_test"`
	EnableGeoTest   bool          `yaml:"enable_geo_test" json:"enable_geo_test"`
	EnableDNSTest   bool          `yaml:"enable_dns_test" json:"enable_dns_test"`
	EnablePrivacyTest bool        `yaml:"enable_privacy_test" json:"enable_privacy_test"`
}

// DomainLists contains domain lists for testing
type DomainLists struct {
	RU       []string `yaml:"ru" json:"ru"`
	CN       []string `yaml:"cn" json:"cn"`
	IR       []string `yaml:"ir" json:"ir"`
	US       []string `yaml:"us" json:"us"`
	Ads      []string `yaml:"ads" json:"ads"`
	Tracking []string `yaml:"tracking" json:"tracking"`
	Custom   []string `yaml:"custom" json:"custom"`
}

// APIEndpoints contains external API endpoints
type APIEndpoints struct {
	IPCheck      []string `yaml:"ip_check" json:"ip_check"`
	DNSLeak      []string `yaml:"dns_leak" json:"dns_leak"`
	SpeedTest    []string `yaml:"speed_test" json:"speed_test"`
	GeoLocation  []string `yaml:"geo_location" json:"geo_location"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	Format      string `yaml:"format" json:"format"` // json, markdown, html
	OutputPath  string `yaml:"output_path" json:"output_path"`
	Verbose     bool   `yaml:"verbose" json:"verbose"`
	ShowSuccess bool   `yaml:"show_success" json:"show_success"`
	ShowFailed  bool   `yaml:"show_failed" json:"show_failed"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		TestConfig: TestConfig{
			Timeout:           30 * time.Second,
			Concurrency:       5,
			RetryAttempts:     2,
			EnableSpeedTest:   true,
			EnableGeoTest:     true,
			EnableDNSTest:     true,
			EnablePrivacyTest: true,
		},
		DomainLists: DomainLists{
			RU: []string{
				"vk.com",
				"yandex.ru",
				"rt.com",
				"mail.ru",
			},
			CN: []string{
				"baidu.com",
				"weibo.com",
				"qq.com",
				"taobao.com",
			},
			IR: []string{
				"isna.ir",
				"farsnews.ir",
				"tasnimnews.com",
			},
			US: []string{
				"google.com",
				"twitter.com",
				"facebook.com",
				"youtube.com",
			},
			Ads: []string{
				"googleadservices.com",
				"doubleclick.net",
				"adservice.google.com",
				"googlesyndication.com",
			},
			Tracking: []string{
				"google-analytics.com",
				"facebook.com/tr",
				"scorecardresearch.com",
			},
		},
		APIEndpoints: APIEndpoints{
			IPCheck: []string{
				"https://api.ipify.org",
				"https://ifconfig.me/ip",
				"https://icanhazip.com",
			},
			DNSLeak: []string{
				"https://www.dnsleaktest.com",
			},
			SpeedTest: []string{
				"https://speed.cloudflare.com/__down?bytes=10000000",
			},
			GeoLocation: []string{
				"http://ip-api.com/json/",
			},
		},
		OutputConfig: OutputConfig{
			Format:      "console",
			Verbose:     false,
			ShowSuccess: true,
			ShowFailed:  true,
		},
	}
}
