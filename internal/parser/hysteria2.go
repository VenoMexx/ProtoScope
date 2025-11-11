package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ParseHysteria2 parses a Hysteria2 URL
// Format: hysteria2://password@server:port?params#name
// Or: hy2://password@server:port?params#name
func ParseHysteria2(rawURL string) (*models.Protocol, error) {
	// Normalize URL
	rawURL = strings.ReplaceAll(rawURL, "hy2://", "hysteria2://")

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hysteria2 url: %w", err)
	}

	// Extract password from user info
	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("missing password in hysteria2 url")
	}

	// Extract server and port
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in hysteria2 url")
	}

	portStr := u.Port()
	if portStr == "" {
		portStr = "443" // Default port
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Extract name from fragment
	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	// Parse query parameters
	query := u.Query()
	sni := query.Get("sni")
	if sni == "" {
		sni = host
	}

	protocol := &models.Protocol{
		Type:     models.ProtocolHysteria2,
		Name:     name,
		Server:   host,
		Port:     port,
		Password: password,
		Network:  "udp", // Hysteria2 uses UDP
		TLS:      true,  // Hysteria2 always uses TLS
		SNI:      sni,
		Raw:      rawURL,
		Extra: map[string]interface{}{
			"obfs":         query.Get("obfs"),
			"obfs-password": query.Get("obfs-password"),
			"insecure":     query.Get("insecure"),
			"pinSHA256":    query.Get("pinSHA256"),
		},
	}

	return protocol, nil
}

// ParseTUIC parses a TUIC URL
// Format: tuic://uuid:password@server:port?params#name
func ParseTUIC(rawURL string) (*models.Protocol, error) {
	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tuic url: %w", err)
	}

	// Extract UUID and password from user info
	uuid := u.User.Username()
	password, _ := u.User.Password()
	if uuid == "" {
		return nil, fmt.Errorf("missing uuid in tuic url")
	}

	// Extract server and port
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in tuic url")
	}

	portStr := u.Port()
	if portStr == "" {
		portStr = "443" // Default port
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Extract name from fragment
	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	// Parse query parameters
	query := u.Query()
	sni := query.Get("sni")
	if sni == "" {
		sni = host
	}

	protocol := &models.Protocol{
		Type:     models.ProtocolTUIC,
		Name:     name,
		Server:   host,
		Port:     port,
		UUID:     uuid,
		Password: password,
		Network:  "udp", // TUIC uses UDP
		TLS:      true,  // TUIC always uses TLS
		SNI:      sni,
		Raw:      rawURL,
		Extra: map[string]interface{}{
			"congestion_control": query.Get("congestion_control"),
			"alpn":               query.Get("alpn"),
			"disable_sni":        query.Get("disable_sni"),
		},
	}

	return protocol, nil
}
