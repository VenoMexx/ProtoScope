package parser

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ParseVLESS parses a VLESS URL
// Format: vless://uuid@server:port?params#name
func ParseVLESS(rawURL string) (*models.Protocol, error) {
	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vless url: %w", err)
	}

	// Extract UUID from user info
	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("missing uuid in vless url")
	}

	// Extract server and port
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in vless url")
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
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}

	security := query.Get("security")
	tls := security == "tls" || security == "xtls" || security == "reality"

	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("peer")
	}

	protocol := &models.Protocol{
		Type:    models.ProtocolVLESS,
		Name:    name,
		Server:  host,
		Port:    port,
		UUID:    uuid,
		Network: network,
		TLS:     tls,
		SNI:     sni,
		Raw:     rawURL,
		Extra: map[string]interface{}{
			"security":  security,
			"flow":      query.Get("flow"),
			"encryption": query.Get("encryption"),
			"headerType": query.Get("headerType"),
			"host":      query.Get("host"),
			"path":      query.Get("path"),
		},
	}

	return protocol, nil
}
