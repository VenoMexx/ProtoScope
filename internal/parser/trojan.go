package parser

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ParseTrojan parses a Trojan URL
// Format: trojan://password@server:port?params#name
func ParseTrojan(rawURL string) (*models.Protocol, error) {
	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trojan url: %w", err)
	}

	// Extract password from user info
	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("missing password in trojan url")
	}

	// Extract server and port
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in trojan url")
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
	tls := true // Trojan always uses TLS

	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("peer")
	}
	if sni == "" {
		sni = host
	}

	protocol := &models.Protocol{
		Type:     models.ProtocolTrojan,
		Name:     name,
		Server:   host,
		Port:     port,
		Password: password,
		Network:  network,
		TLS:      tls,
		SNI:      sni,
		Raw:      rawURL,
		Extra: map[string]interface{}{
			"security":   security,
			"headerType": query.Get("headerType"),
			"host":       query.Get("host"),
			"path":       query.Get("path"),
		},
	}

	return protocol, nil
}
