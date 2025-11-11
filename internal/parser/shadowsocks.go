package parser

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ParseShadowsocks parses a Shadowsocks URL
// Format: ss://base64(method:password)@server:port#name
// Or: ss://base64(method:password@server:port)#name
func ParseShadowsocks(rawURL string) (*models.Protocol, error) {
	// Remove ss:// prefix
	content := strings.TrimPrefix(rawURL, "ss://")

	// Split by # to get name
	parts := strings.SplitN(content, "#", 2)
	encoded := parts[0]
	name := ""
	if len(parts) == 2 {
		name, _ = url.QueryUnescape(parts[1])
	}

	// Try to decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("failed to decode shadowsocks: %w", err)
			}
		}
	}

	decodedStr := string(decoded)

	// Parse decoded string
	var method, password, server string
	var port int

	if strings.Contains(decodedStr, "@") {
		// Format: method:password@server:port
		atIndex := strings.LastIndex(decodedStr, "@")
		userInfo := decodedStr[:atIndex]
		serverInfo := decodedStr[atIndex+1:]

		// Parse user info
		colonIndex := strings.Index(userInfo, ":")
		if colonIndex == -1 {
			return nil, fmt.Errorf("invalid shadowsocks format")
		}
		method = userInfo[:colonIndex]
		password = userInfo[colonIndex+1:]

		// Parse server info
		colonIndex = strings.LastIndex(serverInfo, ":")
		if colonIndex == -1 {
			return nil, fmt.Errorf("invalid shadowsocks format")
		}
		server = serverInfo[:colonIndex]
		portStr := serverInfo[colonIndex+1:]
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported shadowsocks format")
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	protocol := &models.Protocol{
		Type:     models.ProtocolShadowsocks,
		Name:     name,
		Server:   server,
		Port:     port,
		Password: password,
		Network:  "tcp",
		TLS:      false,
		Raw:      rawURL,
		Extra: map[string]interface{}{
			"method": method,
		},
	}

	return protocol, nil
}
