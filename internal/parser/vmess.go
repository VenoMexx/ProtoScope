package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// VMessConfig represents VMess configuration
type VMessConfig struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	AID  string `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
}

// ParseVMess parses a VMess URL
func ParseVMess(url string) (*models.Protocol, error) {
	// Remove vmess:// prefix
	encoded := strings.TrimPrefix(url, "vmess://")

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			// Try raw base64
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("failed to decode vmess: %w", err)
			}
		}
	}

	// Parse JSON
	var config VMessConfig
	if err := json.Unmarshal(decoded, &config); err != nil {
		return nil, fmt.Errorf("failed to parse vmess config: %w", err)
	}

	// Convert port to int
	port, err := strconv.Atoi(config.Port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	protocol := &models.Protocol{
		Type:     models.ProtocolVMess,
		Name:     config.PS,
		Server:   config.Add,
		Port:     port,
		UUID:     config.ID,
		Network:  config.Net,
		TLS:      config.TLS == "tls",
		SNI:      config.SNI,
		Raw:      url,
		Extra: map[string]interface{}{
			"aid":  config.AID,
			"host": config.Host,
			"path": config.Path,
			"type": config.Type,
		},
	}

	return protocol, nil
}
