package tester

import (
	"encoding/json"
	"fmt"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// generateSingboxConfig generates sing-box configuration
func (pm *ProxyManager) generateSingboxConfig() (map[string]interface{}, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "error",
		},
		"inbounds": []map[string]interface{}{
			{
				"type":   "socks",
				"tag":    "socks-in",
				"listen": pm.socksAddress,
				"listen_port": pm.socksPort,
			},
		},
		"outbounds": []map[string]interface{}{},
	}

	// Generate outbound based on protocol type
	var outbound map[string]interface{}
	var err error

	switch pm.protocol.Type {
	case models.ProtocolHysteria2:
		outbound, err = pm.generateHysteria2Outbound()
	case models.ProtocolTUIC:
		outbound, err = pm.generateTUICOutbound()
	case models.ProtocolVMess:
		outbound, err = pm.generateSingboxVMessOutbound()
	case models.ProtocolVLESS:
		outbound, err = pm.generateSingboxVLESSOutbound()
	case models.ProtocolTrojan:
		outbound, err = pm.generateSingboxTrojanOutbound()
	case models.ProtocolShadowsocks:
		outbound, err = pm.generateSingboxShadowsocksOutbound()
	default:
		return nil, fmt.Errorf("unsupported protocol for sing-box: %s", pm.protocol.Type)
	}

	if err != nil {
		return nil, err
	}

	config["outbounds"] = []map[string]interface{}{outbound}

	return config, nil
}

// generateHysteria2Outbound generates Hysteria2 outbound for sing-box
func (pm *ProxyManager) generateHysteria2Outbound() (map[string]interface{}, error) {
	outbound := map[string]interface{}{
		"type":   "hysteria2",
		"tag":    "proxy",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"password": pm.protocol.Password,
	}

	// Add TLS settings
	if pm.protocol.TLS || pm.protocol.SNI != "" {
		tls := map[string]interface{}{
			"enabled": true,
		}
		if pm.protocol.SNI != "" {
			tls["server_name"] = pm.protocol.SNI
		}
		// Hysteria2 often uses self-signed certs
		tls["insecure"] = true

		// Add ALPN to TLS if present
		if alpn, ok := pm.protocol.Extra["alpn"].(string); ok && alpn != "" {
			tls["alpn"] = []string{alpn}
		}

		outbound["tls"] = tls
	}

	// Add obfs if present
	if obfs, ok := pm.protocol.Extra["obfs"].(string); ok && obfs != "" {
		obfsPassword := ""
		if obfsPwd, ok := pm.protocol.Extra["obfs-password"].(string); ok {
			obfsPassword = obfsPwd
		}
		outbound["obfs"] = map[string]interface{}{
			"type":     obfs,
			"password": obfsPassword,
		}
	}

	return outbound, nil
}

// generateTUICOutbound generates TUIC outbound for sing-box
func (pm *ProxyManager) generateTUICOutbound() (map[string]interface{}, error) {
	outbound := map[string]interface{}{
		"type":        "tuic",
		"tag":         "proxy",
		"server":      pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"uuid":        pm.protocol.UUID,
		"password":    pm.protocol.Password,
	}

	// Add TLS settings
	tls := map[string]interface{}{
		"enabled": true,
	}
	if pm.protocol.SNI != "" {
		tls["server_name"] = pm.protocol.SNI
	}

	// Add ALPN to TLS (not root level!)
	if alpn, ok := pm.protocol.Extra["alpn"].(string); ok && alpn != "" {
		tls["alpn"] = []string{alpn}
	}

	outbound["tls"] = tls

	// Add congestion control if present
	if cc, ok := pm.protocol.Extra["congestion_control"].(string); ok && cc != "" {
		outbound["congestion_control"] = cc
	}

	return outbound, nil
}

// generateSingboxVMessOutbound generates VMess outbound for sing-box
func (pm *ProxyManager) generateSingboxVMessOutbound() (map[string]interface{}, error) {
	outbound := map[string]interface{}{
		"type":        "vmess",
		"tag":         "proxy",
		"server":      pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"uuid":        pm.protocol.UUID,
		"security":    "auto",
		"alter_id":    0,
	}

	// Add transport settings
	if pm.protocol.Network != "" && pm.protocol.Network != "tcp" {
		transport := map[string]interface{}{
			"type": pm.protocol.Network,
		}

		switch pm.protocol.Network {
		case "ws":
			if path, ok := pm.protocol.Extra["path"].(string); ok {
				transport["path"] = path
			}
			if host, ok := pm.protocol.Extra["host"].(string); ok {
				transport["headers"] = map[string]interface{}{
					"Host": host,
				}
			}
		case "grpc":
			if serviceName, ok := pm.protocol.Extra["serviceName"].(string); ok {
				transport["service_name"] = serviceName
			}
		}

		outbound["transport"] = transport
	}

	// Add TLS settings
	if pm.protocol.TLS {
		tls := map[string]interface{}{
			"enabled": true,
		}
		if pm.protocol.SNI != "" {
			tls["server_name"] = pm.protocol.SNI
		}

		// Add uTLS if fingerprint specified (optional for VMess)
		if fp, ok := pm.protocol.Extra["fp"].(string); ok && fp != "" {
			tls["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": fp,
			}
		} else if fp, ok := pm.protocol.Extra["fingerprint"].(string); ok && fp != "" {
			tls["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": fp,
			}
		}

		outbound["tls"] = tls
	}

	return outbound, nil
}

// generateSingboxVLESSOutbound generates VLESS outbound for sing-box
func (pm *ProxyManager) generateSingboxVLESSOutbound() (map[string]interface{}, error) {
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         "proxy",
		"server":      pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"uuid":        pm.protocol.UUID,
	}

	// Add flow if present
	if flow, ok := pm.protocol.Extra["flow"].(string); ok && flow != "" {
		outbound["flow"] = flow
	}

	// Add transport settings
	if pm.protocol.Network != "" && pm.protocol.Network != "tcp" {
		transport := map[string]interface{}{
			"type": pm.protocol.Network,
		}

		switch pm.protocol.Network {
		case "ws":
			if path, ok := pm.protocol.Extra["path"].(string); ok {
				transport["path"] = path
			}
			if host, ok := pm.protocol.Extra["host"].(string); ok {
				transport["headers"] = map[string]interface{}{
					"Host": host,
				}
			}
		case "grpc":
			if serviceName, ok := pm.protocol.Extra["serviceName"].(string); ok {
				transport["service_name"] = serviceName
			}
		}

		outbound["transport"] = transport
	}

	// Add TLS settings
	if pm.protocol.TLS {
		tls := map[string]interface{}{
			"enabled": true,
		}
		if pm.protocol.SNI != "" {
			tls["server_name"] = pm.protocol.SNI
		}

		// Check for REALITY
		if security, ok := pm.protocol.Extra["security"].(string); ok && security == "reality" {
			reality := map[string]interface{}{
				"enabled": true,
			}

			// Add public key
			if publicKey, ok := pm.protocol.Extra["pbk"].(string); ok && publicKey != "" {
				reality["public_key"] = publicKey
			} else if publicKey, ok := pm.protocol.Extra["public_key"].(string); ok && publicKey != "" {
				reality["public_key"] = publicKey
			}

			// Add short ID
			if shortID, ok := pm.protocol.Extra["sid"].(string); ok && shortID != "" {
				reality["short_id"] = shortID
			} else if shortID, ok := pm.protocol.Extra["short_id"].(string); ok && shortID != "" {
				reality["short_id"] = shortID
			}

			tls["reality"] = reality

			// CRITICAL: uTLS is REQUIRED for REALITY
			utls := map[string]interface{}{
				"enabled": true,
			}

			// Add fingerprint (chrome is most common)
			fingerprint := "chrome"
			if fp, ok := pm.protocol.Extra["fp"].(string); ok && fp != "" {
				fingerprint = fp
			} else if fp, ok := pm.protocol.Extra["fingerprint"].(string); ok && fp != "" {
				fingerprint = fp
			}
			utls["fingerprint"] = fingerprint

			tls["utls"] = utls
		}

		outbound["tls"] = tls
	}

	return outbound, nil
}

// generateSingboxTrojanOutbound generates Trojan outbound for sing-box
func (pm *ProxyManager) generateSingboxTrojanOutbound() (map[string]interface{}, error) {
	outbound := map[string]interface{}{
		"type":        "trojan",
		"tag":         "proxy",
		"server":      pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"password":    pm.protocol.Password,
	}

	// Add TLS settings (Trojan always uses TLS)
	tls := map[string]interface{}{
		"enabled": true,
	}
	if pm.protocol.SNI != "" {
		tls["server_name"] = pm.protocol.SNI
	}

	// Add uTLS if fingerprint specified (optional for Trojan)
	if fp, ok := pm.protocol.Extra["fp"].(string); ok && fp != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	} else if fp, ok := pm.protocol.Extra["fingerprint"].(string); ok && fp != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	}

	outbound["tls"] = tls

	// Add transport settings
	if pm.protocol.Network != "" && pm.protocol.Network != "tcp" {
		transport := map[string]interface{}{
			"type": pm.protocol.Network,
		}

		switch pm.protocol.Network {
		case "ws":
			if path, ok := pm.protocol.Extra["path"].(string); ok {
				transport["path"] = path
			}
			if host, ok := pm.protocol.Extra["host"].(string); ok {
				transport["headers"] = map[string]interface{}{
					"Host": host,
				}
			}
		case "grpc":
			if serviceName, ok := pm.protocol.Extra["serviceName"].(string); ok {
				transport["service_name"] = serviceName
			}
		}

		outbound["transport"] = transport
	}

	return outbound, nil
}

// generateSingboxShadowsocksOutbound generates Shadowsocks outbound for sing-box
func (pm *ProxyManager) generateSingboxShadowsocksOutbound() (map[string]interface{}, error) {
	method := "aes-256-gcm"
	if extra, ok := pm.protocol.Extra["method"].(string); ok && extra != "" {
		method = extra
	}

	outbound := map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         "proxy",
		"server":      pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"method":      method,
		"password":    pm.protocol.Password,
	}

	return outbound, nil
}

// GetSingboxConfig returns the generated sing-box config as JSON string for debugging
func (pm *ProxyManager) GetSingboxConfig() (string, error) {
	config, err := pm.generateSingboxConfig()
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
