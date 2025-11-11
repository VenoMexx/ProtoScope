package tester

import (
	"encoding/json"
)

// generateVMessOutbound generates VMess outbound configuration
func (pm *ProxyManager) generateVMessOutbound() (map[string]interface{}, error) {
	streamSettings := pm.generateStreamSettings()

	outbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": pm.protocol.Server,
					"port":    pm.protocol.Port,
					"users": []map[string]interface{}{
						{
							"id":       pm.protocol.UUID,
							"alterId":  0,
							"security": "auto",
						},
					},
				},
			},
		},
		"streamSettings": streamSettings,
	}

	return outbound, nil
}

// generateVLESSOutbound generates VLESS outbound configuration
func (pm *ProxyManager) generateVLESSOutbound() (map[string]interface{}, error) {
	streamSettings := pm.generateStreamSettings()

	encryption := "none"
	if extra, ok := pm.protocol.Extra["encryption"].(string); ok && extra != "" {
		encryption = extra
	}

	flow := ""
	if extra, ok := pm.protocol.Extra["flow"].(string); ok {
		flow = extra
	}

	user := map[string]interface{}{
		"id":         pm.protocol.UUID,
		"encryption": encryption,
	}
	if flow != "" {
		user["flow"] = flow
	}

	outbound := map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": pm.protocol.Server,
					"port":    pm.protocol.Port,
					"users":   []map[string]interface{}{user},
				},
			},
		},
		"streamSettings": streamSettings,
	}

	return outbound, nil
}

// generateTrojanOutbound generates Trojan outbound configuration
func (pm *ProxyManager) generateTrojanOutbound() (map[string]interface{}, error) {
	streamSettings := pm.generateStreamSettings()

	outbound := map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  pm.protocol.Server,
					"port":     pm.protocol.Port,
					"password": pm.protocol.Password,
				},
			},
		},
		"streamSettings": streamSettings,
	}

	return outbound, nil
}

// generateShadowsocksOutbound generates Shadowsocks outbound configuration
func (pm *ProxyManager) generateShadowsocksOutbound() (map[string]interface{}, error) {
	method := "aes-256-gcm"
	if extra, ok := pm.protocol.Extra["method"].(string); ok && extra != "" {
		method = extra
	}

	outbound := map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  pm.protocol.Server,
					"port":     pm.protocol.Port,
					"method":   method,
					"password": pm.protocol.Password,
				},
			},
		},
	}

	return outbound, nil
}

// generateStreamSettings generates stream settings for the outbound
func (pm *ProxyManager) generateStreamSettings() map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network": pm.protocol.Network,
	}

	// Add TLS settings if enabled
	if pm.protocol.TLS {
		tlsSettings := map[string]interface{}{
			"allowInsecure": false,
		}

		if pm.protocol.SNI != "" {
			tlsSettings["serverName"] = pm.protocol.SNI
		}

		// Check for reality or xtls
		if security, ok := pm.protocol.Extra["security"].(string); ok {
			switch security {
			case "reality":
				// Reality settings
				streamSettings["security"] = "reality"
				streamSettings["realitySettings"] = tlsSettings
			case "xtls":
				streamSettings["security"] = "xtls"
				streamSettings["xtlsSettings"] = tlsSettings
			default:
				streamSettings["security"] = "tls"
				streamSettings["tlsSettings"] = tlsSettings
			}
		} else {
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = tlsSettings
		}
	}

	// Add network-specific settings
	switch pm.protocol.Network {
	case "ws":
		wsSettings := map[string]interface{}{}
		if path, ok := pm.protocol.Extra["path"].(string); ok && path != "" {
			wsSettings["path"] = path
		}
		if host, ok := pm.protocol.Extra["host"].(string); ok && host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
		if len(wsSettings) > 0 {
			streamSettings["wsSettings"] = wsSettings
		}

	case "grpc":
		grpcSettings := map[string]interface{}{}
		if serviceName, ok := pm.protocol.Extra["serviceName"].(string); ok && serviceName != "" {
			grpcSettings["serviceName"] = serviceName
		}
		if len(grpcSettings) > 0 {
			streamSettings["grpcSettings"] = grpcSettings
		}

	case "h2", "http":
		httpSettings := map[string]interface{}{}
		if path, ok := pm.protocol.Extra["path"].(string); ok && path != "" {
			httpSettings["path"] = path
		}
		if host, ok := pm.protocol.Extra["host"].(string); ok && host != "" {
			httpSettings["host"] = []string{host}
		}
		if len(httpSettings) > 0 {
			streamSettings["httpSettings"] = httpSettings
		}

	case "quic":
		quicSettings := map[string]interface{}{
			"security": "none",
		}
		if headerType, ok := pm.protocol.Extra["headerType"].(string); ok && headerType != "" {
			quicSettings["header"] = map[string]interface{}{
				"type": headerType,
			}
		}
		streamSettings["quicSettings"] = quicSettings

	case "kcp":
		kcpSettings := map[string]interface{}{}
		if headerType, ok := pm.protocol.Extra["headerType"].(string); ok && headerType != "" {
			kcpSettings["header"] = map[string]interface{}{
				"type": headerType,
			}
		}
		if len(kcpSettings) > 0 {
			streamSettings["kcpSettings"] = kcpSettings
		}
	}

	return streamSettings
}

// GetXrayConfig returns the generated Xray config as JSON string for debugging
func (pm *ProxyManager) GetXrayConfig() (string, error) {
	config, err := pm.generateXrayConfig()
	if err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
