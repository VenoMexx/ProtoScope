package tester

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ProxyManagerV2 manages embedded sing-box proxy using JSON config
type ProxyManagerV2 struct {
	protocol     *models.Protocol
	box          *box.Box
	socksAddress string
	socksPort    int
	isRunning    bool
	verbose      bool
}

// NewProxyManagerV2 creates a new embedded proxy manager
func NewProxyManagerV2(protocol *models.Protocol, socksPort int) *ProxyManagerV2 {
	return &ProxyManagerV2{
		protocol:     protocol,
		socksAddress: "127.0.0.1",
		socksPort:    socksPort,
		isRunning:    false,
		verbose:      false,
	}
}

// SetVerbose enables verbose logging
func (pm *ProxyManagerV2) SetVerbose(verbose bool) {
	pm.verbose = verbose
}

// GetBackendLogs returns empty for embedded mode
func (pm *ProxyManagerV2) GetBackendLogs() string {
	return ""
}

// GetLastError returns a detailed error with diagnosis
func (pm *ProxyManagerV2) GetLastError(err error) *models.DetailedError {
	return models.AnalyzeError(err, "sing-box-embedded", "")
}

// Start starts the embedded sing-box proxy
func (pm *ProxyManagerV2) Start(ctx context.Context) error {
	// Generate JSON config
	config, err := pm.generateJSONConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Convert config to option.Options
	var opts option.Options
	if err := json.Unmarshal(config, &opts); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Create box instance with options
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		return fmt.Errorf("failed to create sing-box instance: %w", err)
	}
	pm.box = instance

	// Start the box
	if err := pm.box.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	// Wait for SOCKS5 server to be ready
	if err := pm.waitForProxy(ctx, 10*time.Second); err != nil {
		pm.Stop()
		return fmt.Errorf("proxy failed to start: %w", err)
	}

	pm.isRunning = true
	return nil
}

// Stop stops the embedded proxy
func (pm *ProxyManagerV2) Stop() error {
	if pm.box != nil {
		if err := pm.box.Close(); err != nil {
			return err
		}
	}
	pm.isRunning = false
	return nil
}

// GetHTTPClient returns an HTTP client configured to use the proxy
func (pm *ProxyManagerV2) GetHTTPClient(timeout time.Duration) (*http.Client, error) {
	if !pm.isRunning {
		return nil, fmt.Errorf("proxy is not running")
	}

	// Create SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp",
		fmt.Sprintf("%s:%d", pm.socksAddress, pm.socksPort),
		nil,
		proxy.Direct,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// Create HTTP transport
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// waitForProxy waits for the proxy to be ready
func (pm *ProxyManagerV2) waitForProxy(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", pm.socksAddress, pm.socksPort),
			1*time.Second,
		)
		if err == nil {
			conn.Close()
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for proxy to start")
}

// generateJSONConfig generates JSON config for sing-box
func (pm *ProxyManagerV2) generateJSONConfig() ([]byte, error) {
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
	}

	// Generate outbound based on protocol type
	var outbound map[string]interface{}
	var err error

	switch pm.protocol.Type {
	case models.ProtocolVMess:
		outbound, err = pm.generateVMessOutbound()
	case models.ProtocolVLESS:
		outbound, err = pm.generateVLESSOutbound()
	case models.ProtocolTrojan:
		outbound, err = pm.generateTrojanOutbound()
	case models.ProtocolShadowsocks:
		outbound, err = pm.generateShadowsocksOutbound()
	case models.ProtocolHysteria2:
		outbound, err = pm.generateHysteria2Outbound()
	case models.ProtocolTUIC:
		outbound, err = pm.generateTUICOutbound()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", pm.protocol.Type)
	}

	if err != nil {
		return nil, err
	}

	config["outbounds"] = []map[string]interface{}{outbound}

	return json.Marshal(config)
}

// Protocol-specific outbound generators
func (pm *ProxyManagerV2) generateVMessOutbound() (map[string]interface{}, error) {
	uuid := pm.protocol.UUID
	if uuid == "" {
		if pm.protocol.Extra != nil {
			if id, ok := pm.protocol.Extra["id"].(string); ok {
				uuid = id
			}
		}
	}

	return map[string]interface{}{
		"type": "vmess",
		"tag":  "proxy-out",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"uuid": uuid,
		"security": getStringFromMap(pm.protocol.Extra, "security", "auto"),
		"alter_id": getIntFromMap(pm.protocol.Extra, "alterId", 0),
	}, nil
}

func (pm *ProxyManagerV2) generateVLESSOutbound() (map[string]interface{}, error) {
	return map[string]interface{}{
		"type": "vless",
		"tag":  "proxy-out",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"uuid": pm.protocol.UUID,
		"flow": getStringFromMap(pm.protocol.Extra, "flow", ""),
	}, nil
}

func (pm *ProxyManagerV2) generateTrojanOutbound() (map[string]interface{}, error) {
	return map[string]interface{}{
		"type": "trojan",
		"tag":  "proxy-out",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"password": pm.protocol.Password,
	}, nil
}

func (pm *ProxyManagerV2) generateShadowsocksOutbound() (map[string]interface{}, error) {
	return map[string]interface{}{
		"type": "shadowsocks",
		"tag":  "proxy-out",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"method": getStringFromMap(pm.protocol.Extra, "method", "aes-256-gcm"),
		"password": pm.protocol.Password,
	}, nil
}

func (pm *ProxyManagerV2) generateHysteria2Outbound() (map[string]interface{}, error) {
	return map[string]interface{}{
		"type": "hysteria2",
		"tag":  "proxy-out",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"password": pm.protocol.Password,
	}, nil
}

func (pm *ProxyManagerV2) generateTUICOutbound() (map[string]interface{}, error) {
	return map[string]interface{}{
		"type": "tuic",
		"tag":  "proxy-out",
		"server": pm.protocol.Server,
		"server_port": pm.protocol.Port,
		"uuid": pm.protocol.UUID,
		"password": pm.protocol.Password,
	}, nil
}

// Helper functions
func getStringFromMap(m map[string]interface{}, key, defaultVal string) string {
	if m == nil {
		return defaultVal
	}
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultVal
}

func getIntFromMap(m map[string]interface{}, key string, defaultVal int) int {
	if m == nil {
		return defaultVal
	}
	if val, ok := m[key]; ok {
		if i, ok := val.(int); ok {
			return i
		}
		if f, ok := val.(float64); ok {
			return int(f)
		}
	}
	return defaultVal
}
