package tester

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"golang.org/x/net/proxy"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ProxyManager manages proxy connections
type ProxyManager struct {
	protocol     *models.Protocol
	backend      ProxyBackend
	proxyCmd     *exec.Cmd
	socksAddress string
	socksPort    int
	configFile   string
	isRunning    bool
	stderrBuf    *bytes.Buffer
	stdoutBuf    *bytes.Buffer
	verbose      bool
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(protocol *models.Protocol, socksPort int) *ProxyManager {
	backend := SelectBackend(protocol)
	return &ProxyManager{
		protocol:     protocol,
		backend:      backend,
		socksAddress: "127.0.0.1",
		socksPort:    socksPort,
		isRunning:    false,
		stderrBuf:    &bytes.Buffer{},
		stdoutBuf:    &bytes.Buffer{},
		verbose:      false,
	}
}

// SetVerbose enables verbose logging
func (pm *ProxyManager) SetVerbose(verbose bool) {
	pm.verbose = verbose
}

// GetBackendLogs returns captured backend logs
func (pm *ProxyManager) GetBackendLogs() string {
	if pm.stderrBuf.Len() > 0 {
		return pm.stderrBuf.String()
	}
	if pm.stdoutBuf.Len() > 0 {
		return pm.stdoutBuf.String()
	}
	return ""
}

// GetLastError returns a detailed error with diagnosis
func (pm *ProxyManager) GetLastError(err error) *models.DetailedError {
	backendLogs := pm.GetBackendLogs()
	return models.AnalyzeError(err, string(pm.backend), backendLogs)
}

// Start starts the proxy
func (pm *ProxyManager) Start(ctx context.Context) error {
	// Check if backend is available
	if !IsBackendAvailable(pm.backend) {
		return fmt.Errorf("%s binary not found (please install %s)", pm.backend, pm.backend)
	}

	// Generate config based on backend
	var config map[string]interface{}
	var err error

	switch pm.backend {
	case BackendXray:
		config, err = pm.generateXrayConfig()
	case BackendSingbox:
		config, err = pm.generateSingboxConfig()
	default:
		return fmt.Errorf("unsupported backend: %s", pm.backend)
	}

	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Write config to temp file
	configFile, err := pm.writeConfigFile(config)
	if err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	pm.configFile = configFile

	// Get binary path
	binaryName := GetBackendBinary(pm.backend)
	binaryPath, err := exec.LookPath(binaryName)
	if err != nil {
		return fmt.Errorf("%s binary not found: %w", binaryName, err)
	}

	// Start proxy process
	var args []string
	switch pm.backend {
	case BackendXray:
		args = []string{"run", "-c", configFile}
	case BackendSingbox:
		args = []string{"run", "-c", configFile}
	}

	pm.proxyCmd = exec.CommandContext(ctx, binaryPath, args...)

	// Capture stdout and stderr for diagnostics
	if pm.verbose {
		// In verbose mode, show output to user as well
		pm.proxyCmd.Stdout = io.MultiWriter(pm.stdoutBuf, os.Stdout)
		pm.proxyCmd.Stderr = io.MultiWriter(pm.stderrBuf, os.Stderr)
	} else {
		// Otherwise just capture to buffer
		pm.proxyCmd.Stdout = pm.stdoutBuf
		pm.proxyCmd.Stderr = pm.stderrBuf
	}

	if err := pm.proxyCmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", pm.backend, err)
	}

	// Wait for proxy to be ready
	if err := pm.waitForProxy(ctx, 10*time.Second); err != nil {
		pm.Stop()
		return fmt.Errorf("proxy failed to start: %w", err)
	}

	pm.isRunning = true
	return nil
}

// Stop stops the proxy
func (pm *ProxyManager) Stop() error {
	if pm.proxyCmd != nil && pm.proxyCmd.Process != nil {
		pm.proxyCmd.Process.Kill()
		pm.proxyCmd.Wait()
	}

	if pm.configFile != "" {
		os.Remove(pm.configFile)
	}

	pm.isRunning = false
	return nil
}

// GetHTTPClient returns an HTTP client configured to use the proxy
func (pm *ProxyManager) GetHTTPClient(timeout time.Duration) (*http.Client, error) {
	if !pm.isRunning {
		return nil, fmt.Errorf("proxy is not running")
	}

	// Create SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp",
		fmt.Sprintf("%s:%d", pm.socksAddress, pm.socksPort),
		nil, // No auth
		proxy.Direct,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// Create HTTP transport with SOCKS5 proxy
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return client, nil
}

// GetDialer returns a proxy dialer
func (pm *ProxyManager) GetDialer() (proxy.Dialer, error) {
	if !pm.isRunning {
		return nil, fmt.Errorf("proxy is not running")
	}

	dialer, err := proxy.SOCKS5("tcp",
		fmt.Sprintf("%s:%d", pm.socksAddress, pm.socksPort),
		nil,
		proxy.Direct,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	return dialer, nil
}

// waitForProxy waits for the proxy to be ready
func (pm *ProxyManager) waitForProxy(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try to connect to SOCKS5 port
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

// writeConfigFile writes config to a temporary file
func (pm *ProxyManager) writeConfigFile(config map[string]interface{}) (string, error) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	tmpFile, err := os.CreateTemp("", "xray-config-*.json")
	if err != nil {
		return "", err
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	tmpFile.Close()
	return tmpFile.Name(), nil
}

// generateXrayConfig generates Xray configuration
func (pm *ProxyManager) generateXrayConfig() (map[string]interface{}, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     pm.socksPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"udp": true,
				},
				"listen": pm.socksAddress,
			},
		},
		"outbounds": []map[string]interface{}{},
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
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", pm.protocol.Type)
	}

	if err != nil {
		return nil, err
	}

	config["outbounds"] = []map[string]interface{}{outbound}

	return config, nil
}

// Protocol-specific outbound generators will be implemented in separate files
