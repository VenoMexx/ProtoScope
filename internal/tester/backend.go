package tester

import (
	"os/exec"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ProxyBackend represents the backend type for proxy
type ProxyBackend string

const (
	// BackendXray uses Xray-core
	BackendXray ProxyBackend = "xray"
	// BackendSingbox uses sing-box
	BackendSingbox ProxyBackend = "sing-box"
)

// SelectBackend selects the appropriate backend for a protocol
// Currently always returns Sing-box as it supports all protocols
func SelectBackend(protocol *models.Protocol) ProxyBackend {
	// Sing-box supports all protocols:
	// - VMess, VLESS, Trojan, Shadowsocks (traditional)
	// - Hysteria2, TUIC (modern QUIC-based)
	// - And more!
	return BackendSingbox
}

// IsBackendAvailable checks if a backend binary is available
func IsBackendAvailable(backend ProxyBackend) bool {
	var binaryName string
	switch backend {
	case BackendXray:
		binaryName = "xray"
	case BackendSingbox:
		binaryName = "sing-box"
	default:
		return false
	}

	// Check if binary exists in PATH
	_, err := exec.LookPath(binaryName)
	return err == nil
}

// GetBackendBinary returns the binary name for a backend
func GetBackendBinary(backend ProxyBackend) string {
	switch backend {
	case BackendXray:
		return "xray"
	case BackendSingbox:
		return "sing-box"
	default:
		return ""
	}
}
