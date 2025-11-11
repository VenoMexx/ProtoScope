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
func SelectBackend(protocol *models.Protocol) ProxyBackend {
	switch protocol.Type {
	case models.ProtocolHysteria2, models.ProtocolTUIC:
		// Use sing-box for protocols not supported by Xray
		return BackendSingbox
	case models.ProtocolVMess, models.ProtocolVLESS, models.ProtocolTrojan, models.ProtocolShadowsocks:
		// Use Xray for traditional protocols
		return BackendXray
	default:
		// Default to Xray
		return BackendXray
	}
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
