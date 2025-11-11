package models

import "strings"

// ErrorType represents the type of error encountered
type ErrorType string

const (
	ErrorTypeBackendNotFound   ErrorType = "backend_not_found"
	ErrorTypeConfigGeneration  ErrorType = "config_generation"
	ErrorTypeProxyStartFailed  ErrorType = "proxy_start_failed"
	ErrorTypeProxyTimeout      ErrorType = "proxy_timeout"
	ErrorTypeConnectivity      ErrorType = "connectivity"
	ErrorTypeDNS               ErrorType = "dns"
	ErrorTypeAuthentication    ErrorType = "authentication"
	ErrorTypeSSLHandshake      ErrorType = "ssl_handshake"
	ErrorTypeNetworkUnreachable ErrorType = "network_unreachable"
	ErrorTypePortConflict      ErrorType = "port_conflict"
	ErrorTypeUnknown           ErrorType = "unknown"
)

// DetailedError provides detailed error information
type DetailedError struct {
	Type         ErrorType `json:"type"`
	Message      string    `json:"message"`
	Details      string    `json:"details,omitempty"`
	Backend      string    `json:"backend,omitempty"`
	Suggestion   string    `json:"suggestion,omitempty"`
	BackendLog   string    `json:"backend_log,omitempty"`
}

// GetTroubleshootingSuggestion returns a helpful suggestion based on error type
func (e *DetailedError) GetTroubleshootingSuggestion() string {
	if e.Suggestion != "" {
		return e.Suggestion
	}

	switch e.Type {
	case ErrorTypeBackendNotFound:
		return "Install the required backend (xray or sing-box). See README for installation instructions."

	case ErrorTypeConfigGeneration:
		return "Check if the protocol configuration is valid. The protocol URL may be malformed."

	case ErrorTypeProxyStartFailed:
		return "Check if the port is already in use. Try running with different port or stop other proxies."

	case ErrorTypeProxyTimeout:
		return "The proxy took too long to start. This might be a network issue or invalid server address."

	case ErrorTypeConnectivity:
		return "Cannot connect to the proxy server. Check if the server is online and accessible."

	case ErrorTypeDNS:
		return "DNS resolution failed. Check your internet connection or try a different DNS server."

	case ErrorTypeAuthentication:
		return "Authentication failed. The password/UUID might be incorrect or the server rejected the connection."

	case ErrorTypeSSLHandshake:
		return "SSL/TLS handshake failed. The server certificate might be invalid or SNI is incorrect."

	case ErrorTypeNetworkUnreachable:
		return "Network unreachable. Check your internet connection or firewall settings."

	case ErrorTypePortConflict:
		return "Port is already in use. Close other applications using the same port or try a different port."

	default:
		return "Check the error details and backend logs for more information. Try with -verbose flag."
	}
}

// AnalyzeError analyzes an error and returns a detailed error
func AnalyzeError(err error, backend string, backendLog string) *DetailedError {
	if err == nil {
		return nil
	}

	errMsg := err.Error()
	detailedErr := &DetailedError{
		Message:    errMsg,
		Backend:    backend,
		BackendLog: backendLog,
	}

	// Analyze error message to determine type
	switch {
	case strings.Contains(errMsg, "binary not found"), strings.Contains(errMsg, "executable file not found"):
		detailedErr.Type = ErrorTypeBackendNotFound
		detailedErr.Details = "The required backend binary is not installed or not in PATH"

	case strings.Contains(errMsg, "failed to generate config"):
		detailedErr.Type = ErrorTypeConfigGeneration
		detailedErr.Details = "Could not generate proxy configuration"

	case strings.Contains(errMsg, "address already in use"), strings.Contains(errMsg, "bind"):
		detailedErr.Type = ErrorTypePortConflict
		detailedErr.Details = "The SOCKS5 port is already in use by another application"

	case strings.Contains(errMsg, "timeout"), strings.Contains(errMsg, "deadline exceeded"):
		detailedErr.Type = ErrorTypeProxyTimeout
		detailedErr.Details = "Operation timed out while waiting for proxy"

	case strings.Contains(errMsg, "connection refused"):
		detailedErr.Type = ErrorTypeConnectivity
		detailedErr.Details = "Server refused the connection"

	case strings.Contains(errMsg, "no such host"), strings.Contains(errMsg, "dns"):
		detailedErr.Type = ErrorTypeDNS
		detailedErr.Details = "Could not resolve server hostname"

	case strings.Contains(errMsg, "authentication failed"), strings.Contains(errMsg, "invalid credentials"):
		detailedErr.Type = ErrorTypeAuthentication
		detailedErr.Details = "Server rejected authentication"

	case strings.Contains(errMsg, "tls"), strings.Contains(errMsg, "certificate"), strings.Contains(errMsg, "handshake"):
		detailedErr.Type = ErrorTypeSSLHandshake
		detailedErr.Details = "TLS/SSL handshake failed"

	case strings.Contains(errMsg, "network is unreachable"):
		detailedErr.Type = ErrorTypeNetworkUnreachable
		detailedErr.Details = "Cannot reach the network"

	case strings.Contains(errMsg, "failed to start"):
		detailedErr.Type = ErrorTypeProxyStartFailed
		detailedErr.Details = "Backend process failed to start"

	default:
		detailedErr.Type = ErrorTypeUnknown
		detailedErr.Details = "Unknown error occurred"
	}

	// Analyze backend logs for additional context
	if backendLog != "" {
		detailedErr.Details += "\n" + analyzeBackendLog(backendLog)
	}

	// Set suggestion
	detailedErr.Suggestion = detailedErr.GetTroubleshootingSuggestion()

	return detailedErr
}

// analyzeBackendLog extracts useful information from backend logs
func analyzeBackendLog(log string) string {
	log = strings.ToLower(log)

	var findings []string

	if strings.Contains(log, "permission denied") {
		findings = append(findings, "Permission denied - may need elevated privileges")
	}
	if strings.Contains(log, "invalid config") {
		findings = append(findings, "Invalid configuration detected")
	}
	if strings.Contains(log, "failed to dial") {
		findings = append(findings, "Failed to connect to remote server")
	}
	if strings.Contains(log, "rejected") {
		findings = append(findings, "Connection rejected by server")
	}

	if len(findings) > 0 {
		return "Backend reported: " + strings.Join(findings, "; ")
	}

	return ""
}
