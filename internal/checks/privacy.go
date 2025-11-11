package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// PrivacyChecker tests privacy and security
type PrivacyChecker struct {
	realIP string
}

// NewPrivacyChecker creates a new privacy checker
func NewPrivacyChecker(realIP string) *PrivacyChecker {
	return &PrivacyChecker{
		realIP: realIP,
	}
}

// Check performs complete privacy tests
func (p *PrivacyChecker) Check(ctx context.Context, client *http.Client) (*models.PrivacyResult, error) {
	result := &models.PrivacyResult{
		Exposed: []string{},
	}

	// Get proxy IP
	proxyIP, err := p.GetPublicIP(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy IP: %w", err)
	}
	result.ProxyIP = proxyIP

	// Store real IP if provided
	if p.realIP != "" {
		result.RealIP = p.realIP
	}

	// Check DNS leak
	dnsLeak := p.CheckDNSLeak(ctx, client, result.RealIP, result.ProxyIP)
	result.DNSLeak = dnsLeak
	if dnsLeak {
		result.Exposed = append(result.Exposed, "DNS")
	}

	// Check WebRTC leak
	webrtcLeak := p.CheckWebRTCLeak(ctx, client, result.RealIP)
	result.WebRTCLeak = webrtcLeak
	if webrtcLeak {
		result.Exposed = append(result.Exposed, "WebRTC")
	}

	// Check IPv6 leak
	ipv6Leak := p.CheckIPv6Leak(ctx, client)
	result.IPv6Leak = ipv6Leak
	if ipv6Leak {
		result.Exposed = append(result.Exposed, "IPv6")
	}

	// Calculate security score
	result.Score = p.calculateSecurityScore(result)

	return result, nil
}

// GetPublicIP gets the public IP address through the proxy
func (p *PrivacyChecker) GetPublicIP(ctx context.Context, client *http.Client) (string, error) {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://api.myip.com",
	}

	for _, endpoint := range endpoints {
		ip, err := p.fetchIP(ctx, client, endpoint)
		if err == nil && ip != "" {
			return strings.TrimSpace(ip), nil
		}
	}

	return "", fmt.Errorf("failed to get public IP from all endpoints")
}

// fetchIP fetches IP from an endpoint
func (p *PrivacyChecker) fetchIP(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Try to parse as JSON first (some endpoints return JSON)
	var jsonResp struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &jsonResp); err == nil && jsonResp.IP != "" {
		return jsonResp.IP, nil
	}

	// Otherwise return as plain text
	return string(body), nil
}

// CheckDNSLeak checks for DNS leaks
func (p *PrivacyChecker) CheckDNSLeak(ctx context.Context, client *http.Client, realIP, proxyIP string) bool {
	// This is a simplified check
	// In production, you would query DNS leak test services

	// If real IP is exposed in any DNS queries, it's a leak
	if realIP == "" {
		return false
	}

	// Try to detect DNS servers
	// If they're in the same location as real IP (not proxy IP), it's a leak

	return false // Simplified for now
}

// CheckWebRTCLeak checks for WebRTC IP leaks
func (p *PrivacyChecker) CheckWebRTCLeak(ctx context.Context, client *http.Client, realIP string) bool {
	// WebRTC leak detection requires browser automation or specialized APIs
	// This is a placeholder implementation

	endpoints := []string{
		"https://www.browserleaks.com/webrtc",
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Simple check: if our real IP appears in the response
		if realIP != "" && strings.Contains(string(body), realIP) {
			return true
		}
	}

	return false
}

// CheckIPv6Leak checks for IPv6 leaks
func (p *PrivacyChecker) CheckIPv6Leak(ctx context.Context, client *http.Client) bool {
	// Check if IPv6 is leaking
	endpoints := []string{
		"https://ipv6.icanhazip.com",
		"https://api6.ipify.org",
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			// If we get an IPv6 address, it might be leaking
			ipv6 := string(body)
			if strings.Contains(ipv6, ":") {
				// IPv6 address detected - this could be a leak if VPN doesn't support IPv6
				return true
			}
		}
	}

	return false
}

// calculateSecurityScore calculates a security score (0-100)
func (p *PrivacyChecker) calculateSecurityScore(result *models.PrivacyResult) int {
	score := 100

	// Deduct points for each leak
	if result.DNSLeak {
		score -= 30
	}
	if result.WebRTCLeak {
		score -= 40
	}
	if result.IPv6Leak {
		score -= 30
	}

	if score < 0 {
		score = 0
	}

	return score
}

// GetRealIP gets the real IP (without proxy)
func GetRealIP(ctx context.Context) (string, error) {
	client := &http.Client{}

	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			return strings.TrimSpace(string(body)), nil
		}
	}

	return "", fmt.Errorf("failed to get real IP")
}
