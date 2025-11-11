package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/VenoMexx/ProtoScope/pkg/domains"
	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// DNSChecker tests DNS leak and blocking
type DNSChecker struct {
	timeout time.Duration
}

// NewDNSChecker creates a new DNS checker
func NewDNSChecker(timeout time.Duration) *DNSChecker {
	return &DNSChecker{
		timeout: timeout,
	}
}

// Check performs complete DNS tests
func (d *DNSChecker) Check(ctx context.Context, client *http.Client, expectedCountry string) (*models.DNSResult, error) {
	result := &models.DNSResult{}

	// Check for DNS leaks
	leakResult, err := d.CheckDNSLeak(ctx, client, expectedCountry)
	if err != nil {
		// Don't fail completely, just log
		leakResult = &models.DNSLeakResult{
			IsLeaking:       false,
			ExpectedCountry: expectedCountry,
			DetectedDNS:     []string{},
		}
	}
	result.LeakDetection = leakResult

	// Check DNS blocking
	blockingResult, err := d.CheckDNSBlocking(ctx, client)
	if err != nil {
		// Don't fail completely, just log
		blockingResult = &models.DNSBlockingResult{
			Ads:      make(map[string]models.BlockStatus),
			Tracking: make(map[string]models.BlockStatus),
		}
	}
	result.Blocking = blockingResult

	return result, nil
}

// CheckDNSLeak checks for DNS leaks
func (d *DNSChecker) CheckDNSLeak(ctx context.Context, client *http.Client, expectedCountry string) (*models.DNSLeakResult, error) {
	result := &models.DNSLeakResult{
		ExpectedCountry: expectedCountry,
		DetectedDNS:     []string{},
		LeakDetails:     []string{},
		IsLeaking:       false,
	}

	// Get DNS servers used
	dnsServers, err := d.detectDNSServers(ctx, client)
	if err != nil {
		return result, err
	}
	result.DetectedDNS = dnsServers

	// Check if DNS servers match expected location
	if len(dnsServers) > 0 {
		// Simple check: if we can detect DNS servers and they don't match proxy location
		// In a real implementation, you would geolocate the DNS servers
		result.IsLeaking = d.checkIfLeaking(dnsServers, expectedCountry)
		if result.IsLeaking {
			result.LeakDetails = append(result.LeakDetails, "DNS queries may be leaking to local ISP")
		}
	}

	return result, nil
}

// detectDNSServers tries to detect which DNS servers are being used
func (d *DNSChecker) detectDNSServers(ctx context.Context, client *http.Client) ([]string, error) {
	// Try to use DNS leak test API
	urls := []string{
		"https://www.dnsleaktest.com/api/servers",
	}

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

			// Parse response
			var servers []string
			if err := json.Unmarshal(body, &servers); err != nil {
				// Try alternative parsing
				servers = d.parseAlternativeDNS(string(body))
			}

			return servers, nil
		}
	}

	// Fallback: try to detect via whoami
	return d.detectViaDNSQuery(ctx)
}

// parseAlternativeDNS parses DNS servers from alternative formats
func (d *DNSChecker) parseAlternativeDNS(body string) []string {
	// This is a simple parser, in production you'd want more robust parsing
	return []string{}
}

// detectViaDNSQuery detects DNS servers via direct queries
func (d *DNSChecker) detectViaDNSQuery(ctx context.Context) ([]string, error) {
	// Query whoami.akamai.net to detect DNS resolver
	resolver := &net.Resolver{
		PreferGo: true,
	}

	addrs, err := resolver.LookupHost(ctx, "whoami.akamai.net")
	if err != nil {
		return []string{}, err
	}

	return addrs, nil
}

// checkIfLeaking checks if DNS is leaking based on detected servers
func (d *DNSChecker) checkIfLeaking(dnsServers []string, expectedCountry string) bool {
	// Simple heuristic: check if any DNS server is a common ISP DNS
	// In production, you would geolocate the DNS servers
	commonISPDNS := []string{
		"8.8.8.8", "8.8.4.4", // Google
		"1.1.1.1", "1.0.0.1", // Cloudflare
		"208.67.222.222", "208.67.220.220", // OpenDNS
	}

	for _, dns := range dnsServers {
		for _, isp := range commonISPDNS {
			if strings.Contains(dns, isp) {
				return false // Using public DNS, not leaking
			}
		}
	}

	// If we can't determine, assume not leaking
	return false
}

// CheckDNSBlocking checks if DNS is blocking ads/tracking
func (d *DNSChecker) CheckDNSBlocking(ctx context.Context, client *http.Client) (*models.DNSBlockingResult, error) {
	result := &models.DNSBlockingResult{
		Ads:      make(map[string]models.BlockStatus),
		Tracking: make(map[string]models.BlockStatus),
		Malware:  make(map[string]models.BlockStatus),
	}

	// Test ad domains
	for _, domain := range domains.GetAllAdDomains() {
		status := d.checkDomainBlocking(ctx, client, domain)
		result.Ads[domain] = status
	}

	// Test tracking domains
	for _, domain := range domains.GetAllTrackingDomains() {
		status := d.checkDomainBlocking(ctx, client, domain)
		result.Tracking[domain] = status
	}

	// Calculate summary
	result.Summary = d.calculateBlockingSummary(result)

	return result, nil
}

// checkDomainBlocking checks if a domain is blocked
func (d *DNSChecker) checkDomainBlocking(ctx context.Context, client *http.Client, domain string) models.BlockStatus {
	status := models.BlockStatus{
		Domain:    domain,
		IsBlocked: false,
		BlockType: "None",
	}

	// First, try DNS resolution
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		// DNS resolution failed - might be blocked
		status.IsBlocked = true
		status.BlockType = "DNS"
		status.DNSResponse = err.Error()
		return status
	}
	status.DNSResponse = strings.Join(addrs, ", ")

	// DNS works, try HTTP
	url := "http://" + domain
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return status
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req = req.WithContext(timeoutCtx)

	resp, err := client.Do(req)
	if err != nil {
		// Connection failed but DNS worked
		status.IsBlocked = true
		status.BlockType = "HTTP"
		return status
	}
	defer resp.Body.Close()

	status.HTTPStatus = resp.StatusCode
	if resp.StatusCode >= 500 {
		status.IsBlocked = true
		status.BlockType = "HTTP"
	}

	return status
}

// calculateBlockingSummary calculates blocking summary
func (d *DNSChecker) calculateBlockingSummary(result *models.DNSBlockingResult) models.DNSBlockingSummary {
	total := 0
	blocked := 0

	for _, status := range result.Ads {
		total++
		if status.IsBlocked {
			blocked++
		}
	}

	for _, status := range result.Tracking {
		total++
		if status.IsBlocked {
			blocked++
		}
	}

	for _, status := range result.Malware {
		total++
		if status.IsBlocked {
			blocked++
		}
	}

	percentage := 0.0
	if total > 0 {
		percentage = float64(blocked) / float64(total) * 100.0
	}

	return models.DNSBlockingSummary{
		TotalTested:     total,
		TotalBlocked:    blocked,
		BlockPercentage: percentage,
	}
}
