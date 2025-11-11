package checks

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/VenoMexx/ProtoScope/pkg/domains"
	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// GeoAccessChecker tests access to geo-specific domains
type GeoAccessChecker struct {
	timeout time.Duration
}

// NewGeoAccessChecker creates a new geo-access checker
func NewGeoAccessChecker(timeout time.Duration) *GeoAccessChecker {
	return &GeoAccessChecker{
		timeout: timeout,
	}
}

// Check performs geo-access tests for all regions
func (g *GeoAccessChecker) Check(ctx context.Context, client *http.Client) (*models.GeoAccessResult, error) {
	result := &models.GeoAccessResult{
		RU:     make(map[string]models.AccessStatus),
		CN:     make(map[string]models.AccessStatus),
		IR:     make(map[string]models.AccessStatus),
		US:     make(map[string]models.AccessStatus),
		Custom: make(map[string]models.AccessStatus),
	}

	// Test RU domains
	for _, domain := range domains.GeoDomainsRU {
		status := g.checkDomain(ctx, client, domain)
		result.RU[domain] = status
	}

	// Test CN domains
	for _, domain := range domains.GeoDomainsCN {
		status := g.checkDomain(ctx, client, domain)
		result.CN[domain] = status
	}

	// Test IR domains
	for _, domain := range domains.GeoDomainsIR {
		status := g.checkDomain(ctx, client, domain)
		result.IR[domain] = status
	}

	// Test US domains
	for _, domain := range domains.GeoDomainsUS {
		status := g.checkDomain(ctx, client, domain)
		result.US[domain] = status
	}

	// Calculate summary
	result.Summary = g.calculateSummary(result)

	return result, nil
}

// CheckCountry tests access to a specific country's domains
func (g *GeoAccessChecker) CheckCountry(ctx context.Context, client *http.Client, country string) (map[string]models.AccessStatus, error) {
	domainList := domains.GetGeoDomainsForCountry(country)
	if len(domainList) == 0 {
		return nil, fmt.Errorf("unknown country code: %s", country)
	}

	results := make(map[string]models.AccessStatus)
	for _, domain := range domainList {
		status := g.checkDomain(ctx, client, domain)
		results[domain] = status
	}

	return results, nil
}

// checkDomain checks access to a single domain
func (g *GeoAccessChecker) checkDomain(ctx context.Context, client *http.Client, domain string) models.AccessStatus {
	start := time.Now()

	// Try HTTPS first
	url := "https://" + domain
	status := g.tryURL(ctx, client, url)
	if status.Accessible {
		return status
	}

	// Try HTTP as fallback
	url = "http://" + domain
	status = g.tryURL(ctx, client, url)
	status.Latency = time.Since(start)

	return status
}

// tryURL attempts to access a URL
func (g *GeoAccessChecker) tryURL(ctx context.Context, client *http.Client, url string) models.AccessStatus {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.AccessStatus{
			Accessible: false,
			Latency:    time.Since(start),
			Error:      err.Error(),
		}
	}

	// Set timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	req = req.WithContext(timeoutCtx)

	resp, err := client.Do(req)
	if err != nil {
		return models.AccessStatus{
			Accessible: false,
			Latency:    time.Since(start),
			Error:      err.Error(),
		}
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	// Consider 2xx, 3xx, and even some 4xx as "accessible"
	// (4xx means we connected, just not authorized/not found)
	accessible := resp.StatusCode < 500

	return models.AccessStatus{
		Accessible: accessible,
		StatusCode: resp.StatusCode,
		Latency:    latency,
	}
}

// calculateSummary calculates summary statistics
func (g *GeoAccessChecker) calculateSummary(result *models.GeoAccessResult) models.GeoAccessSummary {
	total := 0
	accessible := 0

	// Count RU
	for _, status := range result.RU {
		total++
		if status.Accessible {
			accessible++
		}
	}

	// Count CN
	for _, status := range result.CN {
		total++
		if status.Accessible {
			accessible++
		}
	}

	// Count IR
	for _, status := range result.IR {
		total++
		if status.Accessible {
			accessible++
		}
	}

	// Count US
	for _, status := range result.US {
		total++
		if status.Accessible {
			accessible++
		}
	}

	// Count Custom
	for _, status := range result.Custom {
		total++
		if status.Accessible {
			accessible++
		}
	}

	blocked := total - accessible
	percentage := 0.0
	if total > 0 {
		percentage = float64(accessible) / float64(total) * 100.0
	}

	return models.GeoAccessSummary{
		TotalTested:      total,
		TotalAccessible:  accessible,
		TotalBlocked:     blocked,
		AccessPercentage: percentage,
	}
}
