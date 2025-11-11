package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// PerformanceChecker tests latency and speed
type PerformanceChecker struct {
	timeout time.Duration
}

// NewPerformanceChecker creates a new performance checker
func NewPerformanceChecker(timeout time.Duration) *PerformanceChecker {
	return &PerformanceChecker{
		timeout: timeout,
	}
}

// Check performs complete performance test
func (p *PerformanceChecker) Check(ctx context.Context, client *http.Client) (*models.PerformanceResult, error) {
	result := &models.PerformanceResult{}

	// Measure latency
	latency, err := p.MeasureLatency(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("latency test failed: %w", err)
	}
	result.Latency = latency

	// Measure download speed
	downloadSpeed, err := p.MeasureDownloadSpeed(ctx, client)
	if err != nil {
		// Don't fail completely, just log
		downloadSpeed = 0
	}
	result.DownloadSpeed = downloadSpeed

	// Measure jitter (optional)
	jitter, _ := p.MeasureJitter(ctx, client, 3)
	result.Jitter = jitter

	return result, nil
}

// MeasureLatency measures latency to a test endpoint
func (p *PerformanceChecker) MeasureLatency(ctx context.Context, client *http.Client) (time.Duration, error) {
	testURLs := []string{
		"https://www.google.com",
		"https://www.cloudflare.com",
		"http://www.gstatic.com/generate_204",
	}

	var totalLatency time.Duration
	successCount := 0

	for _, url := range testURLs {
		start := time.Now()

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		latency := time.Since(start)
		totalLatency += latency
		successCount++

		if successCount >= 1 {
			break
		}
	}

	if successCount == 0 {
		return 0, fmt.Errorf("all latency tests failed")
	}

	return totalLatency / time.Duration(successCount), nil
}

// MeasureDownloadSpeed measures download speed
func (p *PerformanceChecker) MeasureDownloadSpeed(ctx context.Context, client *http.Client) (float64, error) {
	// Test file URLs (approximately 10MB)
	testURLs := []string{
		"https://speed.cloudflare.com/__down?bytes=10000000",
		"http://ipv4.download.thinkbroadband.com/10MB.zip",
	}

	for _, url := range testURLs {
		speed, err := p.downloadTest(ctx, client, url, 10*1024*1024)
		if err == nil {
			return speed, nil
		}
	}

	return 0, fmt.Errorf("all download tests failed")
}

// downloadTest performs a single download test
func (p *PerformanceChecker) downloadTest(ctx context.Context, client *http.Client, url string, expectedSize int64) (float64, error) {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Read and discard the body
	written, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return 0, err
	}

	elapsed := time.Since(start)

	// Calculate speed in Mbps
	bytes := float64(written)
	seconds := elapsed.Seconds()
	bitsPerSecond := (bytes * 8) / seconds
	mbps := bitsPerSecond / 1_000_000

	return mbps, nil
}

// MeasureJitter measures connection jitter
func (p *PerformanceChecker) MeasureJitter(ctx context.Context, client *http.Client, samples int) (time.Duration, error) {
	if samples < 2 {
		samples = 2
	}

	latencies := make([]time.Duration, 0, samples)

	for i := 0; i < samples; i++ {
		latency, err := p.MeasureLatency(ctx, client)
		if err != nil {
			continue
		}
		latencies = append(latencies, latency)
		time.Sleep(100 * time.Millisecond)
	}

	if len(latencies) < 2 {
		return 0, fmt.Errorf("insufficient samples for jitter calculation")
	}

	// Calculate jitter as average deviation
	var totalDiff time.Duration
	for i := 1; i < len(latencies); i++ {
		diff := latencies[i] - latencies[i-1]
		if diff < 0 {
			diff = -diff
		}
		totalDiff += diff
	}

	jitter := totalDiff / time.Duration(len(latencies)-1)
	return jitter, nil
}

// MeasureUploadSpeed measures upload speed (simplified)
func (p *PerformanceChecker) MeasureUploadSpeed(ctx context.Context, client *http.Client) (float64, error) {
	// This is a placeholder for upload speed testing
	// In a real implementation, you would upload data to a test server
	return 0, fmt.Errorf("upload speed test not implemented")
}
