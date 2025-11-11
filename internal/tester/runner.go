package tester

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/VenoMexx/ProtoScope/internal/checks"
	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// TestRunner orchestrates all tests for protocols
type TestRunner struct {
	config      *models.Config
	realIP      string
	concurrency int
}

// NewTestRunner creates a new test runner
func NewTestRunner(config *models.Config) *TestRunner {
	return &TestRunner{
		config:      config,
		concurrency: config.TestConfig.Concurrency,
	}
}

// RunTests runs all tests for the given protocols
func (tr *TestRunner) RunTests(ctx context.Context, protocols []*models.Protocol) ([]*models.TestResult, error) {
	return tr.runTests(ctx, protocols, nil, nil)
}

// RunTestsStream runs tests and invokes onResult for each completed protocol.
func (tr *TestRunner) RunTestsStream(ctx context.Context, protocols []*models.Protocol, onResult func(int, *models.TestResult)) ([]*models.TestResult, error) {
	return tr.runTests(ctx, protocols, onResult, nil)
}

// RunTestsStreamWithProgress runs tests and invokes onProgress for live updates and onResult for completed protocols.
func (tr *TestRunner) RunTestsStreamWithProgress(ctx context.Context, protocols []*models.Protocol, onProgress func(*models.TestProgress), onResult func(int, *models.TestResult)) ([]*models.TestResult, error) {
	return tr.runTests(ctx, protocols, onResult, onProgress)
}

func (tr *TestRunner) runTests(ctx context.Context, protocols []*models.Protocol, onResult func(int, *models.TestResult), onProgress func(*models.TestProgress)) ([]*models.TestResult, error) {
	// Get real IP first (without proxy)
	realIP, err := checks.GetRealIP(ctx)
	if err != nil {
		// Not fatal, continue without real IP
		realIP = ""
	}
	tr.realIP = realIP

	results := make([]*models.TestResult, len(protocols))

	// Use semaphore for concurrency control
	sem := make(chan struct{}, tr.concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, protocol := range protocols {
		wg.Add(1)
		go func(idx int, proto *models.Protocol) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create progress callback for this protocol
			var progressCallback func(stage, message string)
			if onProgress != nil {
				progressCallback = func(stage, message string) {
					onProgress(&models.TestProgress{
						ProtocolIndex:  idx,
						TotalProtocols: len(protocols),
						Protocol:       proto,
						Stage:          stage,
						Message:        message,
					})
				}
			}

			result := tr.testProtocol(ctx, proto, progressCallback)

			if onResult != nil {
				onResult(idx, result)
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, protocol)
	}

	wg.Wait()

	return results, nil
}

// testProtocol tests a single protocol
func (tr *TestRunner) testProtocol(ctx context.Context, protocol *models.Protocol, onProgress func(stage, message string)) *models.TestResult {
	result := &models.TestResult{
		Protocol:  protocol,
		Timestamp: time.Now(),
		Success:   false,
	}

	if onProgress != nil {
		onProgress("Starting", "Initializing proxy...")
	}

	// Create proxy manager with dynamic port
	socksPort := 10808 + (int(time.Now().UnixNano()) % 1000)
	proxyMgr := NewProxyManager(protocol, socksPort)

	// Start proxy
	proxyCtx, cancel := context.WithTimeout(ctx, tr.config.TestConfig.Timeout)
	defer cancel()

	if onProgress != nil {
		onProgress("Starting", "Starting proxy backend...")
	}

	if err := proxyMgr.Start(proxyCtx); err != nil {
		result.Error = fmt.Sprintf("Failed to start proxy: %v", err)
		result.ErrorDetails = proxyMgr.GetLastError(err)
		return result
	}
	defer proxyMgr.Stop()

	// Get HTTP client
	client, err := proxyMgr.GetHTTPClient(tr.config.TestConfig.Timeout)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create HTTP client: %v", err)
		result.ErrorDetails = proxyMgr.GetLastError(err)
		return result
	}

	// Run connectivity test
	if onProgress != nil {
		onProgress("Connectivity", "Testing connection...")
	}

	connectivityChecker := checks.NewConnectivityChecker(10 * time.Second)
	connectivityResult, err := connectivityChecker.CheckHTTP(proxyCtx, "http://www.gstatic.com/generate_204", client)
	if err != nil || !connectivityResult.Connected {
		result.Error = "Connectivity test failed"
		result.Connectivity = connectivityResult
		return result
	}
	result.Connectivity = connectivityResult
	result.Success = true

	// Run performance tests if enabled
	if tr.config.TestConfig.EnableSpeedTest {
		if onProgress != nil {
			onProgress("Performance", "Testing speed and latency...")
		}
		perfChecker := checks.NewPerformanceChecker(30 * time.Second)
		perfResult, err := perfChecker.Check(proxyCtx, client)
		if err == nil {
			result.Performance = perfResult
		}
	}

	// Run geo-access tests if enabled
	if tr.config.TestConfig.EnableGeoTest {
		if onProgress != nil {
			onProgress("GeoAccess", "Testing geo-restrictions...")
		}
		geoChecker := checks.NewGeoAccessChecker(10 * time.Second)
		geoResult, err := geoChecker.Check(proxyCtx, client)
		if err == nil {
			result.GeoAccess = geoResult
		}
	}

	// Run DNS tests if enabled
	if tr.config.TestConfig.EnableDNSTest {
		if onProgress != nil {
			onProgress("DNS", "Testing DNS leak and blocking...")
		}
		// Try to get expected country from geo result
		expectedCountry := ""
		if result.GeoAccess != nil {
			// Simple heuristic based on which regions are accessible
			if result.GeoAccess.Summary.AccessPercentage > 50 {
				expectedCountry = "US" // Assume US if most sites are accessible
			}
		}

		dnsChecker := checks.NewDNSChecker(10 * time.Second)
		dnsResult, err := dnsChecker.Check(proxyCtx, client, expectedCountry)
		if err == nil {
			result.DNS = dnsResult
		}
	}

	// Run privacy tests if enabled
	if tr.config.TestConfig.EnablePrivacyTest {
		if onProgress != nil {
			onProgress("Privacy", "Testing privacy and security...")
		}
		privacyChecker := checks.NewPrivacyChecker(tr.realIP)
		privacyResult, err := privacyChecker.Check(proxyCtx, client)
		if err == nil {
			result.Privacy = privacyResult
		}
	}

	if onProgress != nil {
		onProgress("Complete", "Test completed")
	}

	return result
}

// TestSingle tests a single protocol and returns the result
func (tr *TestRunner) TestSingle(ctx context.Context, protocol *models.Protocol) (*models.TestResult, error) {
	// Get real IP if not already set
	if tr.realIP == "" {
		realIP, err := checks.GetRealIP(ctx)
		if err == nil {
			tr.realIP = realIP
		}
	}

	result := tr.testProtocol(ctx, protocol, nil)
	return result, nil
}

// QuickTest performs only connectivity test
func (tr *TestRunner) QuickTest(ctx context.Context, protocol *models.Protocol) (*models.TestResult, error) {
	result := &models.TestResult{
		Protocol:  protocol,
		Timestamp: time.Now(),
		Success:   false,
	}

	// Create proxy manager
	socksPort := 10808 + (int(time.Now().UnixNano()) % 1000)
	proxyMgr := NewProxyManager(protocol, socksPort)

	// Start proxy
	proxyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := proxyMgr.Start(proxyCtx); err != nil {
		result.Error = fmt.Sprintf("Failed to start proxy: %v", err)
		result.ErrorDetails = proxyMgr.GetLastError(err)
		return result, nil
	}
	defer proxyMgr.Stop()

	// Get HTTP client
	client, err := proxyMgr.GetHTTPClient(10 * time.Second)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create HTTP client: %v", err)
		result.ErrorDetails = proxyMgr.GetLastError(err)
		return result, nil
	}

	// Run connectivity test only
	connectivityChecker := checks.NewConnectivityChecker(10 * time.Second)
	connectivityResult, err := connectivityChecker.CheckHTTP(proxyCtx, "http://www.gstatic.com/generate_204", client)
	if err != nil || !connectivityResult.Connected {
		result.Error = "Connectivity test failed"
		result.Connectivity = connectivityResult
		if err != nil {
			result.ErrorDetails = proxyMgr.GetLastError(err)
		}
		return result, nil
	}

	result.Connectivity = connectivityResult
	result.Success = true

	return result, nil
}
