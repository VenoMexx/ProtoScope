package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/VenoMexx/ProtoScope/internal/parser"
	"github.com/VenoMexx/ProtoScope/internal/tester"
	"github.com/VenoMexx/ProtoScope/pkg/models"
)

var (
	subscriptionURL = flag.String("url", "", "Subscription URL to test")
	outputFormat    = flag.String("format", "console", "Output format (console, json, markdown)")
	timeout         = flag.Duration("timeout", 30*time.Second, "Timeout for each test")
	concurrency     = flag.Int("concurrent", 3, "Number of concurrent tests")
	quickMode       = flag.Bool("quick", false, "Quick mode (connectivity only)")
	verbose         = flag.Bool("verbose", false, "Verbose output")
	noSpeedTest     = flag.Bool("no-speed", false, "Disable speed tests")
	noGeoTest       = flag.Bool("no-geo", false, "Disable geo-access tests")
	noDNSTest       = flag.Bool("no-dns", false, "Disable DNS tests")
	noPrivacyTest   = flag.Bool("no-privacy", false, "Disable privacy tests")
)

func main() {
	flag.Parse()

	if *subscriptionURL == "" {
		fmt.Println("ProtoScope - Protocol Security Tester")
		fmt.Println("Usage: protoscope -url <subscription-url>")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx := context.Background()

	// Parse subscription
	fmt.Println("ProtoScope v0.2.0 - Protocol Security Tester")
	fmt.Println("===========================================")
	fmt.Println()
	fmt.Printf("📡 Fetching subscription from: %s\n", *subscriptionURL)

	decoder := parser.NewDecoder()
	subscription, err := decoder.DecodeSubscription(*subscriptionURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: Failed to decode subscription: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Found %d protocols\n", len(subscription.Protocols))
	if len(subscription.Protocols) == 0 {
		fmt.Println("No protocols found in subscription")
		os.Exit(0)
	}
	fmt.Println()

	// Create test configuration
	config := createConfig()

	// Create test runner
	runner := tester.NewTestRunner(config)

	var results []*models.TestResult

	if *quickMode {
		fmt.Println("🚀 Running quick connectivity tests...")
		fmt.Println()
		results = runQuickTests(ctx, runner, subscription.Protocols)
	} else {
		fmt.Println("🔍 Running comprehensive tests...")
		fmt.Println()
		results = runFullTests(ctx, runner, subscription.Protocols)
	}

	// Output results
	fmt.Println()
	switch *outputFormat {
	case "json":
		outputJSON(results)
	case "markdown":
		outputMarkdown(results)
	default:
		outputConsole(results)
	}
}

// createConfig creates test configuration from flags
func createConfig() *models.Config {
	config := models.DefaultConfig()

	config.TestConfig.Timeout = *timeout
	config.TestConfig.Concurrency = *concurrency
	config.TestConfig.EnableSpeedTest = !*noSpeedTest && !*quickMode
	config.TestConfig.EnableGeoTest = !*noGeoTest && !*quickMode
	config.TestConfig.EnableDNSTest = !*noDNSTest && !*quickMode
	config.TestConfig.EnablePrivacyTest = !*noPrivacyTest && !*quickMode

	return config
}

// runQuickTests runs quick connectivity tests
func runQuickTests(ctx context.Context, runner *tester.TestRunner, protocols []*models.Protocol) []*models.TestResult {
	results := make([]*models.TestResult, 0, len(protocols))

	for i, protocol := range protocols {
		fmt.Printf("[%d/%d] Testing: %s [%s]\n", i+1, len(protocols), protocol.Name, protocol.Type)
		fmt.Printf("       Server: %s:%d\n", protocol.Server, protocol.Port)

		result, err := runner.QuickTest(ctx, protocol)
		if err != nil {
			fmt.Printf("       ❌ Error: %v\n\n", err)
			continue
		}

		if result.Success {
			fmt.Printf("       ✓ Connected (%dms)\n\n", result.Connectivity.ResponseTime.Milliseconds())
		} else {
			// Check if it's an unsupported protocol error
			if strings.Contains(result.Error, "not yet supported") {
				fmt.Printf("       ⚠ Skipped: %s\n\n", result.Error)
			} else {
				fmt.Printf("       ✗ Failed: %s\n\n", result.Error)
			}
		}

		results = append(results, result)
	}

	return results
}

// runFullTests runs comprehensive tests
func runFullTests(ctx context.Context, runner *tester.TestRunner, protocols []*models.Protocol) []*models.TestResult {
	results, err := runner.RunTests(ctx, protocols)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error running tests: %v\n", err)
		os.Exit(1)
	}

	// Print results as they come
	for i, result := range results {
		if result == nil {
			continue
		}

		fmt.Printf("[%d/%d] %s [%s]\n", i+1, len(protocols), result.Protocol.Name, result.Protocol.Type)
		fmt.Printf("       Server: %s:%d\n", result.Protocol.Server, result.Protocol.Port)

		if !result.Success {
			// Check if it's an unsupported protocol error
			if strings.Contains(result.Error, "not yet supported") {
				fmt.Printf("       ⚠ Skipped: %s\n\n", result.Error)
			} else {
				fmt.Printf("       ✗ Failed: %s\n\n", result.Error)
			}
			continue
		}

		fmt.Printf("       ✓ Connected (%dms)\n", result.Connectivity.ResponseTime.Milliseconds())

		if result.Performance != nil {
			fmt.Printf("       📊 Speed: ↓%.1f Mbps\n", result.Performance.DownloadSpeed)
			fmt.Printf("       ⏱  Latency: %dms\n", result.Performance.Latency.Milliseconds())
		}

		if result.GeoAccess != nil && *verbose {
			fmt.Printf("       🌍 Geo: %d/%d accessible (%.0f%%)\n",
				result.GeoAccess.Summary.TotalAccessible,
				result.GeoAccess.Summary.TotalTested,
				result.GeoAccess.Summary.AccessPercentage)
		}

		if result.DNS != nil && *verbose {
			leak := "✓"
			if result.DNS.LeakDetection != nil && result.DNS.LeakDetection.IsLeaking {
				leak = "⚠"
			}
			fmt.Printf("       🔒 DNS Leak: %s\n", leak)

			if result.DNS.Blocking != nil {
				fmt.Printf("       🛡  Blocked: %d/%d domains\n",
					result.DNS.Blocking.Summary.TotalBlocked,
					result.DNS.Blocking.Summary.TotalTested)
			}
		}

		if result.Privacy != nil && *verbose {
			fmt.Printf("       🔐 Security Score: %d/100\n", result.Privacy.Score)
		}

		fmt.Println()
	}

	return results
}

func outputJSON(results []*models.TestResult) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
	}
}

func outputMarkdown(results []*models.TestResult) {
	fmt.Println("# ProtoScope Test Results")
	fmt.Println()
	fmt.Printf("**Generated**: %s\n\n", time.Now().Format(time.RFC1123))
	fmt.Printf("**Total Protocols**: %d\n\n", len(results))

	fmt.Println("## Summary")
	fmt.Println()

	working := 0
	failed := 0
	avgLatency := time.Duration(0)
	latencyCount := 0

	for _, result := range results {
		if result == nil {
			continue
		}
		if result.Success {
			working++
			if result.Connectivity != nil {
				avgLatency += result.Connectivity.ResponseTime
				latencyCount++
			}
		} else {
			failed++
		}
	}

	if latencyCount > 0 {
		avgLatency = avgLatency / time.Duration(latencyCount)
	}

	fmt.Printf("- **Working**: %d (%.1f%%)\n", working, float64(working)/float64(len(results))*100)
	fmt.Printf("- **Failed**: %d (%.1f%%)\n", failed, float64(failed)/float64(len(results))*100)
	if latencyCount > 0 {
		fmt.Printf("- **Average Latency**: %dms\n", avgLatency.Milliseconds())
	}
	fmt.Println()

	fmt.Println("## Detailed Results")
	fmt.Println()

	for i, result := range results {
		if result == nil {
			continue
		}

		status := "✗ Failed"
		if result.Success {
			status = "✓ Working"
		}

		fmt.Printf("### %d. %s - %s\n", i+1, result.Protocol.Name, status)
		fmt.Println()
		fmt.Printf("- **Type**: %s\n", result.Protocol.Type)
		fmt.Printf("- **Server**: %s:%d\n", result.Protocol.Server, result.Protocol.Port)

		if result.Success {
			if result.Connectivity != nil {
				fmt.Printf("- **Response Time**: %dms\n", result.Connectivity.ResponseTime.Milliseconds())
			}

			if result.Performance != nil {
				fmt.Printf("- **Download Speed**: %.1f Mbps\n", result.Performance.DownloadSpeed)
				fmt.Printf("- **Latency**: %dms\n", result.Performance.Latency.Milliseconds())
			}

			if result.GeoAccess != nil {
				fmt.Printf("- **Geo Access**: %d/%d (%.0f%%)\n",
					result.GeoAccess.Summary.TotalAccessible,
					result.GeoAccess.Summary.TotalTested,
					result.GeoAccess.Summary.AccessPercentage)
			}

			if result.Privacy != nil {
				fmt.Printf("- **Security Score**: %d/100\n", result.Privacy.Score)
			}
		} else {
			fmt.Printf("- **Error**: %s\n", result.Error)
		}

		fmt.Println()
	}
}

func outputConsole(results []*models.TestResult) {
	fmt.Println("===========================================")
	fmt.Println("📊 Test Summary")
	fmt.Println("===========================================")

	working := 0
	failed := 0
	avgLatency := time.Duration(0)
	latencyCount := 0
	avgSpeed := 0.0
	speedCount := 0

	for _, result := range results {
		if result == nil {
			continue
		}
		if result.Success {
			working++
			if result.Connectivity != nil {
				avgLatency += result.Connectivity.ResponseTime
				latencyCount++
			}
			if result.Performance != nil && result.Performance.DownloadSpeed > 0 {
				avgSpeed += result.Performance.DownloadSpeed
				speedCount++
			}
		} else {
			failed++
		}
	}

	if latencyCount > 0 {
		avgLatency = avgLatency / time.Duration(latencyCount)
	}
	if speedCount > 0 {
		avgSpeed = avgSpeed / float64(speedCount)
	}

	fmt.Printf("Total Protocols: %d\n", len(results))
	fmt.Printf("✓ Working: %d (%.1f%%)\n", working, float64(working)/float64(len(results))*100)
	fmt.Printf("✗ Failed: %d (%.1f%%)\n", failed, float64(failed)/float64(len(results))*100)

	if latencyCount > 0 {
		fmt.Printf("⏱  Average Latency: %dms\n", avgLatency.Milliseconds())
	}
	if speedCount > 0 {
		fmt.Printf("📊 Average Speed: %.1f Mbps\n", avgSpeed)
	}

	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("💡 Tip: Use -format json or -format markdown for detailed output")
	fmt.Println("💡 Use -verbose for more details in console mode")
	fmt.Println("===========================================")
}
