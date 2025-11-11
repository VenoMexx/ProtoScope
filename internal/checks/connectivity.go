package checks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// ConnectivityChecker tests basic connectivity
type ConnectivityChecker struct {
	timeout time.Duration
}

// NewConnectivityChecker creates a new connectivity checker
func NewConnectivityChecker(timeout time.Duration) *ConnectivityChecker {
	return &ConnectivityChecker{
		timeout: timeout,
	}
}

// Check performs basic connectivity test
func (c *ConnectivityChecker) Check(ctx context.Context, protocol *models.Protocol, proxyDialer proxy.Dialer) (*models.ConnectivityResult, error) {
	start := time.Now()

	// Try to connect through the proxy
	conn, err := proxyDialer.Dial("tcp", "www.google.com:80")
	if err != nil {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}
	defer conn.Close()

	// Try to make a simple HTTP request
	err = conn.SetDeadline(time.Now().Add(c.timeout))
	if err != nil {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}

	// Send HTTP request
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
	if err != nil {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}

	// Read response
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil && err != io.EOF {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}

	elapsed := time.Since(start)

	return &models.ConnectivityResult{
		Connected:    true,
		ResponseTime: elapsed,
	}, nil
}

// CheckDirect performs a direct connectivity test without proxy
func (c *ConnectivityChecker) CheckDirect(ctx context.Context, address string) (*models.ConnectivityResult, error) {
	start := time.Now()

	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}
	defer conn.Close()

	elapsed := time.Since(start)

	return &models.ConnectivityResult{
		Connected:    true,
		ResponseTime: elapsed,
	}, nil
}

// CheckHTTP performs HTTP connectivity test
func (c *ConnectivityChecker) CheckHTTP(ctx context.Context, url string, client *http.Client) (*models.ConnectivityResult, error) {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return &models.ConnectivityResult{
			Connected:    false,
			ResponseTime: time.Since(start),
			Error:        err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return &models.ConnectivityResult{
			Connected:    true,
			ResponseTime: elapsed,
		}, nil
	}

	return &models.ConnectivityResult{
		Connected:    false,
		ResponseTime: elapsed,
		Error:        fmt.Sprintf("HTTP status: %d", resp.StatusCode),
	}, nil
}

// Ping performs a simple ping-like test
func (c *ConnectivityChecker) Ping(ctx context.Context, address string) (time.Duration, error) {
	start := time.Now()

	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return time.Since(start), nil
}
