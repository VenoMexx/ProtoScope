package parser

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/VenoMexx/ProtoScope/pkg/models"
)

// Decoder handles subscription link decoding
type Decoder struct {
	client *http.Client
}

// NewDecoder creates a new decoder instance
func NewDecoder() *Decoder {
	return &Decoder{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DecodeSubscription decodes a subscription URL and returns protocols
func (d *Decoder) DecodeSubscription(url string) (*models.Subscription, error) {
	// Fetch subscription content
	content, err := d.fetchSubscription(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}

	// Try to decode as base64
	decoded, err := d.decodeBase64(content)
	if err != nil {
		// If base64 decode fails, use content as-is
		decoded = content
	}

	// Parse protocols from decoded content
	protocols, err := d.parseProtocols(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse protocols: %w", err)
	}

	return &models.Subscription{
		URL:       url,
		Protocols: protocols,
		ParsedAt:  time.Now(),
	}, nil
}

// fetchSubscription fetches subscription content from URL
func (d *Decoder) fetchSubscription(url string) (string, error) {
	resp, err := d.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// decodeBase64 decodes base64 encoded content
func (d *Decoder) decodeBase64(content string) (string, error) {
	// Try standard base64
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err == nil {
		return string(decoded), nil
	}

	// Try URL-safe base64
	decoded, err = base64.URLEncoding.DecodeString(content)
	if err == nil {
		return string(decoded), nil
	}

	// Try raw base64 (without padding)
	decoded, err = base64.RawStdEncoding.DecodeString(content)
	if err == nil {
		return string(decoded), nil
	}

	return "", fmt.Errorf("failed to decode base64")
}

// parseProtocols parses protocols from decoded content
func (d *Decoder) parseProtocols(content string) ([]*models.Protocol, error) {
	var protocols []*models.Protocol

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		protocol, err := d.parseProtocolLine(line)
		if err != nil {
			// Skip invalid lines but continue parsing
			continue
		}

		protocols = append(protocols, protocol)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(protocols) == 0 {
		return nil, fmt.Errorf("no valid protocols found")
	}

	return protocols, nil
}

// parseProtocolLine parses a single protocol line
func (d *Decoder) parseProtocolLine(line string) (*models.Protocol, error) {
	// Detect protocol type from URL scheme
	switch {
	case strings.HasPrefix(line, "vmess://"):
		return ParseVMess(line)
	case strings.HasPrefix(line, "vless://"):
		return ParseVLESS(line)
	case strings.HasPrefix(line, "trojan://"):
		return ParseTrojan(line)
	case strings.HasPrefix(line, "ss://"):
		return ParseShadowsocks(line)
	case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
		return ParseHysteria2(line)
	case strings.HasPrefix(line, "tuic://"):
		return ParseTUIC(line)
	default:
		return nil, fmt.Errorf("unknown protocol type")
	}
}

// DecodeFromFile decodes protocols from a local file
func (d *Decoder) DecodeFromFile(filepath string) (*models.Subscription, error) {
	// This will be implemented if needed
	return nil, fmt.Errorf("file decoding not yet implemented")
}
