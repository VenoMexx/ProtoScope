package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	
	"github.com/VenoMexx/ProtoScope/internal/parser"
	"github.com/VenoMexx/ProtoScope/pkg/models"
)

func main() {
	data, _ := os.ReadFile("/tmp/subscription_decoded.txt")
	content := string(data)
	var protocols []*models.Protocol
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	skippedCount := 0
	supportedCount := 0
	unsupportedCount := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		var protocol *models.Protocol
		var err error
		
		switch {
		case strings.HasPrefix(line, "vmess://"):
			protocol, err = parser.ParseVMess(line)
		case strings.HasPrefix(line, "vless://"):
			protocol, err = parser.ParseVLESS(line)
		case strings.HasPrefix(line, "trojan://"):
			protocol, err = parser.ParseTrojan(line)
		case strings.HasPrefix(line, "ss://"):
			protocol, err = parser.ParseShadowsocks(line)
		case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
			protocol, err = parser.ParseHysteria2(line)
		case strings.HasPrefix(line, "tuic://"):
			protocol, err = parser.ParseTUIC(line)
		case strings.HasPrefix(line, "wg://"), strings.HasPrefix(line, "ssh://"):
			unsupportedCount++
			fmt.Printf("[Line %d] UNSUPPORTED: %s\n", lineNum, strings.Split(line, "://")[0])
			continue
		default:
			continue
		}
		
		if err != nil {
			skippedCount++
			protoType := strings.Split(line, "://")[0]
			fmt.Printf("[Line %d] ERROR (%s): %v\n", lineNum, protoType, err)
			if len(line) > 100 {
				fmt.Printf("          %s...\n", line[:100])
			}
		} else {
			supportedCount++
			protocols = append(protocols, protocol)
		}
	}
	
	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("✓ Successfully parsed: %d\n", supportedCount)
	fmt.Printf("✗ Parse errors: %d\n", skippedCount)
	fmt.Printf("⊘ Unsupported (wg/ssh): %d\n", unsupportedCount)
	fmt.Printf("Total lines: %d\n", lineNum)
}
