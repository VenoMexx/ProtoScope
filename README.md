# 🔍 ProtoScope

**ProtoScope** is a comprehensive security testing tool for VPN/Proxy protocols. It tests subscription links containing Xray, Hysteria2, and Sing-box protocols for connectivity, performance, geo-access, DNS security, and privacy.

## ✨ Features

### 🌐 Protocol Support

| Protocol | Parse | Test | Status |
|----------|-------|------|--------|
| **VMess** | ✅ | ✅ | Fully Supported |
| **VLESS** | ✅ | ✅ | Fully Supported |
| **Trojan** | ✅ | ✅ | Fully Supported |
| **Shadowsocks** | ✅ | ✅ | Fully Supported |
| **Hysteria2** | ✅ | ✅ | Fully Supported |
| **TUIC** | ✅ | ✅ | Fully Supported |

**🎯 Powered by Sing-box:**
ProtoScope uses **Sing-box** as the universal backend for all protocols. Sing-box is a modern, feature-rich proxy platform that supports:
- ✅ Traditional protocols (VMess, VLESS, Trojan, Shadowsocks)
- ✅ Modern QUIC-based protocols (Hysteria2, TUIC)
- ✅ And many more!

This unified approach provides **maximum compatibility** with a single, powerful backend!

### 🔬 Test Categories

#### 1. **Connectivity & Performance**
- Basic connection testing
- Latency measurement (ping)
- Download/Upload speed tests
- Connection jitter analysis

#### 2. **Geo-Access Testing**
- **RU Domains**: vk.com, yandex.ru, mail.ru, rt.com
- **CN Domains**: baidu.com, qq.com, weibo.com, taobao.com
- **IR Domains**: isna.ir, farsnews.ir, tasnimnews.com
- **US Domains**: google.com, youtube.com, facebook.com, twitter.com
- Tests which geographic restrictions are bypassed

#### 3. **DNS Security**
- **DNS Leak Detection**: Checks if DNS queries leak to ISP
- **DNS Blocking**: Tests if ads/tracking domains are blocked
  - Google Ads (googleadservices.com, doubleclick.net)
  - Tracking domains (google-analytics.com, facebook.com/tr)
  - Analytics services

#### 4. **Privacy & Security**
- DNS leak detection
- WebRTC leak detection
- IPv6 leak detection
- Real IP exposure check
- Security score (0-100)

## 📋 Requirements

### System Requirements
- Go 1.20 or higher
- **Sing-box** (Required)

### Installing Sing-box

**Linux:**
```bash
bash <(curl -fsSL https://sing-box.app/deb-install.sh)
```

**macOS:**
```bash
brew install sing-box
```

**Windows:**
Download from [Sing-box Releases](https://github.com/SagerNet/sing-box/releases)

**Verify Installation:**
```bash
sing-box version
```

**Why Sing-box?** ProtoScope uses Sing-box as the universal backend because it natively supports **all protocols** including traditional ones (VMess, VLESS, Trojan, Shadowsocks) and modern QUIC-based protocols (Hysteria2, TUIC)!

## 🚀 Installation

### From Source

```bash
git clone https://github.com/VenoMexx/ProtoScope.git
cd ProtoScope
go build -o protoscope ./cmd/protoscope
```

### Using Go Install

```bash
go install github.com/VenoMexx/ProtoScope/cmd/protoscope@latest
```

## 📖 Usage

### Basic Usage

```bash
# Test a subscription URL
protoscope -url "https://example.com/subscription"

# Quick mode (connectivity only)
protoscope -url "https://example.com/subscription" -quick

# JSON output
protoscope -url "https://example.com/subscription" -format json

# Markdown report
protoscope -url "https://example.com/subscription" -format markdown > report.md

# Custom timeout and concurrency
protoscope -url "https://example.com/subscription" -timeout 60s -concurrent 10

# Verbose output
protoscope -url "https://example.com/subscription" -verbose
```

### Command Line Options

```
-url string
    Subscription URL to test (required)

-format string
    Output format: console, json, markdown (default: console)

-timeout duration
    Timeout for each test (default: 30s)

-concurrent int
    Number of concurrent tests (default: 3)

-quick
    Quick mode - only connectivity tests

-verbose
    Enable verbose output with detailed results

-no-speed
    Disable speed tests (useful for faster testing)

-no-geo
    Disable geo-access tests

-no-dns
    Disable DNS leak and blocking tests

-no-privacy
    Disable privacy and security tests
```

### Advanced Usage

```bash
# Test only connectivity (fastest)
protoscope -url <url> -quick

# Skip speed tests for faster results
protoscope -url <url> -no-speed

# Full test with verbose output
protoscope -url <url> -verbose

# Test with custom concurrency
protoscope -url <url> -concurrent 10

# Export results to JSON
protoscope -url <url> -format json > results.json

# Generate markdown report
protoscope -url <url> -format markdown > report.md
```

## 📊 Example Output

### Console Output

```
ProtoScope v0.1.0 - Protocol Security Tester
===========================================

Testing 15 protocols from subscription...

Protocol 1/15: HK-01 [vmess] ✓
  ├─ Connectivity: Connected (245ms)
  ├─ Speed: ↓ 45.2 Mbps / ↑ 12.3 Mbps
  ├─ Geo Access:
  │  ├─ RU: ✓ Accessible (4/4 domains)
  │  ├─ CN: ✗ Blocked (0/4 domains)
  │  └─ IR: ✓ Accessible (3/3 domains)
  ├─ DNS:
  │  ├─ Leak: ✓ No leak detected
  │  └─ Ad Blocking: ✗ 0/10 ads blocked
  └─ Privacy:
     ├─ DNS Leak: ✓ Safe
     ├─ IPv6 Leak: ✓ Safe
     └─ Security Score: 90/100

Protocol 2/15: US-02 [hysteria2] ✗
  └─ Connection failed: timeout

===========================================
Summary
===========================================
Total Protocols: 15
Working: 12 (80%)
Failed: 3 (20%)

Best Latency: HK-03 (89ms)
Best Speed: US-01 (78.5 Mbps)
Most Secure: HK-01, SG-02, JP-01 (Score: 90+)
```

### JSON Output

```json
[
  {
    "protocol": {
      "type": "vmess",
      "name": "HK-01",
      "server": "hk.example.com",
      "port": 443,
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    },
    "timestamp": "2025-11-11T20:00:00Z",
    "success": true,
    "connectivity": {
      "connected": true,
      "response_time": 245000000
    },
    "performance": {
      "latency": 245000000,
      "download_speed_mbps": 45.2,
      "upload_speed_mbps": 12.3
    },
    "geo_access": {
      "summary": {
        "total_tested": 15,
        "total_accessible": 12,
        "access_percentage": 80.0
      }
    },
    "dns": {
      "leak_detection": {
        "is_leaking": false
      },
      "blocking": {
        "summary": {
          "total_tested": 10,
          "total_blocked": 0
        }
      }
    },
    "privacy": {
      "dns_leak": false,
      "webrtc_leak": false,
      "ipv6_leak": false,
      "security_score": 90
    }
  }
]
```

## 🏗️ Architecture

```
ProtoScope/
├── cmd/
│   └── protoscope/          # CLI application
├── internal/
│   ├── parser/              # Subscription parsers
│   ├── tester/              # Protocol testers
│   ├── checks/              # Test modules
│   │   ├── connectivity.go  # Connection tests
│   │   ├── performance.go   # Speed & latency
│   │   ├── geo.go          # Geo-access tests
│   │   ├── dns.go          # DNS leak & blocking
│   │   └── privacy.go      # Privacy tests
│   ├── metrics/             # Performance metrics
│   └── reporter/            # Report generation
├── pkg/
│   ├── models/              # Data models
│   └── domains/             # Test domain lists
└── configs/                 # Configuration files
```

## 🧪 Test Methodology

### Connectivity Test
1. Establish connection through proxy
2. Make HTTP request to test endpoint
3. Measure connection time
4. Verify data transmission

### Geo-Access Test
1. Attempt to connect to geo-specific domains
2. Test both HTTP and HTTPS
3. Record accessibility and response times
4. Categorize by region

### DNS Leak Test
1. Query external DNS leak detection APIs
2. Compare detected DNS servers with proxy location
3. Check for ISP DNS exposure
4. Verify DNS routing through proxy

### DNS Blocking Test
1. Attempt to resolve ad/tracking domains
2. Try HTTP/HTTPS connections
3. Categorize block type (DNS/HTTP/None)
4. Calculate blocking percentage

### Privacy Test
1. Get public IP through proxy
2. Check for WebRTC leaks
3. Test IPv6 connectivity
4. Calculate security score

## 🔒 Security & Privacy

ProtoScope is designed for **authorized testing only**:
- ✅ Test your own VPN/proxy subscriptions
- ✅ Evaluate service quality and security
- ✅ Check for DNS/IP leaks
- ❌ Do not test unauthorized services
- ❌ Do not use for malicious purposes

## 🛠️ Development

### Requirements
- Go 1.20 or higher
- Internet connection for testing

### Building

```bash
go build -o protoscope ./cmd/protoscope
```

### Testing

```bash
go test ./...
```

### Adding Custom Domains

Edit `configs/domains.yaml` to add custom test domains:

```yaml
geo_domains:
  custom:
    - example.com
    - custom-site.net

dns_blocking:
  custom_ads:
    - custom-ad-domain.com
```

## 📝 Roadmap

- [x] Basic subscription parsing
- [x] Protocol models (VMess, VLESS, Trojan, Hysteria2)
- [x] Connectivity testing
- [x] Performance testing
- [x] Geo-access testing
- [x] DNS leak detection
- [x] DNS blocking tests
- [x] Privacy tests
- [x] **Sing-box integration for all protocols**
- [x] **Full test runner implementation**
- [x] **Multiple output formats (console, JSON, markdown)**
- [x] **Universal backend using Sing-box only**
- [x] **All protocols support (VMess, VLESS, Trojan, Shadowsocks, Hysteria2, TUIC)**
- [x] **Comprehensive error diagnostics and troubleshooting**
- [ ] WebRTC leak testing (browser automation required)
- [ ] HTML report generation
- [ ] Configuration file support (YAML)
- [ ] CI/CD integration
- [ ] Docker support
- [ ] Batch testing from file
- [ ] Streaming service tests (Netflix, YouTube)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**. Users are responsible for ensuring they have permission to test any proxy/VPN services. The authors are not responsible for misuse of this tool.

## 🙏 Acknowledgments

- Inspired by various VPN testing tools
- Built with Go and modern security practices
- Community feedback and contributions

---

**Made with ❤️ for the privacy community**
