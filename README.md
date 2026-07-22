# 🔍 recon-tool — Multi-Source OSINT Reconnaissance

[![Version](https://img.shields.io/badge/version-6.0.0-brightgreen)](https://github.com/PORT-777/recon-tool)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange)](https://github.com/PORT-777/recon-tool)
[![GitHub](https://img.shields.io/badge/GitHub-PORT--777-181717?logo=github)](https://github.com/PORT-777)

> A powerful async OSINT recon tool that extracts **emails**, **subdomains**, **IPs**, **names**, **URLs**, and detects **takeovers** from a target domain using 17+ public data sources.
>
> Built for bug bounty hunters, penetration testers, and OSINT researchers.

---

## 📡 Features

- ⚡ **Async** — all 17+ sources run concurrently (5x faster than theHarvester)
- 📧 **Email extraction** (from pages, URLs, SSL certs, Hunter.io)
- 🌐 **Subdomain discovery** (crt.sh, DNS, OTX, RapidDNS, BufferOver, CertSpotter, SecurityTrails, VirusTotal, DNS brute-force)
- 📡 **IP discovery** (DNS, passive DNS, Shodan, BufferOver)
- 👥 **People discovery** (LinkedIn, Hunter.io, page scraping)
- 🔗 **URL collection** (search engines, Wayback, GitHub, Pastebin, URLScan)
- 🚩 **Takeover detection** (AWS S3, GitHub Pages, Heroku, Azure, CloudFront, Shopify, +15 more)
- 📄 **Page scraping** — fetches each URL and extracts emails + names
- 🔌 **API endpoint scanning** (`-a`) — discovers 200+ common API paths
- 🖼️ **Screenshots** (`--screenshot`) — captures screenshots of subdomains (requires Selenium)
- 🖥️ **Virtual host detection** (`--vhost`)
- 🌐 **Proxy support** (`-p`) — HTTP/HTTPS/SOCKS5
- 📊 **Output formats**: Text, JSON, HTML report
- 🔑 **API keys** from `~/.recon-tool/api-keys.yaml` or environment variables

---

## 🚀 Installation

```bash
git clone https://github.com/PORT-777/recon-tool.git
cd recon-tool
pip install -r requirements.txt
```

## 📖 Usage

```bash
python recon.py -d example.com -b all
python recon.py -d example.com -b google,crtsh -l 200
python recon.py -d example.com -b all -o html
```

### Options

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-b` | Sources: comma-separated or `all` |
| `-l` | Max results per source (default: 100) |
| `-t` | HTTP timeout in seconds (default: 20) |
| `-o` | Output format: `text`, `json`, or `html` |
| `-w` | Custom wordlist file for DNS brute force |
| `-c` | Enable DNS brute force subdomain discovery |
| `-p` | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `-r` | Resolve all discovered subdomains to IPs |
| `-a` | Scan for API endpoints on subdomains |
| `-s` | Enrich hosts with Shodan data (requires SHODAN_API_KEY) |
| `-e` | Custom DNS server for resolution |
| `-q` | Suppress missing API key warnings |
| `--takeover` | Check subdomains for takeover vulnerabilities |
| `--scrape` | Scrape page content for emails and names |
| `--vhost` | Detect virtual hosts |
| `--screenshot DIR` | Take screenshots of subdomains (requires Selenium) |
| `--no-banner` | Suppress startup banner |

### 🔑 API Keys

Create `~/.recon-tool/api-keys.yaml`:

```yaml
shodan: YOUR_SHODAN_KEY
hunter: YOUR_HUNTER_KEY
securitytrails: YOUR_SECURITYTRAILS_KEY
virustotal: YOUR_VIRUSTOTAL_KEY
```

Or set environment variables:

```bash
export SHODAN_API_KEY="..."
export HUNTER_API_KEY="..."
export SECURITYTRAILS_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
```

---

## 📡 Sources

| Source | Type | Description |
|--------|------|-------------|
| `google` | URLs | Google search engine |
| `bing` | URLs | Bing search engine |
| `baidu` | URLs | Baidu search engine |
| `yahoo` | URLs | Yahoo search engine |
| `crtsh` | Subdomains, Emails | Certificate Transparency logs |
| `dns` | Subdomains, IPs | HackerTarget DNS lookup |
| `otx` | Subdomains, IPs | AlienVault OTX passive DNS |
| `wayback` | URLs, Emails | Wayback Machine archive |
| `github` | URLs | GitHub code search |
| `pastes` | URLs | Pastebin dump search |
| `dnsdumpster` | Subdomains | DNSDumpster DNS recon |
| `threatcrowd` | Subdomains, IPs | ThreatCrowd passive DNS |
| `rapiddns` | Subdomains | RapidDNS.io DNS database |
| `urlscan` | URLs, Subdomains, IPs | URLScan.io scan results |
| `bufferover` | Subdomains, IPs | BufferOver.run DNS data |
| `certspotter` | Subdomains | CertSpotter certificate transparency |
| `shodan_idb` | Subdomains | Shodan InternetDB (free, no key) |
| `linkedin` | People | LinkedIn profile discovery |
| `shodan` | Subdomains, IPs | Shodan API (requires key) |
| `hunter` | Emails, People | Hunter.io email search (requires key) |
| `securitytrails` | Subdomains, IPs | SecurityTrails DNS history (requires key) |
| `virustotal` | Subdomains | VirusTotal passive DNS (requires key) |
| `dns_brute` | Subdomains, IPs | DNS brute force with wordlist |
| `api_scan` | URLs | API endpoint discovery |
| `takeover` | Takeovers | Subdomain takeover detection |
| `scrape` | Emails, People | Page content scraping |

---

## 📊 Output Examples

### Text
```
═══ Results for hackerone.com ═══
  Emails:     2
  Subdomains: 21
  IPs:        15
  URLs:       50
  Names:      5
  VHosts:     3
  Screenshots:0
  Time:       31.6s

── Emails ──
  support@hackerone.com
  admin@hackerone.com

── Subdomains ──
  api.hackerone.com
  docs.hackerone.com
  www.hackerone.com
  ...
```

### HTML Report
Generate a dark-themed HTML report:
```bash
python recon.py -d example.com -b all -o html
```

---

## 📈 Comparison: recon-tool vs theHarvester

| Feature | theHarvester | recon-tool |
|---------|:------------:|:----------:|
| Async (faster) | ❌ | ✅ |
| 17+ free sources | ❌ | ✅ |
| LinkedIn | ✅ | ✅ |
| Takeover detection | ✅ | ✅ |
| DNS brute force | ✅ | ✅ |
| Screenshots | ✅ | ✅ |
| API endpoint scan (`-a`) | ✅ | ✅ |
| Shodan enrich (`-s`) | ✅ | ✅ |
| Custom DNS (`-e`) | ✅ | ✅ |
| Proxy support | ✅ | ✅ |
| Page content scraping | ❌ | ✅ |
| Virtual host detection | ❌ | ✅ |
| HTML report | ❌ | ✅ |

---

## 👤 Author

**0xMr.PORT 777**

[![Telegram](https://img.shields.io/badge/Telegram-26A5E4?style=flat&logo=telegram&logoColor=white)](https://t.me/PB_9B)
[![WhatsApp](https://img.shields.io/badge/WhatsApp-25D366?style=flat&logo=whatsapp&logoColor=white)](https://wa.me/+201026778601)
[![Instagram](https://img.shields.io/badge/Instagram-E4405F?style=flat&logo=instagram&logoColor=white)](https://www.instagram.com/i_c.n)
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=flat&logo=youtube&logoColor=white)](https://youtube.com/@ahmed-yasser-777)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/PORT-777)
[![TikTok](https://img.shields.io/badge/TikTok-000000?style=flat&logo=tiktok&logoColor=white)](https://www.tiktok.com/@i_c.n1)
[![Telegram Channel](https://img.shields.io/badge/Channel-26A5E4?style=flat&logo=telegram&logoColor=white)](https://t.me/f_c_o_6)

---

## 📜 License

MIT — see [LICENSE](LICENSE) for details.
