# recon-tool

Multi-source OSINT reconnaissance tool for email, subdomain, IP, name, and URL discovery.

## Features

- **22 data sources** — search engines, certificate transparency, DNS databases, passive DNS, archives, code repositories, paste sites, professional networks, and API feeds
- **Async concurrency** — all sources execute simultaneously for maximum speed
- **Subdomain takeover detection** — 22 cloud service fingerprints (AWS, GitHub Pages, Heroku, Azure, CloudFront, Shopify, Netlify, Vercel, etc.)
- **API endpoint discovery** — 100+ common API paths scanned across discovered hosts
- **DNS brute force** — 100 built-in subdomain words with custom wordlist support
- **Page content scraping** — extracts emails and names from discovered URLs
- **Virtual host detection** — identifies multiple subdomains sharing the same IP
- **Screenshots** — headless Chrome capture of discovered subdomains
- **Proxy support** — HTTP/HTTPS/SOCKS5
- **Output formats** — text, JSON, HTML report

## Installation

```bash
git clone https://github.com/PORT-777/recon-tool.git
cd recon-tool
pip install -r requirements.txt
```

## Usage

```bash
python recon.py -d example.com -b all
python recon.py -d example.com -b crtsh,dns,urlscan -l 200
python recon.py -d example.com -b all -o html
python recon.py -d example.com -b dns -c --takeover --scrape --vhost --screenshot ./shots
```

### Arguments

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-b` | Sources (comma-separated or `all`) |
| `-l` | Max results per source |
| `-t` | HTTP timeout |
| `-o` | Output format: `text`, `json`, `html` |
| `-w` | Custom wordlist for DNS brute force |
| `-c` | Enable DNS brute force |
| `-p` | Proxy URL |
| `-r` | Resolve subdomains to IPs |
| `-a` | API endpoint scan |
| `-s` | Shodan enrichment |
| `-e` | Custom DNS server |
| `-q` | Suppress API key warnings |
| `--takeover` | Check for subdomain takeovers |
| `--scrape` | Scrape page content |
| `--vhost` | Detect virtual hosts |
| `--screenshot` | Capture screenshots |
| `--no-banner` | Suppress startup banner |

### API Keys

Place keys in `~/.recon-tool/api-keys.yaml`:

```yaml
shodan: YOUR_KEY
hunter: YOUR_KEY
securitytrails: YOUR_KEY
virustotal: YOUR_KEY
```

Or use environment variables: `SHODAN_API_KEY`, `HUNTER_API_KEY`, `SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY`.

## Sources

| Source | Data | Description |
|--------|------|-------------|
| `google` | URLs | Google search |
| `bing` | URLs | Bing search |
| `baidu` | URLs | Baidu search |
| `yahoo` | URLs | Yahoo search |
| `crtsh` | Subdomains, Emails | Certificate Transparency |
| `dns` | Subdomains, IPs | HackerTarget DNS |
| `otx` | Subdomains, IPs | AlienVault OTX |
| `wayback` | URLs, Emails | Wayback Machine |
| `github` | URLs | GitHub code search |
| `pastes` | URLs | Pastebin search |
| `dnsdumpster` | Subdomains | DNSDumpster |
| `threatcrowd` | Subdomains, IPs | ThreatCrowd |
| `rapiddns` | Subdomains | RapidDNS.io |
| `urlscan` | URLs, Subdomains, IPs | URLScan.io |
| `bufferover` | Subdomains, IPs | BufferOver.run |
| `certspotter` | Subdomains | CertSpotter |
| `shodan_idb` | Subdomains | Shodan InternetDB |
| `linkedin` | People | LinkedIn profiles |
| `shodan` | Subdomains, IPs | Shodan API |
| `hunter` | Emails, People | Hunter.io |
| `securitytrails` | Subdomains, IPs | SecurityTrails |
| `virustotal` | Subdomains | VirusTotal |
| `dns_brute` | Subdomains, IPs | DNS brute force |
| `api_scan` | URLs | API endpoint discovery |
| `takeover` | Takeovers | Subdomain takeover check |
| `scrape` | Emails, People | Page scraping |

## Author

**0xMr.PORT 777**

[![Telegram](https://img.shields.io/badge/Telegram-26A5E4?style=flat&logo=telegram&logoColor=white)](https://t.me/PB_9B)
[![WhatsApp](https://img.shields.io/badge/WhatsApp-25D366?style=flat&logo=whatsapp&logoColor=white)](https://wa.me/+201026778601)
[![Instagram](https://img.shields.io/badge/Instagram-E4405F?style=flat&logo=instagram&logoColor=white)](https://www.instagram.com/i_c.n)
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=flat&logo=youtube&logoColor=white)](https://youtube.com/@ahmed-yasser-777)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/PORT-777)
[![TikTok](https://img.shields.io/badge/TikTok-000000?style=flat&logo=tiktok&logoColor=white)](https://www.tiktok.com/@i_c.n1)
[![Telegram Channel](https://img.shields.io/badge/Channel-26A5E4?style=flat&logo=telegram&logoColor=white)](https://t.me/f_c_o_6)

## License

MIT
