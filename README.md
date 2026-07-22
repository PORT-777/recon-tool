# recon.py — Multi-Source OSINT Tool

A powerful async recon tool that extracts **emails**, **subdomains**, **IPs**, and **URLs** from a target domain using multiple public data sources.

> Built for bug bounty hunters, pentesters, and OSINT researchers.

---

## Features

- 🔍 **17 data sources**: Google, Bing, Baidu, Yahoo, crt.sh, DNS (HackerTarget), AlienVault OTX, Wayback Machine, GitHub, Pastebin, DNSDumpster, ThreatCrowd, RapidDNS, URLScan.io, BufferOver, CertSpotter, Shodan InternetDB
- ⚡ **Async** — fast, all sources run concurrently
- 📧 Extracts **emails** (with validation)
- 🌐 Finds **subdomains** (from SSL certs, DNS, passive DNS)
- 📡 Discovers **IPs** (from DNS records, passive DNS)
- 🔗 Collects **URLs** (from search engines, archives, code repos)
- 📊 Output: human-readable **text** or **JSON**
- 💾 Auto-saves JSON results to file

---

## Installation

```bash
git clone https://github.com/yourusername/recon-tool.git
cd recon-tool
pip install -r requirements.txt
```

## Usage

```bash
python recon.py -d example.com -b all
python recon.py -d example.com -b google,crtsh -l 200
python recon.py -d example.com -b all -o json
```

### Options

| Flag | Description |
|------|-------------|
| `-d` | Target domain (required) |
| `-b` | Sources: `google,bing,baidu,yahoo,crtsh,dns,otx,wayback,github,pastes,dnsdumpster,threatcrowd,rapiddns,urlscan,bufferover,certspotter,shodan_idb` or `all` |
| `-l` | Max results per source (default: 100) |
| `-t` | HTTP timeout in seconds (default: 20) |
| `-o` | Output format: `text` or `json` |
| `--no-banner` | Suppress startup banner |

---

## Sources

| Source | Data Type | Description |
|--------|-----------|-------------|
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

---

## Output Example

```
═══ Results for example.com ═══
  Emails:     12
  Subdomains: 34
  IPs:        8
  URLs:       100

── Emails ──
  admin@example.com
  support@example.com
  ...

── Subdomains ──
  mail.example.com
  dev.example.com
  api.example.com
  ...
```
