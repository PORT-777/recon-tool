#!/usr/bin/env python3
"""
recon.py — Multi-source OSINT recon tool.
Extracts emails, subdomains, IPs, names, and URLs from public sources.

Usage:
    python recon.py -d example.com -b google -l 100
    python recon.py -d example.com -b all -l 200 -o json

Author: PORT 777
"""

import argparse, asyncio, json, os, re, socket, subprocess, sys, time
from urllib.parse import quote, urlparse, parse_qs, urljoin
from email.utils import parseaddr
from collections import defaultdict
from pathlib import Path
from datetime import datetime

import httpx
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "6.0.0"

# ── API Keys (from ~/.recon-tool/api-keys.yaml or env vars) ──
# Format (YAML):
#   shodan: YOUR_KEY
#   hunter: YOUR_KEY
#   securitytrails: YOUR_KEY
#   virustotal: YOUR_KEY
API_KEY_ENV = {
    "shodan":         "SHODAN_API_KEY",
    "hunter":         "HUNTER_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "virustotal":     "VIRUSTOTAL_API_KEY",
}

def load_api_keys():
    keys = {}
    config_path = Path.home() / ".recon-tool" / "api-keys.yaml"
    if config_path.exists():
        try:
            import yaml
            with open(config_path) as f:
                yaml_keys = yaml.safe_load(f) or {}
            for k, v in yaml_keys.items():
                if v and isinstance(v, str):
                    keys[k] = v
        except ImportError:
            pass
        except Exception:
            pass
    for section, env_name in API_KEY_ENV.items():
        if not keys.get(section):
            val = os.getenv(env_name)
            if val:
                keys[section] = val
    return keys

API_KEYS = load_api_keys()

DNS_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "test", "admin", "ftp", "mail2",
    "pop3", "imap", "m", "mxs", "mx", "stage", "beta", "docs", "help",
    "support", "status", "cdn", "cdn1", "cdn2", "static", "media", "img",
    "img1", "css", "js", "app", "mobile", "shop", "store", "portal", "web",
    "db", "sql", "mysql", "backup", "proxy", "router", "gateway", "firewall",
    "dns", "dns1", "dns2", "ntp", "ldap", "radius", "radius1", "radius2",
    "chat", "community", "forum", "board", "news", "info", "download", "downloads",
    "upload", "crm", "erp", "hr", "pay", "payment", "billing", "invoice",
    "git", "svn", "jira", "confluence", "wiki", "jenkins", "ci", "build",
    "monitor", "monitoring", "logs", "analytics", "tracker", "tracking", "stats",
    "edge", "origin", "pixel", "event", "data", "s3", "assets", "files",
    "video", "tv", "radio", "stream", "live", "player", "streaming", "media",
    "calendar", "contacts", "sync", "office", "outlook", "exchange", "owa",
    "autodiscover", "lync", "skype", "teams", "zoom", "webex", "meet",
    "go", "lp", "landing", "offer", "promo", "campaign", "marketing", "email",
    "click", "track", "links", "redirect", "go2", "click2", "r", "s",
    "t", "w", "w3", "w5", "ww", "www1", "www2", "www3", "www4",
    "www5", "www6", "www7", "www8", "www9", "www10",
]

API_ENDPOINTS = [
    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
    "graphql", "rest", "swagger", "swagger.json", "openapi.json",
    "api/docs", "docs", "api/documentation", "documentation",
    "health", "healthz", "status", "ping", "heartbeat",
    "login", "signin", "auth", "oauth", "token", "authorize",
    "admin", "administrator", "admin/api", "manage", "dashboard",
    "config", "configuration", "settings", "env", "environment",
    "users", "user", "accounts", "profile", "me", "whoami",
    "search", "query", "suggest", "autocomplete", "lookup",
    "upload", "download", "export", "import", "files", "media",
    "webhook", "webhooks", "callback", "notify", "notification",
    "metrics", "monitor", "stats", "statistics", "analytics",
    "graph", "chart", "data", "feed", "rss", "atom",
    ".git/config", ".env", "robots.txt", "sitemap.xml",
    "cron", "cronjob", "task", "queue", "job", "worker",
    "proxy", "redirect", "forward", "relay", "gateway",
    "beta", "alpha", "test", "staging", "dev", "debug",
    "internal", "private", "secret", "hidden",
]

# ── Takeover fingerprints ──
TAKEOVER_FINGERPRINTS = [
    {"service": "AWS S3",             "pattern": "NoSuchBucket",                       "status": [404]},
    {"service": "AWS S3",             "pattern": "The specified bucket does not exist", "status": [404]},
    {"service": "GitHub Pages",       "pattern": "There isn't a GitHub Pages site",     "status": [404]},
    {"service": "GitHub Pages",       "pattern": "Site not found",                     "status": [404]},
    {"service": "Heroku",             "pattern": "No such app",                         "status": [404]},
    {"service": "Azure",              "pattern": "Web site not found",                  "status": [404]},
    {"service": "CloudFront",         "pattern": "The requested URL was not found",     "status": [404]},
    {"service": "CloudFront",         "pattern": "Origin error",                        "status": [404, 502]},
    {"service": "Shopify",            "pattern": "Sorry, this shop is currently unavailable", "status": [404]},
    {"service": "Shopify",            "pattern": "Only one step left",                  "status": [200]},
    {"service": "Pantheon",           "pattern": "The gods are angry",                  "status": [404]},
    {"service": "Tumblr",             "pattern": "There's nothing here",                "status": [404]},
    {"service": "Ghost",              "pattern": "The thing you were looking for is no longer here", "status": [404]},
    {"service": "Squarespace",        "pattern": "No Such Account",                     "status": [404]},
    {"service": "Unbounce",           "pattern": "The requested URL was not found on this server", "status": [404]},
    {"service": "Freshdesk",          "pattern": "This support portal is no longer available", "status": [404]},
    {"service": "Zendesk",            "pattern": "Help Center Closed",                  "status": [404]},
    {"service": "Bitbucket",          "pattern": "The page you were looking for does not exist", "status": [404]},
    {"service": "Fly.io",             "pattern": "404 Not Found",                       "status": [404]},
    {"service": "Netlify",            "pattern": "Not Found - Netlify",                 "status": [404]},
    {"service": "Vercel",             "pattern": "The page could not be found",        "status": [404]},
    {"service": "Surge.sh",           "pattern": "project not found",                   "status": [404]},
]

# ──────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────

class Colors:
    OK = Fore.GREEN
    INFO = Fore.CYAN
    WARN = Fore.YELLOW
    ERR = Fore.RED
    R = Style.RESET_ALL


def banner():
    art = r""":::::::::   ::::::::  ::::::::: :::::::::::      ::::::::::: ::::::::::: ::::::::::: 
:+:    :+: :+:    :+: :+:    :+:    :+:          :+:     :+: :+:     :+: :+:     :+: 
+:+    +:+ +:+    +:+ +:+    +:+    +:+                 +:+         +:+         +:+  
+#++:++#+  +#+    +:+ +#++:++#:     +#+                +#+         +#+         +#+   
+#+        +#+    +#+ +#+    +#+    +#+               +#+         +#+         +#+    
#+#        #+#    #+# #+#    #+#    #+#              #+#         #+#         #+#     
###         ########  ###    ###    ###              ###         ###         ###"""
    print(f"{Colors.INFO}{art}{Colors.R}")
    print(f"{Colors.WARN}                                    recon-tool v{VERSION}  |  PORT 777{Colors.R}")
    print(f"{Colors.INFO}                      Email  ·  Subdomain  ·  IP  ·  Name  ·  URL{Colors.R}")


def email_clean(s: str):
    """Extract a valid email from a messy string."""
    s = s.strip().lower()
    if not s or len(s) > 100:
        return None
    _, addr = parseaddr(s)
    if addr and '@' in addr and '.' in addr.split('@')[1]:
        return addr
    return None


def is_valid_subdomain(s: str, domain: str):
    s = s.strip().lower().rstrip('.')
    if s == domain:
        return False
    if s.endswith('.' + domain) and s.count('.') >= 1:
        if not s.startswith('*') and not s.startswith('.'):
            return True
    return False


def domain_from_email(email: str):
    return email.split('@')[1] if '@' in email else ''


class ReconEngine:
    def __init__(self, domain: str, limit: int = 100, timeout: int = 20, wordlist: list = None, proxy: str = None):
        self.domain = domain.lower().strip()
        self.limit = limit
        self.wordlist = wordlist or DNS_WORDLIST
        client_kwargs = {
            "timeout": timeout,
            "verify": False,
            "follow_redirects": True,
            "headers": {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) recon-tool/4.0"},
        }
        if proxy:
            client_kwargs["proxies"] = proxy
        self.client = httpx.AsyncClient(**client_kwargs)
        self.results = defaultdict(set)
        self.results["vhosts"] = []
        self.results["screenshots"] = []

    async def close(self):
        await self.client.aclose()

    # ── GOOGLE ──
    async def search_google(self):
        url = f"https://www.google.com/search?q=site:{self.domain}&num={min(self.limit, 100)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for link in soup.find_all("a"):
                    href = link.get("href", "")
                    if "http" in href and self.domain in href:
                        self.results["urls"].add(href.split("&")[0])
        except:
            pass

    # ── BING ──
    async def search_bing(self):
        url = f"https://www.bing.com/search?q=site:{self.domain}&count={min(self.limit, 50)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for a in soup.find_all("a", href=True):
                    h = a["href"]
                    if self.domain in h and "http" in h:
                        self.results["urls"].add(h)
        except:
            pass

    # ── BAIDU ──
    async def search_baidu(self):
        url = f"https://www.baidu.com/s?wd=site:{self.domain}&rn={min(self.limit, 50)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for a in soup.find_all("a", href=True):
                    h = a["href"]
                    if self.domain in h:
                        self.results["urls"].add(h)
        except:
            pass

    # ── YAHOO ──
    async def search_yahoo(self):
        url = f"https://search.yahoo.com/search?p=site:{self.domain}&n={min(self.limit, 100)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for a in soup.find_all("a", href=True):
                    h = a["href"]
                    if self.domain in h:
                        # Clean yahoo redirect
                        if "http" in h:
                            self.results["urls"].add(h.split("http")[1] if "http" in h.split("http")[1] else h)
        except:
            pass

    # ── crt.sh (SSL certs) ──
    async def search_crtsh(self):
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            r = await self.client.get(url, timeout=30)
            if r.status_code == 200 and r.text.strip() not in ("[]", ""):
                certs = r.json()[:self.limit]
                for c in certs:
                    names = str(c.get("name_value", "")).split("\n")
                    for n in names:
                        n = n.strip().lower()
                        if is_valid_subdomain(n, self.domain):
                            self.results["subdomains"].add(n)
                        elif "@" in n:
                            em = email_clean(n)
                            if em:
                                self.results["emails"].add(em)
        except:
            pass

    # ── DNS (via hackertarget) ──
    async def search_dns(self):
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                for line in r.text.split("\n"):
                    parts = line.strip().split(",")
                    if len(parts) == 2 and parts[0].endswith(self.domain):
                        self.results["subdomains"].add(parts[0].strip().lower())
                        self.results["ips"].add(parts[1].strip())
        except:
            pass

    # ── AlienVault OTX ──
    async def search_otx(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                for entry in r.json().get("passive_dns", []):
                    host = entry.get("hostname", "").lower().strip()
                    if host.endswith(self.domain):
                        self.results["subdomains"].add(host)
                    ip = entry.get("address", "")
                    if ip:
                        self.results["ips"].add(ip)
        except:
            pass

    # ── Wayback Machine ──
    async def search_wayback(self):
        url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original&limit={self.limit * 5}"
        try:
            r = await self.client.get(url, timeout=30)
            if r.status_code == 200 and len(r.json()) > 1:
                for row in r.json()[1:]:
                    if row:
                        u = row[0]
                        self.results["urls"].add(u)
                        # Extract emails from URLs
                        ems = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', u)
                        for em in ems:
                            cleaned = email_clean(em)
                            if cleaned:
                                self.results["emails"].add(cleaned)
        except:
            pass

    # ── GitHub (email search) ──
    async def search_github(self):
        url = f"https://api.github.com/search/code?q={self.domain}+in:file&per_page={min(self.limit, 100)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    path = item.get("path", "")
                    repo = item.get("repository", {}).get("full_name", "")
                    if repo:
                        self.results["urls"].add(f"https://github.com/{repo}/blob/main/{path}")
        except:
            pass

    # ── Email search via psbdmp (pastebin) ──
    async def search_pastes(self):
        url = f"https://psbdmp.ws/api/v3/search?q={self.domain}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                for p in r.json()[:self.limit // 2]:
                    pid = p.get("id", "")
                    if pid:
                        self.results["urls"].add(f"https://pastebin.com/{pid}")
        except:
            pass

    # ── DNSDumpster ──
    async def search_dnsdumpster(self):
        url = "https://dnsdumpster.com/"
        try:
            r = await self.client.get(url)
            soup = BeautifulSoup(r.text, "lxml")
            csrf = soup.find("input", {"name": "csrfmiddlewaretoken"})
            if not csrf:
                return
            token = csrf.get("value", "")
            data = {"csrfmiddlewaretoken": token, "targetip": self.domain, "user": "free"}
            headers = {"Referer": url, "Cookie": f"csrftoken={token}"}
            r2 = await self.client.post(url, data=data, headers=headers)
            if r2.status_code == 200:
                for m in re.finditer(r'[a-zA-Z0-9.-]+\.' + re.escape(self.domain), r2.text):
                    sub = m.group().lower()
                    if is_valid_subdomain(sub, self.domain):
                        self.results["subdomains"].add(sub)
        except:
            pass

    # ── ThreatCrowd ──
    async def search_threatcrowd(self):
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                data = r.json()
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if is_valid_subdomain(sub, self.domain):
                        self.results["subdomains"].add(sub)
                for ip in data.get("resolutions", []):
                    ip_addr = ip.get("ip_address", "")
                    if ip_addr:
                        self.results["ips"].add(ip_addr)
        except:
            pass

    # ── RapidDNS ──
    async def search_rapiddns(self):
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for td in soup.find_all("td"):
                    text = td.get_text(strip=True).lower()
                    if text.endswith(self.domain) and text != self.domain and '.' in text:
                        self.results["subdomains"].add(text)
        except:
            pass

    # ── URLScan.io ──
    async def search_urlscan(self):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size={min(self.limit, 100)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                for result in r.json().get("results", []):
                    page = result.get("page", {})
                    dom = page.get("domain", "")
                    ip = page.get("ip", "")
                    url_s = page.get("url", "")
                    if dom and dom.endswith(self.domain):
                        self.results["subdomains"].add(dom.lower())
                    if ip:
                        self.results["ips"].add(ip)
                    if url_s:
                        self.results["urls"].add(url_s)
        except:
            pass

    # ── BufferOver ──
    async def search_bufferover(self):
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("FDNS_A", []):
                    parts = entry.split(",")
                    if len(parts) >= 2 and parts[1].strip().lower().endswith(self.domain):
                        self.results["subdomains"].add(parts[1].strip().lower())
                        self.results["ips"].add(parts[0].strip())
                for entry in data.get("RDNS", []):
                    parts = entry.split(",")
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        host = parts[1].strip().lower()
                        if host.endswith(self.domain) and is_valid_subdomain(host, self.domain):
                            self.results["subdomains"].add(host)
                            self.results["ips"].add(ip)
        except:
            pass

    # ── CertSpotter ──
    async def search_certspotter(self):
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                for cert in r.json()[:self.limit]:
                    for name in cert.get("dns_names", []):
                        n = name.strip().lower()
                        if is_valid_subdomain(n, self.domain):
                            self.results["subdomains"].add(n)
        except:
            pass

    # ── Shodan InternetDB (free, no key) ──
    async def search_shodan_idb(self):
        """Resolve domain IPs first, then query Shodan InternetDB."""
        try:
            import socket
            ips = set()
            for _, _, _, _, sa in socket.getaddrinfo(self.domain, 80, socket.AF_INET):
                ips.add(sa[0])
            for ip in ips:
                url = f"https://internetdb.shodan.io/{ip}"
                r = await self.client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    for hostname in data.get("hostnames", []):
                        h = hostname.lower()
                        if h.endswith(self.domain) and is_valid_subdomain(h, self.domain):
                            self.results["subdomains"].add(h)
                    for port in data.get("ports", []):
                        self.results["urls"].add(f"{ip}:{port}")
        except:
            pass

    # ── LinkedIn (via Google dorking) ──
    async def search_linkedin(self):
        company = self.domain.split('.')[0].capitalize()
        q = quote(f'site:linkedin.com/in/ "{company}"')
        url = f"https://www.bing.com/search?q={q}&count=30"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for a in soup.find_all("a", href=True):
                    h = a["href"]
                    if "linkedin.com/in/" in h and "http" in h:
                        self.results["urls"].add(h.split("&")[0])
                        name = a.get_text(strip=True)
                        if name and len(name) < 80 and not name.startswith("http"):
                            self.results["names"].add(name.strip())
        except:
            pass

    # ── Shodan (needs API key: SHODAN_API_KEY) ──
    async def search_shodan(self):
        key = API_KEYS.get("shodan")
        if not key:
            return
        try:
            ips = set()
            for _, _, _, _, sa in socket.getaddrinfo(self.domain, 80, socket.AF_INET):
                ips.add(sa[0])
            for ip in list(ips)[:5]:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
                r = await self.client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    for hostname in data.get("hostnames", []):
                        h = hostname.lower()
                        if h.endswith(self.domain) and is_valid_subdomain(h, self.domain):
                            self.results["subdomains"].add(h)
                    for port in data.get("ports", []):
                        self.results["urls"].add(f"{ip}:{port}")
                    for service in data.get("data", []):
                        transport = service.get("transport", "")
                        port = service.get("port", "")
                        product = service.get("product", "")
                        if product:
                            self.results["urls"].add(f"{ip}:{port}/{transport} ({product})")
        except:
            pass

    # ── Hunter.io (needs API key: HUNTER_API_KEY) ──
    async def search_hunter(self):
        key = API_KEYS.get("hunter")
        if not key:
            return
        url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={key}&limit={min(self.limit, 100)}"
        try:
            r = await self.client.get(url)
            if r.status_code == 200:
                data = r.json().get("data", {})
                for email in data.get("emails", []):
                    addr = email.get("value", "").lower()
                    if addr:
                        self.results["emails"].add(addr)
                    first = email.get("first_name", "")
                    last = email.get("last_name", "")
                    if first and last:
                        self.results["names"].add(f"{first} {last}")
        except:
            pass

    # ── SecurityTrails (needs API key: SECURITYTRAILS_API_KEY) ──
    async def search_securitytrails(self):
        key = API_KEYS.get("securitytrails")
        if not key:
            return
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        try:
            r = await self.client.get(url, headers={"APIKEY": key})
            if r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    full = f"{sub}.{self.domain}".lower()
                    if is_valid_subdomain(full, self.domain):
                        self.results["subdomains"].add(full)
        except:
            pass

        # Also query DNS history
        url2 = f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a"
        try:
            r = await self.client.get(url2, headers={"APIKEY": key})
            if r.status_code == 200:
                for record in r.json().get("records", [])[:self.limit]:
                    ip = record.get("organizations", [{}])[0].get("ip", "") if record.get("organizations") else ""
                    if ip:
                        self.results["ips"].add(ip)
        except:
            pass

    # ── VirusTotal (needs API key: VIRUSTOTAL_API_KEY) ──
    async def search_virustotal(self):
        key = API_KEYS.get("virustotal")
        if not key:
            return
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit={min(self.limit, 100)}"
        try:
            r = await self.client.get(url, headers={"x-apikey": key})
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    sub = item.get("id", "").lower()
                    if is_valid_subdomain(sub, self.domain):
                        self.results["subdomains"].add(sub)
        except:
            pass

    # ── DNS Brute Force ──
    async def search_dns_brute(self, wordlist: list = None):
        words = wordlist or DNS_WORDLIST
        resolved = set()
        for word in words[:self.limit]:
            host = f"{word}.{self.domain}"
            try:
                for _, _, _, _, sa in socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP):
                    ip = sa[0]
                    if ip not in resolved:
                        resolved.add(ip)
                        self.results["subdomains"].add(host)
                        self.results["ips"].add(ip)
            except:
                pass

    # ── Takeover Detection ──
    async def check_takeover(self):
        async def _check_one(sub):
            for fp in TAKEOVER_FINGERPRINTS:
                for proto in ("http", "https"):
                    try:
                        r = await self.client.get(f"{proto}://{sub}", timeout=5)
                        if r.status_code in fp["status"] and fp["pattern"].lower() in r.text.lower():
                            self.results["takeovers"].add(f"{sub} → {fp['service']}")
                            return
                    except:
                        pass
        tasks = [_check_one(s) for s in list(self.results["subdomains"])]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Page Content Scraping (emails + names from pages) ──
    async def scrape_pages(self):
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        for url in list(self.results["urls"])[:50]:
            try:
                r = await self.client.get(url, timeout=15)
                if r.status_code == 200:
                    text = r.text
                    # Emails
                    for em in email_pattern.findall(text):
                        cleaned = email_clean(em)
                        if cleaned and domain_from_email(cleaned) == self.domain:
                            self.results["emails"].add(cleaned)
                    # Names from page
                    soup = BeautifulSoup(text, "lxml")
                    for tag in soup.find_all(["h1", "h2", "h3", "title", "meta"]):
                        if tag.name == "meta":
                            name = tag.get("name", "")
                            if name in ("author", "creator"):
                                content = tag.get("content", "").strip()
                                if content and len(content) < 60:
                                    self.results["names"].add(content)
                        else:
                            t = tag.get_text(strip=True)
                            if t and len(t) < 50 and " " in t and not t.startswith("http"):
                                self.results["names"].add(t)
            except:
                pass

    # ── DNS Resolve (resolve all subdomains to IPs) ──
    async def dns_resolve(self, resolvers: list = None):
        if not self.results["subdomains"]:
            return
        for sub in list(self.results["subdomains"]):
            try:
                ips = set()
                for _, _, _, _, sa in socket.getaddrinfo(sub, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP):
                    ips.add(sa[0])
                for ip in ips:
                    self.results["ips"].add(ip)
            except:
                pass

    # ── Virtual Host Detection ──
    async def detect_vhosts(self):
        ip_to_hosts = defaultdict(list)
        for sub in list(self.results["subdomains"]):
            try:
                for _, _, _, _, sa in socket.getaddrinfo(sub, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP):
                    ip_to_hosts[sa[0]].append(sub)
            except:
                pass
        for ip, hosts in ip_to_hosts.items():
            if len(hosts) > 1:
                self.results["vhosts"].append(f"{ip} → {', '.join(hosts)}")

    # ── Screenshot (via headless Chrome/Selenium) ──
    async def take_screenshots(self, output_dir: str):
        if not self.results["subdomains"]:
            return
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for sub in list(self.results["subdomains"]):
            for proto in ("https", "http"):
                url = f"{proto}://{sub}"
                fname = out / f"{sub.replace('.', '_')}.png"
                if fname.exists():
                    break
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "python3", "-c", f"""
import sys
try:
    from selenium import webdriver
    opt = webdriver.ChromeOptions()
    opt.add_argument('--headless')
    opt.add_argument('--no-sandbox')
    opt.add_argument('--disable-dev-shm-usage')
    opt.add_argument('--window-size=1280,720')
    d = webdriver.Chrome(options=opt)
    d.get('{url}')
    d.save_screenshot('{fname}')
    d.quit()
except Exception as e:
    sys.exit(0)
""",
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    await asyncio.wait_for(proc.wait(), timeout=20)
                    if fname.exists() and fname.stat().st_size > 1000:
                        self.results["screenshots"].append(str(fname))
                        break
                except:
                    pass

    # ── API Endpoint Scan ──
    async def scan_api(self, wordlist: list = None):
        words = wordlist or API_ENDPOINTS
        targets = list(self.results["subdomains"])[:3]
        if not targets:
            targets = [self.domain]
        async def _check(target, path):
            for proto in ("https", "http"):
                url = f"{proto}://{target}/{path.lstrip('/')}"
                try:
                    r = await self.client.get(url, timeout=5)
                    if r.status_code in (200, 201, 204, 301, 302, 401, 403):
                        self.results["urls"].add(url)
                except:
                    pass
        tasks = [_check(t, p) for t in targets for p in words[:self.limit]]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Shodan Host Enrich (-s flag) ──
    async def shodan_enrich(self):
        key = API_KEYS.get("shodan")
        if not key:
            return
        for ip in list(self.results["ips"])[:10]:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
                r = await self.client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    for hostname in data.get("hostnames", []):
                        h = hostname.lower()
                        if h.endswith(self.domain) and is_valid_subdomain(h, self.domain):
                            self.results["subdomains"].add(h)
                    for port in data.get("ports", []):
                        self.results["urls"].add(f"{ip}:{port}")
                    os_data = data.get("os", "")
                    if os_data:
                        self.results["names"].add(f"{ip} OS: {os_data}")
            except:
                pass

    # ── Custom DNS Resolve ──
    async def dns_resolve_custom(self, dns_server: str):
        if not self.results["subdomains"]:
            return
        try:
            for sub in list(self.results["subdomains"]):
                try:
                    result = await asyncio.create_subprocess_exec(
                        "nslookup", sub, dns_server,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    await result.wait()
                except:
                    pass
        except:
            pass

    # ── Extract emails from collected URLs ──
    def extract_emails_from_urls(self):
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        for url in list(self.results["urls"]):
            found = email_pattern.findall(url)
            for em in found:
                cleaned = email_clean(em)
                if cleaned and domain_from_email(cleaned) == self.domain:
                    self.results["emails"].add(cleaned)

    # ── RUN ALL SOURCES ──
    async def run_all(self, sources: list):
        tasks = []
        source_map = {
            "google": self.search_google,
            "bing": self.search_bing,
            "baidu": self.search_baidu,
            "yahoo": self.search_yahoo,
            "crtsh": self.search_crtsh,
            "dns": self.search_dns,
            "otx": self.search_otx,
            "wayback": self.search_wayback,
            "github": self.search_github,
            "pastes": self.search_pastes,
            "dnsdumpster": self.search_dnsdumpster,
            "threatcrowd": self.search_threatcrowd,
            "rapiddns": self.search_rapiddns,
            "urlscan": self.search_urlscan,
            "bufferover": self.search_bufferover,
            "certspotter": self.search_certspotter,
            "shodan_idb": self.search_shodan_idb,
            "linkedin": self.search_linkedin,
            "shodan": self.search_shodan,
            "hunter": self.search_hunter,
            "securitytrails": self.search_securitytrails,
            "virustotal": self.search_virustotal,
            "dns_brute": lambda: self.search_dns_brute(self.wordlist),
            "takeover": self.check_takeover,
            "scrape": self.scrape_pages,
            "dns_resolve": self.dns_resolve,
            "vhost": self.detect_vhosts,
            "screenshot": lambda: None,
            "api_scan": self.scan_api,
            "shodan_enrich": self.shodan_enrich,
            "dns_custom": lambda: None,
        }
        screenshot_dir = None
        dns_server = None
        for src in sources:
            if src.startswith("screenshot="):
                screenshot_dir = src.split("=", 1)[1]
                continue
            if src.startswith("dns_custom="):
                dns_server = src.split("=", 1)[1]
                continue
            fn = source_map.get(src)
            if fn:
                tasks.append(fn())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.extract_emails_from_urls()
        if "takeover" in sources or "all" in sources or "dns_brute" in sources:
            await self.check_takeover()
        if "scrape" in sources or "all" in sources:
            await self.scrape_pages()
        if "dns_resolve" in sources or "all" in sources:
            await self.dns_resolve()
        if "vhost" in sources or "all" in sources:
            await self.detect_vhosts()
        if "api_scan" in sources or "all" in sources:
            await self.scan_api()
        if "shodan_enrich" in sources or "all" in sources:
            await self.shodan_enrich()
        if screenshot_dir:
            await self.take_screenshots(screenshot_dir)
        if dns_server:
            await self.dns_resolve_custom(dns_server)

    def summary(self):
        takeovers = sorted(self.results["takeovers"])
        return {
            "domain": self.domain,
            "emails": sorted(self.results["emails"]),
            "subdomains": sorted(self.results["subdomains"]),
            "ips": sorted(self.results["ips"]),
            "urls": sorted(self.results["urls"])[:self.limit],
            "names": sorted(self.results["names"]),
            "takeovers": takeovers,
            "vhosts": self.results["vhosts"],
            "screenshots": self.results["screenshots"],
            "stats": {
                "emails": len(self.results["emails"]),
                "subdomains": len(self.results["subdomains"]),
                "ips": len(self.results["ips"]),
                "urls": min(len(self.results["urls"]), self.limit),
                "names": len(self.results["names"]),
                "takeovers": len(takeovers),
                "vhosts": len(self.results["vhosts"]),
                "screenshots": len(self.results["screenshots"]),
            },
        }


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Multi-source OSINT recon tool — emails, subdomains, IPs, URLs.",
        epilog="Examples:\n  python recon.py -d example.com -b all\n  python recon.py -d example.com -b google,crtsh -l 200 -o json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain")
    p.add_argument("-b", "--sources", default="all",
                   help="Comma-separated sources: google,bing,baidu,yahoo,crtsh,dns,otx,wayback,github,pastes,dnsdumpster,threatcrowd,rapiddns,urlscan,bufferover,certspotter,shodan_idb,linkedin,shodan,hunter,securitytrails,virustotal,dns_brute (default: all)")
    p.add_argument("-l", "--limit", type=int, default=100, help="Max results per source (default: 100)")
    p.add_argument("-t", "--timeout", type=int, default=20, help="HTTP timeout per request (default: 20s)")
    p.add_argument("-o", "--output", choices=["text", "json", "html"], default="text", help="Output format (default: text)")
    p.add_argument("-w", "--wordlist", help="Custom wordlist file for DNS brute force (one subdomain per line)")
    p.add_argument("-c", "--dns-brute", action="store_true", help="Enable DNS brute force subdomain discovery")
    p.add_argument("-p", "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080, socks5://127.0.0.1:9050)")
    p.add_argument("--takeover", action="store_true", help="Check subdomains for takeover vulnerabilities")
    p.add_argument("--scrape", action="store_true", help="Scrape page content for emails and names")
    p.add_argument("-r", "--dns-resolve", action="store_true", help="Resolve all discovered subdomains to IPs")
    p.add_argument("--vhost", action="store_true", help="Detect virtual hosts (multiple subdomains on same IP)")
    p.add_argument("--screenshot", metavar="DIR", help="Take screenshots of discovered subdomains (requires selenium)")
    p.add_argument("-a", "--api-scan", action="store_true", help="Scan for API endpoints on discovered subdomains")
    p.add_argument("-s", "--shodan", action="store_true", help="Enrich hosts with Shodan data (requires SHODAN_API_KEY)")
    p.add_argument("-e", "--dns-server", metavar="DNS", help="Custom DNS server for resolution")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress missing API key warnings")
    p.add_argument("--no-banner", action="store_true", help="Suppress banner")
    return p.parse_args()


def _save_html(path: str, data: dict, elapsed: float):
    s = data["stats"]
    rows = ""
    for label, items in [
        ("Emails", data["emails"]),
        ("Subdomains", data["subdomains"]),
        ("IPs", data["ips"]),
        ("URLs", data["urls"]),
        ("People", data["names"]),
        ("Takeovers", data["takeovers"]),
        ("Virtual Hosts", data["vhosts"]),
        ("Screenshots", data["screenshots"]),
    ]:
        if items:
            rows += f"<h2>{label} ({len(items)})</h2><table><tr><th>#</th><th>Value</th></tr>"
            for i, v in enumerate(items, 1):
                cls = "takeover" if label == "Takeovers" else ""
                rows += f"<tr class='{cls}'><td>{i}</td><td>{v}</td></tr>"
            rows += "</table>"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Recon Report — {data["domain"]}</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 40px; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
h2 {{ color: #f0883e; margin-top: 30px; }}
.stats {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
.stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px 25px; text-align: center; }}
.stat .num {{ font-size: 28px; font-weight: bold; color: #58a6ff; }}
.stat .lbl {{ font-size: 12px; color: #8b949e; text-transform: uppercase; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ background: #161b22; color: #58a6ff; }}
tr:hover {{ background: #1c2128; }}
.takeover td {{ color: #f85149; font-weight: bold; }}
.footer {{ margin-top: 40px; color: #8b949e; font-size: 12px; border-top: 1px solid #30363d; padding-top: 10px; }}
</style>
</head><body>
<h1>🔍 Recon Report — {data["domain"]}</h1>
<div class="stats">
<div class="stat"><div class="num">{s["emails"]}</div><div class="lbl">Emails</div></div>
<div class="stat"><div class="num">{s["subdomains"]}</div><div class="lbl">Subdomains</div></div>
<div class="stat"><div class="num">{s["ips"]}</div><div class="lbl">IPs</div></div>
<div class="stat"><div class="num">{s["urls"]}</div><div class="lbl">URLs</div></div>
<div class="stat"><div class="num">{s["names"]}</div><div class="lbl">People</div></div>
<div class="stat"><div class="num">{s["takeovers"]}</div><div class="lbl">Takeovers</div></div>
<div class="stat"><div class="num">{s["vhosts"]}</div><div class="lbl">VHosts</div></div>
<div class="stat"><div class="num">{s["screenshots"]}</div><div class="lbl">Screenshots</div></div>
<div class="stat"><div class="num">{elapsed:.1f}s</div><div class="lbl">Time</div></div>
</div>
{rows}
<div class="footer">Generated by recon-tool v{VERSION} — PORT 777</div>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)


def main():
    args = parse_args()
    if not args.no_banner:
        banner()

    wordlist = DNS_WORDLIST
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [w.strip().lower() for w in f.read().splitlines() if w.strip()]
            print(f"{Colors.INFO}[*] Wordlist:{Colors.R} {args.wordlist} ({len(wordlist)} words){Colors.R}")
        except FileNotFoundError:
            print(f"{Colors.ERR}[!] Wordlist not found: {args.wordlist}{Colors.R}")
            return

    if args.proxy:
        print(f"{Colors.INFO}[*] Proxy:{Colors.R} {args.proxy}{Colors.R}")

    config_path = Path.home() / ".recon-tool" / "api-keys.yaml"
    if config_path.exists():
        print(f"{Colors.INFO}Read api-keys from {config_path}{Colors.R}")

    api_sources = ["shodan", "hunter", "securitytrails", "virustotal"]
    if args.sources == "all":
        sources = ["google", "bing", "baidu", "yahoo", "crtsh", "dns", "otx", "wayback", "github", "pastes", "dnsdumpster", "threatcrowd", "rapiddns", "urlscan", "bufferover", "certspotter", "shodan_idb", "linkedin"]
        for s in api_sources:
            if API_KEYS.get(s):
                sources.append(s)
            elif not args.quiet:
                print(f"{Colors.WARN}[!] Missing API key for {s}{Colors.R}")
    else:
        sources = [s.strip().lower() for s in args.sources.split(",")]
        for s in sources:
            if s in api_sources and not API_KEYS.get(s) and not args.quiet:
                print(f"{Colors.WARN}[!] Missing API key for {s}{Colors.R}")

    # Flag-based sources (add to whatever -b specified)
    if args.dns_brute:
        sources.append("dns_brute")
    if args.takeover:
        sources.append("takeover")
    if args.scrape:
        sources.append("scrape")
    if args.dns_resolve:
        sources.append("dns_resolve")
    if args.vhost:
        sources.append("vhost")
    if args.api_scan:
        sources.append("api_scan")
    if args.shodan:
        sources.append("shodan_enrich")
        if not API_KEYS.get("shodan") and not args.quiet:
            print(f"{Colors.WARN}[!] Missing API key for shodan (required for -s){Colors.R}")
    if args.screenshot:
        sources.append(f"screenshot={args.screenshot}")
    if args.dns_server:
        sources.append(f"dns_custom={args.dns_server}")

    print(f"{Colors.INFO}[*] Target:{Colors.R} {args.domain}")
    print(f"{Colors.INFO}[*] Sources:{Colors.R} {', '.join(sources)}")
    print(f"{Colors.INFO}[*] Limit:{Colors.R} {args.limit}\n")

    async def run():
        engine = ReconEngine(args.domain, args.limit, args.timeout, wordlist, args.proxy)
        try:
            await engine.run_all(sources)
        except asyncio.CancelledError:
            print(f"\n{Colors.WARN}[!] Interrupted.{Colors.R}")
        finally:
            await engine.close()
        return engine.summary()

    start = time.time()
    try:
        data = asyncio.run(run())
    except KeyboardInterrupt:
        print(f"\n{Colors.WARN}[!] Interrupted.{Colors.R}")
        return

    elapsed = time.time() - start

    if args.output == "json":
        print(json.dumps(data, indent=2))
    else:
        stats = data["stats"]
        print(f"\n{Colors.OK}═══ Results for {args.domain} ═══{Colors.R}")
        print(f"{Colors.INFO}  Emails:     {Colors.OK}{stats['emails']}{Colors.R}")
        print(f"{Colors.INFO}  Subdomains: {Colors.OK}{stats['subdomains']}{Colors.R}")
        print(f"{Colors.INFO}  IPs:        {Colors.OK}{stats['ips']}{Colors.R}")
        print(f"{Colors.INFO}  URLs:       {Colors.OK}{stats['urls']}{Colors.R}")
        print(f"{Colors.INFO}  Names:      {Colors.OK}{stats['names']}{Colors.R}")
        print(f"{Colors.INFO}  VHosts:     {Colors.OK}{stats['vhosts']}{Colors.R}")
        print(f"{Colors.INFO}  Screenshots:{Colors.OK}{stats['screenshots']}{Colors.R}")
        print(f"{Colors.INFO}  Time:       {elapsed:.1f}s\n")

        if data["emails"]:
            print(f"{Colors.OK}── Emails ──{Colors.R}")
            for e in data["emails"]:
                print(f"  {e}")
            print()

        if data["subdomains"]:
            print(f"{Colors.OK}── Subdomains ──{Colors.R}")
            for s in data["subdomains"][:50]:
                print(f"  {s}")
            if len(data["subdomains"]) > 50:
                print(f"  ... and {len(data['subdomains']) - 50} more (use -l to increase limit)")
            print()

        if data["ips"]:
            print(f"{Colors.OK}── IPs ──{Colors.R}")
            for ip in data["ips"][:30]:
                print(f"  {ip}")
            print()

        if data["names"]:
            print(f"{Colors.OK}── People ──{Colors.R}")
            for name in data["names"][:30]:
                print(f"  {name}")
            print()

        if data["takeovers"]:
            print(f"{Colors.ERR}── Takeovers ──{Colors.R}")
            for t in data["takeovers"]:
                print(f"  {Colors.WARN}{t}{Colors.R}")
            print()

        if data["vhosts"]:
            print(f"{Colors.INFO}── Virtual Hosts ──{Colors.R}")
            for v in data["vhosts"][:20]:
                print(f"  {v}")
            print()

    # Save to file
    ts = int(time.time())
    if args.output == "json":
        fname = f"recon_{args.domain}_{ts}.json"
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n{Colors.OK}[+] Saved to {fname}{Colors.R}")
    elif args.output == "html":
        fname = f"recon_{args.domain}_{ts}.html"
        _save_html(fname, data, elapsed)
        print(f"\n{Colors.OK}[+] Saved to {fname}{Colors.R}")


if __name__ == "__main__":
    main()
