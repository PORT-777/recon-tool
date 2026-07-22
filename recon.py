#!/usr/bin/env python3
"""
recon.py — Multi-source OSINT recon tool.
Extracts emails, subdomains, IPs, names, and URLs from public sources.

Usage:
    python recon.py -d example.com -b google -l 100
    python recon.py -d example.com -b all -l 200 -o json

Author: PORT 777
"""

import argparse, asyncio, json, re, sys, time
from urllib.parse import quote, urlparse, parse_qs
from email.utils import parseaddr
from collections import defaultdict

import httpx
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "2.0.0"

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
    def __init__(self, domain: str, limit: int = 100, timeout: int = 20):
        self.domain = domain.lower().strip()
        self.limit = limit
        self.client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) recon-tool/2.0"}
        )
        self.results = defaultdict(set)

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
        }
        for src in sources:
            fn = source_map.get(src)
            if fn:
                tasks.append(fn())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.extract_emails_from_urls()

    def summary(self):
        return {
            "domain": self.domain,
            "emails": sorted(self.results["emails"]),
            "subdomains": sorted(self.results["subdomains"]),
            "ips": sorted(self.results["ips"]),
            "urls": sorted(self.results["urls"])[:self.limit],
            "stats": {
                "emails": len(self.results["emails"]),
                "subdomains": len(self.results["subdomains"]),
                "ips": len(self.results["ips"]),
                "urls": min(len(self.results["urls"]), self.limit),
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
                   help="Comma-separated sources: google,bing,baidu,yahoo,crtsh,dns,otx,wayback,github,pastes,dnsdumpster,threatcrowd,rapiddns,urlscan,bufferover,certspotter,shodan_idb (default: all)")
    p.add_argument("-l", "--limit", type=int, default=100, help="Max results per source (default: 100)")
    p.add_argument("-t", "--timeout", type=int, default=20, help="HTTP timeout per request (default: 20s)")
    p.add_argument("-o", "--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p.add_argument("--no-banner", action="store_true", help="Suppress banner")
    return p.parse_args()


def main():
    args = parse_args()
    if not args.no_banner:
        banner()

    sources = ["google", "bing", "baidu", "yahoo", "crtsh", "dns", "otx", "wayback", "github", "pastes", "dnsdumpster", "threatcrowd", "rapiddns", "urlscan", "bufferover", "certspotter", "shodan_idb"]
    if args.sources != "all":
        sources = [s.strip().lower() for s in args.sources.split(",")]

    print(f"{Colors.INFO}[*] Target:{Colors.R} {args.domain}")
    print(f"{Colors.INFO}[*] Sources:{Colors.R} {', '.join(sources)}")
    print(f"{Colors.INFO}[*] Limit:{Colors.R} {args.limit}\n")

    async def run():
        engine = ReconEngine(args.domain, args.limit, args.timeout)
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

    # Save to file
    if args.output == "json":
        fname = f"recon_{args.domain}_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n{Colors.OK}[+] Saved to {fname}{Colors.R}")


if __name__ == "__main__":
    main()
