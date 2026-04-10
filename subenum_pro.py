#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              SubEnum Pro - Advanced Subdomain Hunter         ║
║         Deep Recon | Multi-Source | Live Validation          ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python3 subenum_pro.py -d target.com
    python3 subenum_pro.py -d target.com -o results/ -t 100
    python3 subenum_pro.py -d target.com --brute --wordlist dns.txt --deep
    python3 subenum_pro.py -d target.com --ports --screenshots

Requires (install before use):
    pip install aiohttp aiodns colorama dnspython tqdm requests

Optional tools (auto-detected, massively boosts results if present):
    subfinder, amass, assetfinder, findomain, httpx, massdns, puredns

Author: SubEnum Pro | Ravindu  |  For authorized testing only.
"""

import asyncio
import aiohttp
import aiodns
import argparse
import dns.resolver
import json
import os
import re
import socket
import subprocess
import sys
import time
import ipaddress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
 ██████╗ ██╗   ██╗██████╗ ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝ ██║   ██║██╔══██╗██╔════╝████╗  ██║██║   ██║████╗ ████║
╚█████╗  ██║   ██║██████╦╝█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
 ╚═══██╗ ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
██████╔╝ ╚██████╔╝██████╦╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚═════╝   ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
{Fore.YELLOW}          ██████╗ ██████╗  ██████╗
          ██╔══██╗██╔══██╗██╔═══██╗
          ██████╔╝██████╔╝██║   ██║
          ██╔═══╝ ██╔══██╗██║   ██║
          ██║     ██║  ██║╚██████╔╝
          ╚═╝     ╚═╝  ╚═╝ ╚═════╝
{Fore.GREEN}        Advanced Subdomain Enumeration Engine by Ravindu Lakmina
{Fore.WHITE}        Bug Hunting Edition  |  Multi-Source  |  Async
{Style.RESET_ALL}"""

# ─── Configuration ─────────────────────────────────────────────────────────

# Public DNS resolvers — high-performance, reliable
DNS_RESOLVERS = [
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "8.8.8.8", "8.8.4.4",           # Google
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",       # Verisign
    "77.88.8.8", "77.88.8.1",       # Yandex
    "8.26.56.26", "8.20.247.20",    # Comodo
]

# Passive API sources — no keys required
PASSIVE_SOURCES = {
    "crt.sh":          "https://crt.sh/?q=%.{domain}&output=json",
    "hackertarget":    "https://api.hackertarget.com/hostsearch/?q={domain}",
    "rapiddns":        "https://rapiddns.io/subdomain/{domain}?full=1",
    "alienvault":      "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "urlscan":         "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000",
    "threatminer":     "https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
    "anubis":          "https://jldc.me/anubis/subdomains/{domain}",
    "archive":         "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
    "riddler":         "https://riddler.io/search/exportcsv?q=pld:{domain}",
    "certspotter":     "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
    "subdomainfinder": "https://subdomainfinder.c99.nl/api.php?domain={domain}",
    "dnsdumpster":     "https://dnsdumpster.com/",   # needs CSRF, handled separately
    "sonar":           "https://sonar.omnisint.io/subdomains/{domain}",
    "synapsint":       "https://synapsint.com/report.php?q={domain}",
    "bufferover":      "https://dns.bufferover.run/dns?q=.{domain}",
    "sitedossier":     "http://www.sitedossier.com/parentdomain/{domain}",
    "dnstable":        "https://www.dnsdb.info/lookup/rrset/name/*.{domain}/",
}

# Common subdomain prefixes for smart brute-force
SMART_PREFIXES = [
    # Core infrastructure
    "www", "mail", "smtp", "pop", "imap", "mx", "ns", "ns1", "ns2",
    "ftp", "sftp", "ssh", "vpn", "proxy", "gateway",
    # Web services
    "api", "api2", "api3", "apiv1", "apiv2", "rest", "graphql",
    "app", "app1", "app2", "apps", "web", "web1", "web2",
    "mobile", "m", "wap", "cdn", "static", "assets", "media",
    # Dev/Staging
    "dev", "development", "staging", "stage", "stg", "uat", "qa",
    "test", "testing", "sandbox", "demo", "preview", "beta", "alpha",
    "preprod", "pre-prod", "pre", "canary", "feature",
    # Admin/Backend
    "admin", "administrator", "panel", "dashboard", "portal",
    "backend", "internal", "intranet", "extranet", "corp",
    "manage", "management", "control", "console",
    # Infrastructure
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "kafka", "rabbit", "queue", "cache", "memcache",
    "ldap", "ad", "auth", "sso", "login", "oauth",
    # Monitoring/Tools
    "monitor", "monitoring", "grafana", "kibana", "prometheus",
    "jenkins", "jira", "confluence", "gitlab", "github", "bitbucket",
    "sonar", "nexus", "artifactory", "vault", "consul",
    # Cloud/CDN
    "s3", "storage", "blob", "bucket", "files", "upload", "uploads",
    "img", "images", "pics", "videos", "docs",
    # Support/CRM
    "support", "help", "helpdesk", "ticket", "tickets", "crm",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    # Misc common
    "old", "new", "v1", "v2", "v3", "legacy", "archive", "backup",
    "secure", "security", "ssl", "tls", "vpn2", "remote",
    "git", "svn", "wiki", "blog", "forum", "news",
    "us", "eu", "uk", "asia", "global", "aws", "gcp", "azure",
]

# ─── Utility ──────────────────────────────────────────────────────────────────

def log(msg, level="INFO"):
    icons = {
        "INFO":    f"{Fore.CYAN}[*]{Style.RESET_ALL}",
        "SUCCESS": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
        "WARN":    f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
        "ERROR":   f"{Fore.RED}[-]{Style.RESET_ALL}",
        "FOUND":   f"{Fore.GREEN}{Style.BRIGHT}[FOUND]{Style.RESET_ALL}",
        "SECTION": f"{Fore.MAGENTA}{Style.BRIGHT}[>>]{Style.RESET_ALL}",
    }
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.WHITE}{Style.DIM}[{ts}]{Style.RESET_ALL} {icons.get(level,'[?]')} {msg}")

def sanitize_domain(domain):
    """Strip protocol and paths, return clean domain."""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    return domain

def is_valid_subdomain(subdomain, base_domain):
    """Validate a subdomain string."""
    if not subdomain:
        return False
    subdomain = subdomain.lower().strip()
    if not subdomain.endswith('.' + base_domain) and subdomain != base_domain:
        return False
    # RFC 1123 hostname check
    if not re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,253}[a-z0-9])?$', subdomain):
        return False
    return True

def tool_exists(name):
    """Check if an external tool is available in PATH."""
    return subprocess.run(
        ["which", name], capture_output=True
    ).returncode == 0

# ─── Passive Enumeration ──────────────────────────────────────────────────────

class PassiveEnumerator:
    def __init__(self, domain, timeout=15):
        self.domain = domain
        self.timeout = timeout
        self.results = set()

    async def fetch(self, session, name, url):
        """Generic async HTTP fetch with error handling."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   ssl=False,
                                   headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}) as resp:
                if resp.status == 200:
                    return name, await resp.text()
        except Exception:
            pass
        return name, None

    def parse_crtsh(self, data):
        subs = set()
        try:
            entries = json.loads(data)
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if is_valid_subdomain(name, self.domain):
                        subs.add(name)
        except Exception:
            pass
        return subs

    def parse_hackertarget(self, data):
        subs = set()
        for line in data.splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip()
                if is_valid_subdomain(sub, self.domain):
                    subs.add(sub)
        return subs

    def parse_alienvault(self, data):
        subs = set()
        try:
            j = json.loads(data)
            for record in j.get("passive_dns", []):
                h = record.get("hostname", "").strip()
                if is_valid_subdomain(h, self.domain):
                    subs.add(h)
        except Exception:
            pass
        return subs

    def parse_urlscan(self, data):
        subs = set()
        try:
            j = json.loads(data)
            for result in j.get("results", []):
                page = result.get("page", {})
                domain = page.get("domain", "")
                if is_valid_subdomain(domain, self.domain):
                    subs.add(domain)
        except Exception:
            pass
        return subs

    def parse_threatminer(self, data):
        subs = set()
        try:
            j = json.loads(data)
            for sub in j.get("results", []):
                sub = sub.strip()
                if is_valid_subdomain(sub, self.domain):
                    subs.add(sub)
        except Exception:
            pass
        return subs

    def parse_anubis(self, data):
        subs = set()
        try:
            entries = json.loads(data)
            if isinstance(entries, list):
                for e in entries:
                    e = str(e).strip()
                    if is_valid_subdomain(e, self.domain):
                        subs.add(e)
        except Exception:
            pass
        return subs

    def parse_archive(self, data):
        subs = set()
        for line in data.splitlines():
            try:
                parsed = urlparse(line.strip())
                host = parsed.netloc or parsed.path
                host = host.strip("/")
                if is_valid_subdomain(host, self.domain):
                    subs.add(host)
            except Exception:
                pass
        return subs

    def parse_certspotter(self, data):
        subs = set()
        try:
            j = json.loads(data)
            for entry in j:
                for name in entry.get("dns_names", []):
                    name = name.lstrip("*.")
                    if is_valid_subdomain(name, self.domain):
                        subs.add(name)
        except Exception:
            pass
        return subs

    def parse_bufferover(self, data):
        subs = set()
        try:
            j = json.loads(data)
            for record in j.get("FDNS_A", []) + j.get("RDNS", []):
                parts = record.split(",")
                for p in parts:
                    p = p.strip()
                    if is_valid_subdomain(p, self.domain):
                        subs.add(p)
        except Exception:
            pass
        return subs

    def parse_sonar(self, data):
        subs = set()
        try:
            entries = json.loads(data)
            if isinstance(entries, list):
                for e in entries:
                    e = str(e).strip()
                    if is_valid_subdomain(e, self.domain):
                        subs.add(e)
        except Exception:
            pass
        return subs

    def parse_generic_regex(self, data):
        """Fallback: extract anything that looks like a subdomain."""
        subs = set()
        pattern = rf'[a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+)*\.{re.escape(self.domain)}'
        for match in re.finditer(pattern, data, re.IGNORECASE):
            sub = match.group(0).lower().lstrip("*.")
            if is_valid_subdomain(sub, self.domain):
                subs.add(sub)
        return subs

    PARSERS = {
        "crt.sh":       "parse_crtsh",
        "hackertarget": "parse_hackertarget",
        "alienvault":   "parse_alienvault",
        "urlscan":      "parse_urlscan",
        "threatminer":  "parse_threatminer",
        "anubis":       "parse_anubis",
        "archive":      "parse_archive",
        "certspotter":  "parse_certspotter",
        "bufferover":   "parse_bufferover",
        "sonar":        "parse_sonar",
    }

    async def run(self):
        log(f"Running {len(PASSIVE_SOURCES)} passive API sources...", "SECTION")
        urls = {
            name: url.format(domain=self.domain)
            for name, url in PASSIVE_SOURCES.items()
            if name != "dnsdumpster"  # handled separately
        }

        connector = aiohttp.TCPConnector(limit=30, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch(session, name, url) for name, url in urls.items()]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        source_counts = {}
        for item in results:
            if isinstance(item, tuple):
                name, data = item
                if data:
                    parser_name = self.PARSERS.get(name)
                    if parser_name:
                        found = getattr(self, parser_name)(data)
                    else:
                        found = self.parse_generic_regex(data)
                    source_counts[name] = len(found)
                    self.results.update(found)

        for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            if count > 0:
                log(f"  {src:<20} → {Fore.GREEN}{count}{Style.RESET_ALL} subdomains", "SUCCESS")

        log(f"Passive enumeration complete: {Fore.GREEN}{len(self.results)}{Style.RESET_ALL} unique subdomains", "SUCCESS")
        return self.results


# ─── DNS Zone Transfer ────────────────────────────────────────────────────────

def try_zone_transfer(domain):
    """Attempt AXFR zone transfer against all NS records."""
    found = set()
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_str = str(ns).rstrip('.')
            log(f"Trying AXFR on {ns_str}...", "INFO")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, timeout=10))
                for name in zone.nodes.keys():
                    sub = f"{name}.{domain}".strip('.')
                    if sub and sub != domain:
                        found.add(sub)
                log(f"Zone transfer SUCCESS on {ns_str}! Got {len(found)} records", "SUCCESS")
            except Exception:
                pass
    except Exception:
        pass
    return found


# ─── DNS Brute Force ──────────────────────────────────────────────────────────

class BruteForcer:
    def __init__(self, domain, wordlist=None, concurrency=200, resolvers=None):
        self.domain = domain
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.resolvers = resolvers or DNS_RESOLVERS
        self.results = set()
        self._resolver_idx = 0

    def next_resolver(self):
        r = self.resolvers[self._resolver_idx % len(self.resolvers)]
        self._resolver_idx += 1
        return r

    def get_wordlist(self):
        if self.wordlist and os.path.exists(self.wordlist):
            with open(self.wordlist) as f:
                words = [l.strip() for l in f if l.strip()]
            log(f"Loaded {len(words)} words from wordlist: {self.wordlist}", "INFO")
            return words
        else:
            log(f"Using built-in smart prefix list ({len(SMART_PREFIXES)} entries)", "INFO")
            return SMART_PREFIXES

    async def resolve_one(self, semaphore, resolver, subdomain):
        async with semaphore:
            try:
                loop = asyncio.get_event_loop()
                r = aiodns.DNSResolver(loop=loop, nameservers=[resolver])
                await r.query(subdomain, 'A')
                return subdomain
            except Exception:
                return None

    async def run(self):
        words = self.get_wordlist()
        targets = [f"{w}.{self.domain}" for w in words]
        log(f"Brute-forcing {len(targets)} candidates with {self.concurrency} concurrent resolvers...", "SECTION")

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = []
        for i, t in enumerate(targets):
            resolver = self.resolvers[i % len(self.resolvers)]
            tasks.append(self.resolve_one(semaphore, resolver, t))

        results = await asyncio.gather(*tasks)
        self.results = {r for r in results if r}
        log(f"Brute-force complete: {Fore.GREEN}{len(self.results)}{Style.RESET_ALL} resolved", "SUCCESS")
        return self.results


# ─── External Tool Integration ────────────────────────────────────────────────

class ExternalTools:
    def __init__(self, domain, output_dir):
        self.domain = domain
        self.output_dir = output_dir
        self.results = set()

    def run_cmd(self, cmd, label):
        log(f"Running: {label}", "INFO")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            log(f"{label} timed out", "WARN")
        except Exception as e:
            log(f"{label} failed: {e}", "ERROR")
        return ""

    def extract_subdomains(self, text):
        subs = set()
        pattern = rf'[a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+)*\.{re.escape(self.domain)}'
        for match in re.finditer(pattern, text, re.IGNORECASE):
            sub = match.group(0).lower()
            if is_valid_subdomain(sub, self.domain):
                subs.add(sub)
        return subs

    def run_subfinder(self):
        if not tool_exists("subfinder"):
            return set()
        out = os.path.join(self.output_dir, "subfinder.txt")
        self.run_cmd(
            f"subfinder -d {self.domain} -all -recursive -silent -o {out}",
            "subfinder"
        )
        subs = set()
        if os.path.exists(out):
            with open(out) as f:
                for line in f:
                    sub = line.strip()
                    if is_valid_subdomain(sub, self.domain):
                        subs.add(sub)
        log(f"subfinder → {Fore.GREEN}{len(subs)}{Style.RESET_ALL} subdomains", "SUCCESS")
        return subs

    def run_amass(self):
        if not tool_exists("amass"):
            return set()
        out = os.path.join(self.output_dir, "amass.txt")
        self.run_cmd(
            f"amass enum -passive -d {self.domain} -o {out} -timeout 10",
            "amass (passive)"
        )
        subs = set()
        if os.path.exists(out):
            with open(out) as f:
                for line in f:
                    sub = line.strip()
                    if is_valid_subdomain(sub, self.domain):
                        subs.add(sub)
        log(f"amass → {Fore.GREEN}{len(subs)}{Style.RESET_ALL} subdomains", "SUCCESS")
        return subs

    def run_assetfinder(self):
        if not tool_exists("assetfinder"):
            return set()
        output = self.run_cmd(
            f"assetfinder --subs-only {self.domain}",
            "assetfinder"
        )
        subs = self.extract_subdomains(output)
        log(f"assetfinder → {Fore.GREEN}{len(subs)}{Style.RESET_ALL} subdomains", "SUCCESS")
        return subs

    def run_findomain(self):
        if not tool_exists("findomain"):
            return set()
        output = self.run_cmd(
            f"findomain -t {self.domain} --quiet",
            "findomain"
        )
        subs = self.extract_subdomains(output)
        log(f"findomain → {Fore.GREEN}{len(subs)}{Style.RESET_ALL} subdomains", "SUCCESS")
        return subs

    def run_all(self):
        log("Checking for installed external tools...", "SECTION")
        tools_found = []
        for tool in ["subfinder", "amass", "assetfinder", "findomain"]:
            if tool_exists(tool):
                tools_found.append(tool)
        if not tools_found:
            log("No external tools found. Install subfinder/amass for better results.", "WARN")
            return set()
        log(f"External tools available: {', '.join(tools_found)}", "INFO")
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(self.run_subfinder): "subfinder",
                ex.submit(self.run_amass):     "amass",
                ex.submit(self.run_assetfinder):"assetfinder",
                ex.submit(self.run_findomain): "findomain",
            }
            for f in as_completed(futures):
                self.results.update(f.result())
        return self.results


# ─── DNS Resolution & Enrichment ─────────────────────────────────────────────

class DNSResolver:
    def __init__(self, domain, concurrency=300):
        self.domain = domain
        self.concurrency = concurrency
        self.resolved = {}   # subdomain -> {ips, cname, mx, txt}

    async def resolve_full(self, semaphore, subdomain):
        async with semaphore:
            info = {"subdomain": subdomain, "ips": [], "cname": None, "status": "dead"}
            resolver_ip = DNS_RESOLVERS[hash(subdomain) % len(DNS_RESOLVERS)]
            try:
                loop = asyncio.get_event_loop()
                r = aiodns.DNSResolver(loop=loop, nameservers=[resolver_ip])
                # Try CNAME first
                try:
                    cname = await r.query(subdomain, 'CNAME')
                    info["cname"] = str(cname.cname).rstrip('.')
                except Exception:
                    pass
                # A record
                try:
                    a_records = await r.query(subdomain, 'A')
                    info["ips"] = [r.host for r in a_records]
                    info["status"] = "alive"
                except Exception:
                    pass
                # AAAA
                if not info["ips"]:
                    try:
                        aaaa = await r.query(subdomain, 'AAAA')
                        info["ips"] = [r.host for r in aaaa]
                        info["status"] = "alive"
                    except Exception:
                        pass
            except Exception:
                pass
            return info

    async def run(self, subdomains):
        log(f"Resolving {len(subdomains)} subdomains via async DNS...", "SECTION")
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self.resolve_full(semaphore, sub) for sub in subdomains]

        if TQDM_AVAILABLE:
            results = []
            for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks),
                             desc="Resolving", unit="sub",
                             bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Style.RESET_ALL)):
                results.append(await coro)
        else:
            results = await asyncio.gather(*tasks)

        alive = 0
        for info in results:
            if info["status"] == "alive":
                self.resolved[info["subdomain"]] = info
                alive += 1

        log(f"DNS resolution: {Fore.GREEN}{alive} alive{Style.RESET_ALL} / {len(subdomains)} total", "SUCCESS")
        return self.resolved


# ─── HTTP Probing ─────────────────────────────────────────────────────────────

class HTTPProber:
    def __init__(self, concurrency=100, timeout=8):
        self.concurrency = concurrency
        self.timeout = timeout
        self.results = {}

    async def probe_one(self, semaphore, session, subdomain):
        async with semaphore:
            result = {
                "subdomain": subdomain,
                "status_code": None,
                "title": None,
                "redirect": None,
                "tech": [],
                "alive_http": False,
                "scheme": None,
                "length": 0,
            }
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}"
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True, ssl=False,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
                    ) as resp:
                        body = await resp.text(errors='replace')
                        result["status_code"] = resp.status
                        result["scheme"] = scheme
                        result["alive_http"] = True
                        result["length"] = len(body)
                        # Extract title
                        m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.IGNORECASE)
                        if m:
                            result["title"] = m.group(1).strip()
                        # Detect redirect
                        if str(resp.url) != url:
                            result["redirect"] = str(resp.url)
                        # Basic tech fingerprinting from headers
                        server = resp.headers.get("Server", "")
                        powered = resp.headers.get("X-Powered-By", "")
                        if server:
                            result["tech"].append(f"Server:{server}")
                        if powered:
                            result["tech"].append(f"X-Powered-By:{powered}")
                        break  # https worked, no need for http
                except Exception:
                    continue
            return result

    async def run(self, subdomains):
        log(f"HTTP probing {len(subdomains)} hosts...", "SECTION")
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False,
                                         limit_per_host=5)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.probe_one(semaphore, session, sub) for sub in subdomains]
            if TQDM_AVAILABLE:
                results = []
                for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks),
                                 desc="HTTP Probe", unit="host",
                                 bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)):
                    results.append(await coro)
            else:
                results = await asyncio.gather(*tasks)

        for r in results:
            if r["alive_http"]:
                self.results[r["subdomain"]] = r

        log(f"HTTP probing: {Fore.GREEN}{len(self.results)} live HTTP services{Style.RESET_ALL}", "SUCCESS")
        return self.results


# ─── Subdomain Takeover Detection ────────────────────────────────────────────

# Signatures for dangling CNAME services
TAKEOVER_FINGERPRINTS = {
    "github.io":          "There isn't a GitHub Pages site here",
    "amazonaws.com":      "NoSuchBucket",
    "herokucdn.com":      "No such app",
    "herokuapp.com":      "No such app",
    "azure-api.net":      "404 Web Site not found",
    "azurewebsites.net":  "404 Web Site not found",
    "cloudfront.net":     "ERROR: The request could not be satisfied",
    "fastly.net":         "Fastly error: unknown domain",
    "pantheon.io":        "The gods are wise",
    "helpscoutdocs.com":  "No settings were found for this company",
    "zendesk.com":        "Help Center Closed",
    "shopify.com":        "Sorry, this shop is currently unavailable",
    "cargo.site":         "404 Not Found",
    "tumblr.com":         "There's nothing here",
    "ghost.io":           "The thing you were looking for is no longer here",
    "surge.sh":           "project not found",
    "netlify.app":        "Not Found",
    "readme.io":          "Project doesnt exist",
    "statuspage.io":      "Better luck next time",
    "tictail.com":        "to target URL",
    "wordpress.com":      "Do you want to register",
    "bitbucket.io":       "Repository not found",
}

async def check_takeover(semaphore, session, subdomain, cname):
    """Check if a CNAME points to an unclaimed service."""
    async with semaphore:
        if not cname:
            return None
        service = None
        for sig in TAKEOVER_FINGERPRINTS:
            if sig in cname:
                service = sig
                break
        if not service:
            return None
        # Fetch page and look for fingerprint
        try:
            url = f"https://{subdomain}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                   ssl=False) as resp:
                body = await resp.text(errors='replace')
                fingerprint = TAKEOVER_FINGERPRINTS[service]
                if fingerprint.lower() in body.lower():
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": service,
                        "fingerprint": fingerprint,
                    }
        except Exception:
            pass
        return None


# ─── Deep Permutation Engine ──────────────────────────────────────────────────

def generate_permutations(known_subs, domain, max_depth=2):
    """Generate smart permutations from known subdomains."""
    permutations = set()
    words = set()
    for sub in known_subs:
        parts = sub.replace(f".{domain}", "").split(".")
        words.update(parts)

    modifiers = ["dev", "test", "stg", "prod", "new", "old", "v2", "v3",
                 "api", "admin", "beta", "internal", "secure", "backup"]

    for w in list(words)[:100]:  # Cap to avoid explosion
        for m in modifiers:
            permutations.add(f"{w}-{m}.{domain}")
            permutations.add(f"{m}-{w}.{domain}")
            permutations.add(f"{w}.{m}.{domain}")

    return permutations - set(known_subs)


# ─── Port Scanner ─────────────────────────────────────────────────────────────

# Common ports worth scanning on bug bounty targets
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 443, 445, 587, 631,
    1080, 1443, 2082, 2083, 2086, 2087, 2095, 2096,
    3000, 3001, 3306, 3389, 4443, 4848, 5000, 5432,
    5900, 6379, 7000, 7001, 7070, 7443, 7474, 8000,
    8001, 8008, 8009, 8080, 8081, 8082, 8083, 8088,
    8090, 8099, 8161, 8180, 8443, 8444, 8500, 8800,
    8880, 8888, 8983, 9000, 9001, 9090, 9200, 9300,
    9443, 9999, 10000, 10250, 11211, 15672, 27017,
    28017, 50000, 50070,
]

# Port → service label
PORT_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-alt", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
    1080: "SOCKS", 2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM",
    2087: "WHM-SSL", 3000: "Dev/Grafana", 3001: "Dev", 3306: "MySQL",
    3389: "RDP", 4443: "HTTPS-alt", 4848: "GlassFish", 5000: "Dev/Docker",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 7001: "WebLogic",
    7474: "Neo4j", 8000: "Dev", 8080: "HTTP-proxy", 8081: "HTTP-alt",
    8088: "HTTP-alt", 8090: "Confluence", 8161: "ActiveMQ", 8180: "Tomcat",
    8443: "HTTPS-alt", 8500: "Consul", 8800: "HTTP-alt", 8888: "Jupyter",
    8983: "Solr", 9000: "PHP-FPM/SonarQube", 9090: "Prometheus/Cockpit",
    9200: "Elasticsearch", 9300: "Elasticsearch-cluster", 9443: "HTTPS-alt",
    10000: "Webmin", 10250: "Kubelet", 11211: "Memcached",
    15672: "RabbitMQ-UI", 27017: "MongoDB", 28017: "MongoDB-HTTP",
    50070: "Hadoop-HDFS",
}

class PortScanner:
    def __init__(self, concurrency=500, timeout=2):
        self.concurrency = concurrency
        self.timeout = timeout
        self.results = {}   # subdomain -> [open_ports]

    async def scan_port(self, semaphore, host, port):
        async with semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None

    async def scan_host(self, semaphore_host, host, ports):
        async with semaphore_host:
            port_sem = asyncio.Semaphore(30)  # max 30 ports per host at once
            tasks = [self.scan_port(port_sem, host, p) for p in ports]
            results = await asyncio.gather(*tasks)
            open_ports = [p for p in results if p is not None]
            return host, open_ports

    async def run(self, hosts, ports=None):
        ports = ports or COMMON_PORTS
        log(f"Port scanning {len(hosts)} hosts × {len(ports)} ports "
            f"({len(hosts)*len(ports):,} total checks)...", "SECTION")

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self.scan_host(semaphore, h, ports) for h in hosts]

        if TQDM_AVAILABLE:
            done = []
            for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks),
                             desc="Port Scan", unit="host",
                             bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.YELLOW, Style.RESET_ALL)):
                done.append(await coro)
        else:
            done = await asyncio.gather(*tasks)

        interesting = 0
        for host, open_ports in done:
            if open_ports:
                self.results[host] = open_ports
                interesting += 1

        log(f"Port scan complete: {Fore.GREEN}{interesting}{Style.RESET_ALL} hosts with open ports", "SUCCESS")
        return self.results

    def format_ports(self, open_ports):
        labeled = []
        for p in sorted(open_ports):
            label = PORT_LABELS.get(p, "unknown")
            labeled.append(f"{p}/{label}")
        return labeled


# ─── Screenshot Engine ────────────────────────────────────────────────────────

class ScreenshotEngine:
    """
    Takes screenshots of live HTTP services.
    Uses gowitness or eyewitness if installed (best quality).
    Falls back to a lightweight HTML thumbnail index using requests + base64.
    """
    def __init__(self, output_dir, timeout=15):
        self.output_dir = output_dir
        self.screenshots_dir = os.path.join(output_dir, "screenshots")
        self.timeout = timeout
        os.makedirs(self.screenshots_dir, exist_ok=True)

    def tool_screenshot(self, urls):
        """Use gowitness or eyewitness if available."""
        url_file = os.path.join(self.output_dir, "urls_for_screenshots.txt")
        with open(url_file, "w") as f:
            for u in urls:
                f.write(u + "\n")

        if tool_exists("gowitness"):
            log("Using gowitness for screenshots...", "INFO")
            cmd = (
                f"gowitness file -f {url_file} "
                f"--screenshot-path {self.screenshots_dir} "
                f"--timeout {self.timeout} --disable-logging"
            )
            subprocess.run(cmd, shell=True, capture_output=True, timeout=600)
            return True

        if tool_exists("eyewitness"):
            log("Using EyeWitness for screenshots...", "INFO")
            cmd = (
                f"eyewitness --web -f {url_file} "
                f"-d {self.screenshots_dir} --timeout {self.timeout} "
                f"--no-prompt --quiet"
            )
            subprocess.run(cmd, shell=True, capture_output=True, timeout=600)
            return True

        return False

    def generate_html_report(self, http_results, port_results=None):
        """
        Generate a standalone HTML report with:
        - Live URL list with status, title, tech
        - Port scan results if available
        - Screenshot placeholders (or embedded if gowitness ran)
        """
        log("Generating HTML visual report...", "INFO")

        rows = []
        for sub, info in sorted(http_results.items(),
                                  key=lambda x: x[1].get("status_code") or 999):
            url = f"{info['scheme']}://{sub}"
            status = info.get("status_code", "?")
            title = info.get("title") or ""
            tech = ", ".join(info.get("tech", []))
            length = info.get("length", 0)
            redirect = info.get("redirect") or ""
            ports = ""
            if port_results and sub in port_results:
                p = PortScanner()
                ports = " · ".join(p.format_ports(port_results[sub]))

            # Color badge based on status
            if str(status).startswith("2"):
                badge_color = "#22c55e"
            elif str(status).startswith("3"):
                badge_color = "#f59e0b"
            elif str(status).startswith("4"):
                badge_color = "#ef4444"
            else:
                badge_color = "#6b7280"

            # Check for screenshot file (gowitness naming)
            safe_url = re.sub(r'[^a-zA-Z0-9]', '_', url)
            screenshot_candidates = [
                os.path.join(self.screenshots_dir, f"{safe_url}.png"),
                os.path.join(self.screenshots_dir, f"{url.replace('://', '_').replace('/', '_')}.png"),
            ]
            screenshot_html = ""
            for sc in screenshot_candidates:
                if os.path.exists(sc):
                    import base64
                    with open(sc, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    screenshot_html = f'<img src="data:image/png;base64,{b64}" style="max-width:320px;border-radius:6px;margin-top:8px;" />'
                    break

            rows.append(f"""
            <tr>
                <td><a href="{url}" target="_blank" style="color:#60a5fa;font-family:monospace">{url}</a></td>
                <td><span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:12px;font-size:12px">{status}</span></td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{title}">{title}</td>
                <td style="font-size:11px;color:#9ca3af">{tech}</td>
                <td style="font-size:11px;color:#f59e0b;font-family:monospace">{ports}</td>
                <td style="font-size:11px">{length:,}</td>
                <td>{f'<a href="{redirect}" style="color:#a78bfa;font-size:11px">{redirect[:40]}...</a>' if redirect else ''}</td>
                {'<td>' + screenshot_html + '</td>' if screenshot_html else '<td></td>'}
            </tr>""")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SubEnum Pro — Results</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 24px; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; color: #60a5fa; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px 20px; }}
  .stat-val {{ font-size: 28px; font-weight: 700; color: #22c55e; }}
  .stat-label {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
  .search {{ width: 100%; padding: 10px 16px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 14px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead th {{ background: #1e293b; color: #94a3b8; padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; position: sticky; top: 0; }}
  tbody tr {{ border-bottom: 1px solid #1e293b; }}
  tbody tr:hover {{ background: #1e293b; }}
  td {{ padding: 8px 12px; vertical-align: top; }}
  .footer {{ margin-top: 24px; color: #475569; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<h1>🔍 SubEnum Pro — {http_results and list(http_results.keys())[0].split('.')[-2] + '.' + list(http_results.keys())[0].split('.')[-1] if http_results else 'Results'}</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; For authorized testing only</p>
<div class="stats">
  <div class="stat"><div class="stat-val">{len(http_results)}</div><div class="stat-label">Live HTTP Services</div></div>
  <div class="stat"><div class="stat-val">{sum(1 for i in http_results.values() if str(i.get('status_code','')).startswith('2'))}</div><div class="stat-label">200 OK</div></div>
  <div class="stat"><div class="stat-val">{sum(1 for i in http_results.values() if str(i.get('status_code','')).startswith('3'))}</div><div class="stat-label">Redirects</div></div>
  <div class="stat"><div class="stat-val">{len(port_results) if port_results else 0}</div><div class="stat-label">Hosts w/ Open Ports</div></div>
</div>
<input class="search" type="text" placeholder="🔍 Filter by URL, title, status..." onkeyup="filterTable(this.value)" />
<table id="results">
  <thead>
    <tr>
      <th>URL</th><th>Status</th><th>Title</th><th>Tech</th><th>Open Ports</th><th>Length</th><th>Redirect</th><th>Screenshot</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>
<div class="footer">SubEnum Pro &nbsp;|&nbsp; {len(http_results)} results &nbsp;|&nbsp; By Ravindu | Authorized use only</div>
<script>
function filterTable(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('#results tbody tr').forEach(tr => {{
    tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        report_path = os.path.join(self.output_dir, "report.html")
        with open(report_path, "w") as f:
            f.write(html)
        log(f"HTML report saved: {report_path}", "SUCCESS")
        return report_path

    def run(self, http_results, port_results=None):
        urls = [f"{info['scheme']}://{sub}" for sub, info in http_results.items()]
        log(f"Screenshot mode: {len(urls)} URLs to capture...", "SECTION")
        used_tool = self.tool_screenshot(urls)
        if not used_tool:
            log("gowitness/eyewitness not found — skipping pixel screenshots.", "WARN")
            log("Install gowitness: go install github.com/sensepost/gowitness@latest", "INFO")
        report = self.generate_html_report(http_results, port_results)
        return report


# ─── Output & Reporting ───────────────────────────────────────────────────────

class Reporter:
    def __init__(self, domain, output_dir):
        self.domain = domain
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save_all_subdomains(self, subs):
        path = os.path.join(self.output_dir, "all_subdomains.txt")
        with open(path, "w") as f:
            for s in sorted(subs):
                f.write(s + "\n")
        return path

    def save_live_urls(self, http_results):
        path = os.path.join(self.output_dir, "live_urls.txt")
        with open(path, "w") as f:
            for sub, info in sorted(http_results.items()):
                url = f"{info['scheme']}://{sub}"
                f.write(url + "\n")
        return path

    def save_json(self, http_results, dns_results, port_results=None):
        path = os.path.join(self.output_dir, "full_results.json")
        ps = PortScanner()
        data = []
        for sub, http in http_results.items():
            dns = dns_results.get(sub, {})
            open_ports = port_results.get(sub, []) if port_results else []
            data.append({
                "subdomain": sub,
                "url": f"{http['scheme']}://{sub}",
                "status_code": http["status_code"],
                "title": http["title"],
                "ips": dns.get("ips", []),
                "cname": dns.get("cname"),
                "tech": http["tech"],
                "content_length": http["length"],
                "redirect": http.get("redirect"),
                "open_ports": ps.format_ports(open_ports) if open_ports else [],
            })
        data.sort(key=lambda x: x["status_code"] or 999)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    def save_csv(self, http_results, dns_results, port_results=None):
        path = os.path.join(self.output_dir, "results.csv")
        ps = PortScanner()
        with open(path, "w") as f:
            f.write("subdomain,url,status,title,ips,cname,tech,open_ports,content_length\n")
            for sub, http in sorted(http_results.items()):
                dns = dns_results.get(sub, {})
                ips = "|".join(dns.get("ips", []))
                cname = dns.get("cname", "")
                tech = "|".join(http.get("tech", []))
                title = (http.get("title") or "").replace(",", " ")
                ports = "|".join(ps.format_ports(port_results.get(sub, []))) if port_results else ""
                f.write(
                    f'{sub},{http["scheme"]}://{sub},'
                    f'{http["status_code"]},{title},'
                    f'{ips},{cname},{tech},{ports},{http["length"]}\n'
                )
        return path

    def save_takeovers(self, takeovers):
        if not takeovers:
            return None
        path = os.path.join(self.output_dir, "potential_takeovers.txt")
        with open(path, "w") as f:
            for t in takeovers:
                f.write(
                    f"[TAKEOVER] {t['subdomain']} → {t['cname']} "
                    f"({t['service']}) :: {t['fingerprint']}\n"
                )
        return path

    def print_summary(self, all_subs, dns_results, http_results, takeovers):
        total = len(all_subs)
        resolved = len(dns_results)
        live_http = len(http_results)

        # Status code breakdown
        status_counts = defaultdict(int)
        for info in http_results.values():
            status_counts[info["status_code"]] += 1

        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*60}")
        print(f"  FINAL RESULTS SUMMARY — {self.domain}")
        print(f"{'═'*60}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Total subdomains found:  {Fore.GREEN}{Style.BRIGHT}{total}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}DNS resolved (alive):    {Fore.GREEN}{Style.BRIGHT}{resolved}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Live HTTP services:      {Fore.GREEN}{Style.BRIGHT}{live_http}{Style.RESET_ALL}")
        if takeovers:
            print(f"  {Fore.RED}{Style.BRIGHT}Potential takeovers:     {len(takeovers)}{Style.RESET_ALL}")
        print(f"\n  {Fore.CYAN}HTTP Status Breakdown:{Style.RESET_ALL}")
        for code, count in sorted(status_counts.items()):
            color = Fore.GREEN if str(code).startswith("2") else \
                    Fore.YELLOW if str(code).startswith("3") else \
                    Fore.RED if str(code).startswith("4") else Fore.WHITE
            print(f"    {color}{code}{Style.RESET_ALL}: {count}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'═'*60}{Style.RESET_ALL}\n")


# ─── Main Orchestrator ────────────────────────────────────────────────────────

async def main(args):
    domain = sanitize_domain(args.domain)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or f"subenum_{domain}_{ts}"
    os.makedirs(output_dir, exist_ok=True)

    print(BANNER)
    log(f"Target: {Fore.YELLOW}{Style.BRIGHT}{domain}{Style.RESET_ALL}", "INFO")
    log(f"Output: {output_dir}", "INFO")
    start_time = time.time()

    all_subs = set()

    # ── Phase 1: Passive ──────────────────────────────────────────────────────
    passive = PassiveEnumerator(domain, timeout=args.timeout)
    all_subs.update(await passive.run())
    log(f"After passive: {len(all_subs)} subdomains", "INFO")

    # ── Phase 2: External Tools ───────────────────────────────────────────────
    ext = ExternalTools(domain, output_dir)
    all_subs.update(ext.run_all())
    log(f"After external tools: {len(all_subs)} subdomains", "INFO")

    # ── Phase 3: Zone Transfer ────────────────────────────────────────────────
    log("Attempting DNS zone transfers...", "SECTION")
    zt_results = try_zone_transfer(domain)
    if zt_results:
        log(f"Zone transfer yielded {len(zt_results)} records!", "SUCCESS")
        all_subs.update(zt_results)

    # ── Phase 4: Brute Force ──────────────────────────────────────────────────
    if args.brute:
        brute = BruteForcer(
            domain, wordlist=args.wordlist,
            concurrency=args.threads,
            resolvers=DNS_RESOLVERS
        )
        brute_results = await brute.run()
        all_subs.update(brute_results)
        log(f"After brute force: {len(all_subs)} subdomains", "INFO")

    # ── Phase 5: Permutation ──────────────────────────────────────────────────
    if args.deep and all_subs:
        log("Generating smart permutations from discovered subdomains...", "SECTION")
        perms = generate_permutations(all_subs, domain)
        log(f"Testing {len(perms)} permutation candidates...", "INFO")
        brute2 = BruteForcer(domain, concurrency=args.threads, resolvers=DNS_RESOLVERS)
        brute2.wordlist = None
        # Resolve permutations directly
        semaphore = asyncio.Semaphore(args.threads)
        tasks = [brute2.resolve_one(semaphore, DNS_RESOLVERS[i % len(DNS_RESOLVERS)], p)
                 for i, p in enumerate(perms)]
        perm_results = await asyncio.gather(*tasks)
        new_subs = {r for r in perm_results if r}
        log(f"Permutation attack found {Fore.GREEN}{len(new_subs)}{Style.RESET_ALL} new subdomains", "SUCCESS")
        all_subs.update(new_subs)

    # ── Always add the base domain ────────────────────────────────────────────
    all_subs.add(domain)

    reporter = Reporter(domain, output_dir)
    reporter.save_all_subdomains(all_subs)
    log(f"Total unique subdomains: {Fore.GREEN}{Style.BRIGHT}{len(all_subs)}{Style.RESET_ALL}", "FOUND")

    # ── Phase 6: DNS Resolution ───────────────────────────────────────────────
    dns_resolver = DNSResolver(domain, concurrency=args.threads * 2)
    dns_results = await dns_resolver.run(all_subs)

    # ── Phase 7: HTTP Probing ─────────────────────────────────────────────────
    http_prober = HTTPProber(concurrency=args.threads, timeout=args.timeout)
    http_results = await http_prober.run(list(dns_results.keys()))

    # ── Phase 8: Takeover Detection ───────────────────────────────────────────
    log("Checking for subdomain takeover candidates...", "SECTION")
    takeovers = []
    semaphore = asyncio.Semaphore(50)
    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            check_takeover(semaphore, session, sub, info.get("cname"))
            for sub, info in dns_results.items()
        ]
        results = await asyncio.gather(*tasks)
        takeovers = [r for r in results if r]

    if takeovers:
        log(f"{Fore.RED}{Style.BRIGHT}⚠  {len(takeovers)} potential subdomain takeovers found!{Style.RESET_ALL}", "WARN")
        for t in takeovers:
            log(f"  {t['subdomain']} → {t['cname']} ({t['service']})", "WARN")

    # ── Phase 9: Port Scanning ────────────────────────────────────────────────
    port_results = None
    if args.ports:
        scanner = PortScanner(concurrency=500, timeout=2)
        port_results = await scanner.run(list(dns_results.keys()))
        # Print interesting findings
        high_value = {
            6379: "Redis (likely unauthenticated!)",
            27017: "MongoDB (likely unauthenticated!)",
            9200: "Elasticsearch (likely unauthenticated!)",
            11211: "Memcached (likely unauthenticated!)",
            5432: "PostgreSQL",
            3306: "MySQL",
            2375: "Docker daemon (CRITICAL!)",
            10250: "Kubelet API (CRITICAL!)",
            4848: "GlassFish Admin",
            7001: "WebLogic",
            50070: "Hadoop HDFS",
        }
        for host, ports in port_results.items():
            for p in ports:
                if p in high_value:
                    log(f"  {Fore.RED}{Style.BRIGHT}[HIGH VALUE] {host}:{p} — {high_value[p]}{Style.RESET_ALL}", "WARN")

    # ── Phase 10: Screenshots & HTML Report ───────────────────────────────────
    screener = ScreenshotEngine(output_dir, timeout=args.timeout)
    if args.screenshots:
        html_report = screener.run(http_results, port_results)
    else:
        # Just generate HTML report (no pixel screenshots)
        html_report = screener.generate_html_report(http_results, port_results)

    # ── Save outputs ──────────────────────────────────────────────────────────
    log("Saving results...", "SECTION")
    p1 = reporter.save_all_subdomains(all_subs)
    p2 = reporter.save_live_urls(http_results)
    p3 = reporter.save_json(http_results, dns_results, port_results)
    p4 = reporter.save_csv(http_results, dns_results, port_results)
    p5 = reporter.save_takeovers(takeovers)

    elapsed = time.time() - start_time
    reporter.print_summary(all_subs, dns_results, http_results, takeovers)

    log(f"Output files:", "INFO")
    log(f"  All subdomains : {p1}", "SUCCESS")
    log(f"  Live URLs      : {p2}", "SUCCESS")
    log(f"  JSON (full)    : {p3}", "SUCCESS")
    log(f"  CSV            : {p4}", "SUCCESS")
    if p5:
        log(f"  Takeovers      : {Fore.RED}{p5}{Style.RESET_ALL}", "SUCCESS")
    if html_report:
        log(f"  HTML Report    : {Fore.CYAN}{html_report}{Style.RESET_ALL}", "SUCCESS")
    if port_results:
        ports_file = os.path.join(output_dir, "open_ports.txt")
        ps = PortScanner()
        with open(ports_file, "w") as f:
            for host, ports in sorted(port_results.items()):
                labeled = ps.format_ports(ports)
                f.write(f"{host}: {', '.join(labeled)}\n")
        log(f"  Open Ports     : {ports_file}", "SUCCESS")
    log(f"Completed in {Fore.YELLOW}{elapsed:.1f}s{Style.RESET_ALL}", "SUCCESS")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="SubEnum Pro — Advanced Subdomain Enumeration for Bug Hunters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subenum_pro.py -d target.com
  python3 subenum_pro.py -d target.com --brute -t 300
  python3 subenum_pro.py -d target.com --brute --wordlist /path/to/dns.txt --deep
  python3 subenum_pro.py -d target.com --ports
  python3 subenum_pro.py -d target.com --ports --screenshots
  python3 subenum_pro.py -d target.com --brute --deep --ports --screenshots -o results/
        """
    )
    parser.add_argument("-d", "--domain", required=True,
                        help="Target domain (e.g. target.com or https://target.com)")
    parser.add_argument("-o", "--output",
                        help="Output directory (default: subenum_<domain>_<timestamp>)")
    parser.add_argument("-t", "--threads", type=int, default=150,
                        help="Concurrency level (default: 150)")
    parser.add_argument("--timeout", type=int, default=12,
                        help="HTTP request timeout in seconds (default: 12)")
    parser.add_argument("--brute", action="store_true",
                        help="Enable DNS brute-force (uses built-in list or --wordlist)")
    parser.add_argument("--wordlist",
                        help="Wordlist file for DNS brute-force")
    parser.add_argument("--deep", action="store_true",
                        help="Enable permutation attack after initial enumeration")
    parser.add_argument("--ports", action="store_true",
                        help="Enable port scanning on all live hosts (60+ ports)")
    parser.add_argument("--screenshots", action="store_true",
                        help="Take screenshots + generate HTML report (requires gowitness or eyewitness)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Partial results may have been saved.{Style.RESET_ALL}")
        sys.exit(0)