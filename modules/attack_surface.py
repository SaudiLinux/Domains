#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import requests
import threading
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console

console = Console()

class AttackSurfaceMapper:
    def __init__(self, domain, threads=10, timeout=30):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {}

        # Common ports to scan
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            119: 'NNTP', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            161: 'SNMP', 194: 'IRC', 443: 'HTTPS', 445: 'SMB',
            465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
            1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            2082: 'cPanel', 2083: 'cPanel SSL', 2086: 'WHM', 2087: 'WHM SSL',
            2181: 'Zookeeper', 3000: 'Dev Server', 3306: 'MySQL',
            3389: 'RDP', 4000: 'Dev Server', 4443: 'Alt HTTPS',
            5000: 'Dev Server', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 7001: 'WebLogic', 8000: 'Alt HTTP',
            8008: 'Alt HTTP', 8080: 'Alt HTTP', 8081: 'Alt HTTP',
            8082: 'Alt HTTP', 8083: 'Alt HTTP', 8088: 'Alt HTTP',
            8090: 'Alt HTTP', 8443: 'Alt HTTPS', 8444: 'Alt HTTPS',
            8880: 'Plesk', 8888: 'Alt HTTP', 9000: 'Dev Server',
            9090: 'Webmin', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
            10000: 'Webmin', 10050: 'Zabbix', 11211: 'Memcached',
            27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB',
        }

    def scan_port(self, ip, port, service):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout / 10)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                # Try to grab banner
                banner = self.grab_banner(ip, port)
                return {
                    'port': port,
                    'service': service,
                    'state': 'open',
                    'banner': banner
                }
        except Exception:
            pass
        return None

    def grab_banner(self, ip, port):
        """Grab service banner"""
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else ''
        except Exception:
            return ''

    def scan_ports(self):
        """Scan common ports"""
        console.print(f"  [cyan]→[/cyan] Scanning {len(self.common_ports)} ports...")
        open_ports = []

        try:
            ip = socket.gethostbyname(self.domain)
        except Exception:
            return {'error': 'Could not resolve domain', 'open_ports': []}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip, port, service): port
                for port, service in self.common_ports.items()
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x['port'])
        console.print(f"  [green]✓[/green] Found {len(open_ports)} open ports")
        for p in open_ports:
            console.print(f"    [green]OPEN[/green] {p['port']}/{p['service']}" +
                          (f" - {p['banner'][:60]}" if p['banner'] else ""))

        return {'ip': ip, 'open_ports': open_ports}

    def analyze_security_headers(self):
        """Analyze security headers"""
        console.print(f"  [cyan]→[/cyan] Analyzing security headers...")
        try:
            resp = requests.get(f"https://{self.domain}", headers=self.headers,
                                timeout=self.timeout, verify=False)

            security_checks = {
                'Strict-Transport-Security': {
                    'present': False, 'value': None,
                    'recommendation': 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'present': False, 'value': None,
                    'recommendation': 'Add CSP header to prevent XSS attacks'
                },
                'X-Frame-Options': {
                    'present': False, 'value': None,
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
                },
                'X-Content-Type-Options': {
                    'present': False, 'value': None,
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'Referrer-Policy': {
                    'present': False, 'value': None,
                    'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
                },
                'Permissions-Policy': {
                    'present': False, 'value': None,
                    'recommendation': 'Add Permissions-Policy to control browser features'
                },
                'X-XSS-Protection': {
                    'present': False, 'value': None,
                    'recommendation': 'Add X-XSS-Protection: 1; mode=block'
                },
            }

            for header in security_checks:
                val = resp.headers.get(header)
                if val:
                    security_checks[header]['present'] = True
                    security_checks[header]['value'] = val

            score = sum(1 for h in security_checks.values() if h['present'])
            return {
                'score': f"{score}/{len(security_checks)}",
                'headers': security_checks
            }
        except Exception as e:
            return {'error': str(e)}

    def detect_waf_cdn(self):
        """Detect WAF and CDN"""
        console.print(f"  [cyan]→[/cyan] Detecting WAF/CDN...")
        detected = []
        try:
            resp = requests.get(f"https://{self.domain}", headers=self.headers,
                                timeout=self.timeout, verify=False)
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body = resp.text.lower()
            server = headers.get('server', '')

            # CDN Detection
            waf_cdn_signatures = {
                'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare'],
                'Fastly': ['x-fastly-request-id', 'fastly'],
                'Akamai': ['x-akamai-request-id', 'akamai'],
                'AWS CloudFront': ['x-amz-cf-id', 'via', 'cloudfront'],
                'Incapsula': ['x-iinfo', 'incap_ses', 'visid_incap'],
                'F5 BIG-IP': ['x-cnection', 'bigip', 'f5'],
                'Sucuri': ['x-sucuri-id', 'sucuri'],
                'StackPath': ['x-sp-url', 'stackpath'],
                'Varnish': ['x-varnish', 'age'],
                'Nginx': ['nginx' in server],
                'Apache': ['apache' in server],
                'Microsoft IIS': ['iis' in server],
            }

            for name, signatures in waf_cdn_signatures.items():
                for sig in signatures:
                    if isinstance(sig, bool):
                        if sig:
                            detected.append(name)
                        break
                    elif sig in headers or sig in body or sig in server:
                        detected.append(name)
                        break

        except Exception as e:
            return {'error': str(e), 'detected': []}

        console.print(f"  [green]✓[/green] Detected: {', '.join(detected) if detected else 'None'}")
        return {'detected': list(set(detected))}

    def detect_technologies(self):
        """Detect web technologies"""
        console.print(f"  [cyan]→[/cyan] Detecting technologies...")
        techs = []
        try:
            resp = requests.get(f"https://{self.domain}", headers=self.headers,
                                timeout=self.timeout, verify=False)
            body = resp.text
            headers = {k.lower(): v for k, v in resp.headers.items()}
            server = headers.get('server', '')
            powered_by = headers.get('x-powered-by', '')

            tech_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Joomla': ['joomla', '/components/com_'],
                'Drupal': ['drupal', 'sites/default/files'],
                'Magento': ['magento', 'mage', 'skin/frontend'],
                'PrestaShop': ['prestashop', 'prestashop.com'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'WooCommerce': ['woocommerce', 'wc-ajax'],
                'Laravel': ['laravel_session', 'laravel'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'React': ['react', '__REACT_DEVTOOLS'],
                'Vue.js': ['vue.js', '__vue__'],
                'Angular': ['ng-version', 'angular.js'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap.min.css', 'bootstrap.min.js'],
                'PHP': ['php' in powered_by.lower() or '.php' in resp.url],
                'ASP.NET': ['asp.net' in powered_by.lower() or '.aspx' in resp.url],
                'Node.js': ['express' in powered_by.lower(), 'node.js' in powered_by.lower()],
                'Ruby on Rails': ['rails' in powered_by.lower()],
                'Google Analytics': ['google-analytics.com', 'gtag', 'ga('],
                'Google Tag Manager': ['googletagmanager.com'],
                'Font Awesome': ['fontawesome', 'font-awesome'],
                'Cloudflare': ['cloudflare'],
            }

            for tech, sigs in tech_signatures.items():
                for sig in sigs:
                    if isinstance(sig, bool):
                        if sig:
                            techs.append(tech)
                        break
                    elif sig.lower() in body.lower() or sig.lower() in server.lower():
                        techs.append(tech)
                        break

        except Exception as e:
            return {'error': str(e), 'technologies': []}

        techs = list(set(techs))
        console.print(f"  [green]✓[/green] Technologies: {', '.join(techs) if techs else 'Unknown'}")
        return {'technologies': techs}

    def check_http_methods(self):
        """Check allowed HTTP methods"""
        console.print(f"  [cyan]→[/cyan] Checking HTTP methods...")
        allowed = []
        dangerous = []
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']

        try:
            resp = requests.options(f"https://{self.domain}", headers=self.headers,
                                    timeout=self.timeout, verify=False)
            allow_header = resp.headers.get('Allow', '') or resp.headers.get('access-control-allow-methods', '')
            if allow_header:
                methods = [m.strip() for m in allow_header.split(',')]
                allowed = methods
                dangerous = [m for m in methods if m in dangerous_methods]
        except Exception:
            pass

        return {
            'allowed': allowed,
            'dangerous': dangerous
        }

    def map(self):
        """Run all attack surface mapping"""
        self.results['ports'] = self.scan_ports()
        self.results['security_headers'] = self.analyze_security_headers()
        self.results['waf_cdn'] = self.detect_waf_cdn()
        self.results['technologies'] = self.detect_technologies()
        self.results['http_methods'] = self.check_http_methods()
        return self.results
