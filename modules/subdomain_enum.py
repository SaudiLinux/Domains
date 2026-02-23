#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import requests
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console

console = Console()

class SubdomainEnumerator:
    def __init__(self, domain, threads=10, timeout=30, wordlist=None, delay=0.0):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist
        self.delay = delay
        self.found_subdomains = set()
        self.lock = threading.Lock()

        # Built-in wordlist
        self.default_wordlist = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'remote',
            'vpn', 'ssh', 'rdp', 'dev', 'test', 'staging', 'api', 'admin',
            'portal', 'login', 'app', 'apps', 'secure', 'mx', 'blog', 'shop',
            'store', 'news', 'static', 'cdn', 'media', 'img', 'images', 'assets',
            'upload', 'uploads', 'download', 'downloads', 'docs', 'help', 'support',
            'forum', 'forums', 'community', 'wiki', 'kb', 'status', 'monitor',
            'git', 'gitlab', 'github', 'jenkins', 'jira', 'confluence', 'redmine',
            'grafana', 'kibana', 'elastic', 'db', 'database', 'mysql', 'postgres',
            'redis', 'mongo', 'cassandra', 'oracle', 'mssql', 'sql', 'backup',
            'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2', 'proxy', 'reverse',
            'load', 'lb', 'haproxy', 'nginx', 'apache', 'web', 'web1', 'web2',
            'server', 'server1', 'server2', 'node', 'node1', 'node2', 'cloud',
            'aws', 'azure', 'gcp', 'k8s', 'kubernetes', 'docker', 'container',
            'ci', 'cd', 'build', 'deploy', 'prod', 'production', 'live',
            'beta', 'alpha', 'demo', 'preview', 'sandbox', 'lab', 'research',
            'internal', 'intranet', 'extranet', 'corp', 'corporate', 'office',
            'hr', 'crm', 'erp', 'accounting', 'finance', 'sales', 'marketing',
            'analytics', 'tracking', 'metrics', 'stats', 'reports', 'dashboard',
            'management', 'mgmt', 'panel', 'cpanel', 'plesk', 'whm', 'webmin',
            'phpmyadmin', 'pma', 'adminer', 'wp-admin', 'webadmin', 'sysadmin',
            'm', 'mobile', 'wap', 'touch', 'pwa', 'socket', 'ws', 'websocket',
            'api2', 'apiv2', 'v1', 'v2', 'v3', 'rest', 'graphql', 'grpc',
            'auth', 'oauth', 'sso', 'ldap', 'ad', 'accounts', 'account',
            'billing', 'pay', 'payment', 'checkout', 'cart', 'order', 'orders',
            'search', 'cache', 'assets2', 'old', 'new', 'legacy', 'archive',
            'email', 'newsletter', 'smtp2', 'bounce', 'lists', 'autodiscover',
            'autoconfig', 'cpcontacts', 'cpcalendars', 'webdisk', 'whois',
        ]

    def passive_crtsh(self):
        """Enumerate subdomains via crt.sh"""
        console.print(f"  [cyan]→[/cyan] Querying crt.sh...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            with self.lock:
                                self.found_subdomains.add(sub)
        except Exception as e:
            console.print(f"  [yellow]![/yellow] crt.sh error: {e}")

    def passive_hackertarget(self):
        """Enumerate subdomains via HackerTarget API"""
        console.print(f"  [cyan]→[/cyan] Querying HackerTarget...")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                for line in resp.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            with self.lock:
                                self.found_subdomains.add(sub)
        except Exception as e:
            console.print(f"  [yellow]![/yellow] HackerTarget error: {e}")

    def passive_rapiddns(self):
        """Enumerate subdomains via RapidDNS"""
        console.print(f"  [cyan]→[/cyan] Querying RapidDNS...")
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                import re
                pattern = rf'([a-zA-Z0-9\-\_\.]+\.{re.escape(self.domain)})'
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    with self.lock:
                        self.found_subdomains.add(match.lower())
        except Exception as e:
            console.print(f"  [yellow]![/yellow] RapidDNS error: {e}")

    def passive_alienvault(self):
        """Enumerate subdomains via AlienVault OTX"""
        console.print(f"  [cyan]→[/cyan] Querying AlienVault OTX...")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').lower()
                    if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                        with self.lock:
                            self.found_subdomains.add(hostname)
        except Exception as e:
            console.print(f"  [yellow]![/yellow] AlienVault error: {e}")

    def passive_urlscan(self):
        """Enumerate subdomains via urlscan.io"""
        console.print(f"  [cyan]→[/cyan] Querying urlscan.io...")
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                import re
                for result in data.get('results', []):
                    page_url = result.get('page', {}).get('domain', '')
                    if page_url.endswith(f".{self.domain}") or page_url == self.domain:
                        with self.lock:
                            self.found_subdomains.add(page_url.lower())
        except Exception as e:
            console.print(f"  [yellow]![/yellow] urlscan.io error: {e}")

    def resolve_subdomain(self, subdomain):
        """Resolve a subdomain via DNS"""
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            fqdn = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(fqdn, 'A', lifetime=5)
            if answers:
                with self.lock:
                    self.found_subdomains.add(fqdn)
                return fqdn
        except Exception:
            pass
        return None

    def active_bruteforce(self):
        """Active DNS brute force"""
        console.print(f"  [cyan]→[/cyan] Running DNS brute force...")
        wordlist = self.default_wordlist
        if self.wordlist:
            try:
                with open(self.wordlist, 'r', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                console.print(f"  [yellow]![/yellow] Wordlist error: {e}")

        count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_subdomain, word): word for word in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    count += 1

        console.print(f"  [green]✓[/green] Brute force found {count} subdomains")

    def enumerate(self):
        """Run all enumeration methods"""
        # Passive methods
        self.passive_crtsh()
        self.passive_hackertarget()
        self.passive_rapiddns()
        self.passive_alienvault()
        self.passive_urlscan()

        # Active brute force
        self.active_bruteforce()

        # Resolve all found subdomains and get IPs
        resolved = {}
        for sub in self.found_subdomains:
            try:
                answers = dns.resolver.resolve(sub, 'A', lifetime=5)
                resolved[sub] = [str(r) for r in answers]
            except Exception:
                resolved[sub] = []

        console.print(f"  [green]✓[/green] Total unique subdomains found: [bold]{len(self.found_subdomains)}[/bold]")

        return {
            'total': len(self.found_subdomains),
            'subdomains': resolved
        }
