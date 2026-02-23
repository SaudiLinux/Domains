#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import concurrent.futures
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

console = Console()

class SubdomainEnumerator:
    """Subdomain enumeration module"""
    
    def __init__(self, domain, threads=10, timeout=10, wordlist=None, delay=0):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.wordlist = wordlist or self._get_default_wordlist()
        self.found_subdomains = []
        
    def _get_default_wordlist(self):
        """Get default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start',
            'sms', 'office', 'exchange', 'ipv4', 'web2', 'panel', 'dashboard', 'gateway'
        ]
    
    def enumerate(self):
        """Enumerate subdomains"""
        console.print(f"[yellow]⟳ جاري البحث عن النطاقات الفرعية لـ {self.domain}...[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]فحص النطاقات الفرعية...", total=len(self.wordlist))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for subdomain in self.wordlist:
                    future = executor.submit(self._check_subdomain, subdomain)
                    futures.append(future)
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.found_subdomains.append(result)
                    progress.advance(task)
                    if self.delay > 0:
                        time.sleep(self.delay)
        
        self._display_results()
        return self.found_subdomains
    
    def _check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{full_domain}"
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    verify=False, 
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                if response.status_code < 500:
                    return {
                        'subdomain': full_domain,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'title': self._extract_title(response.text)
                    }
        except:
            pass
        return None
    
    def _extract_title(self, html):
        """Extract page title from HTML"""
        try:
            import re
            title = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if title:
                return title.group(1).strip()[:50]
        except:
            pass
        return 'N/A'
    
    def _display_results(self):
        """Display found subdomains"""
        if not self.found_subdomains:
            console.print("[yellow]⚠ لم يتم العثور على نطاقات فرعية[/yellow]")
            return
        
        table = Table(title=f"[bold green]تم العثور على {len(self.found_subdomains)} نطاق فرعي[/bold green]")
        table.add_column("النطاق الفرعي", style="cyan", width=30)
        table.add_column("الرابط", style="blue", width=40)
        table.add_column("الحالة", style="green", width=10)
        table.add_column("العنوان", style="white", width=30)
        
        for sub in self.found_subdomains:
            status_color = 'green' if sub['status_code'] == 200 else 'yellow'
            table.add_row(
                sub['subdomain'],
                sub['url'],
                f"[{status_color}]{sub['status_code']}[/{status_color}]",
                sub['title']
            )
        
        console.print(table)
