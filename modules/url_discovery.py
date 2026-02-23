#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import concurrent.futures
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

class URLDiscovery:
    """URL discovery and path enumeration module"""
    
    def __init__(self, domain, threads=10, timeout=10, wordlist=None, delay=0):
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.wordlist = wordlist or self._get_default_wordlist()
        self.found_urls = []
        
    def _get_default_wordlist(self):
        """Get default URL wordlist"""
        return [
            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
            'dashboard', 'config', 'backup', 'test', 'dev', 'api',
            'upload', 'uploads', 'files', 'images', 'css', 'js',
            'includes', 'assets', 'static', 'media', 'tmp', 'temp'
        ]
    
    def discover(self):
        """Discover URLs and paths"""
        console.print(f"[yellow]⟳ جاري اكتشاف المسارات والروابط...[/yellow]")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]اكتشاف المسارات...", total=len(self.wordlist))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._check_path, path) for path in self.wordlist]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.found_urls.append(result)
                    progress.advance(task)
                    if self.delay > 0:
                        time.sleep(self.delay)
        
        self._display_results()
        return self.found_urls
    
    def _check_path(self, path):
        """Check if path exists"""
        try:
            url = f"{self.base_url}/{path}"
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                }
        except:
            pass
        return None
    
    def _display_results(self):
        """Display discovered URLs"""
        if not self.found_urls:
            console.print("[yellow]⚠ لم يتم اكتشاف مسارات جديدة[/yellow]")
            return
        
        table = Table(title=f"[bold green]تم اكتشاف {len(self.found_urls)} مسار[/bold green]")
        table.add_column("الرابط", style="cyan", width=50)
        table.add_column("الحالة", style="green", width=10)
        
        for url_info in self.found_urls:
            table.add_row(url_info['url'], str(url_info['status_code']))
        
        console.print(table)
