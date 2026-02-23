#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import concurrent.futures
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

class AdminFinder:
    """Admin panel finder module"""
    
    def __init__(self, domain, threads=10, timeout=10, wordlist=None, delay=0):
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.wordlist = wordlist or self._get_admin_paths()
        self.found_panels = []
        
    def _get_admin_paths(self):
        """Get admin panel paths wordlist"""
        return [
            'admin', 'administrator', 'admin.php', 'admin.html',
            'admin/', 'admin/login', 'admin/login.php', 'admin/index.php',
            'wp-admin', 'wp-admin/', 'wp-login.php',
            'administrator/', 'administrator/index.php',
            'admincp', 'admincp/', 'adminer.php', 'adminer',
            'phpmyadmin', 'phpmyadmin/', 'pma', 'myadmin',
            'cpanel', 'webmail', 'whm',
            'login', 'login.php', 'login/', 'signin', 'signin.php',
            'user/login', 'auth/login', 'account/login',
            'panel', 'dashboard', 'control', 'manage', 'management'
        ]
    
    def find(self):
        """Find admin panels"""
        console.print(f"[yellow]⟳ جاري البحث عن لوحات التحكم...[/yellow]")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]فحص لوحات التحكم...", total=len(self.wordlist))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._check_admin_path, path) for path in self.wordlist]
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.found_panels.append(result)
                        console.print(f"[green]✓ تم العثور على: {result['url']}[/green]")
                    progress.advance(task)
        
        self._display_results()
        return self.found_panels
    
    def _check_admin_path(self, path):
        """Check if admin path exists"""
        try:
            url = f"{self.base_url}/{path}"
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # علامات لوحة التحكم
            admin_keywords = [
                'login', 'username', 'password', 'admin', 'dashboard',
                'sign in', 'authentication', 'administrator', 'cpanel'
            ]
            
            if response.status_code == 200:
                content_lower = response.text.lower()
                if any(keyword in content_lower for keyword in admin_keywords):
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'title': self._extract_title(response.text)
                    }
        except:
            pass
        return None
    
    def _extract_title(self, html):
        """Extract page title"""
        try:
            import re
            title = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if title:
                return title.group(1).strip()[:50]
        except:
            pass
        return 'N/A'
    
    def _display_results(self):
        """Display found admin panels"""
        if not self.found_panels:
            console.print("[yellow]⚠ لم يتم العثور على لوحات تحكم[/yellow]")
            return
        
        table = Table(title=f"[bold green]تم العثور على {len(self.found_panels)} لوحة تحكم[/bold green]")
        table.add_column("الرابط", style="cyan", width=50)
        table.add_column("العنوان", style="white", width=30)
        
        for panel in self.found_panels:
            table.add_row(panel['url'], panel['title'])
        
        console.print(table)
