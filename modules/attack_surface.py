#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from rich.console import Console
from rich.table import Table

console = Console()

class AttackSurfaceMapper:
    """Attack surface mapping module"""
    
    def __init__(self, domain, threads=10, timeout=15):
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.timeout = timeout
        self.attack_surface = {}
        
    def map(self):
        """Map attack surface"""
        console.print(f"[yellow]⟳ جاري رسم خريطة سطح الهجوم...[/yellow]")
        
        self.attack_surface = {
            'technologies': self._detect_technologies(),
            'ports': self._scan_common_ports(),
            'emails': self._find_emails(),
            'forms': self._find_forms(),
            'javascript': self._find_javascript_files()
        }
        
        self._display_results()
        return self.attack_surface
    
    def _detect_technologies(self):
        """Detect web technologies"""
        console.print("[dim]→ كشف التقنيات المستخدمة...[/dim]")
        technologies = []
        
        try:
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            headers = response.headers
            content = response.text.lower()
            
            # من الـ Headers
            if 'X-Powered-By' in headers:
                technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
            if 'Server' in headers:
                technologies.append(f"Server: {headers['Server']}")
            
            # من المحتوى
            tech_patterns = {
                'WordPress': 'wp-content',
                'Joomla': 'joomla',
                'Drupal': 'drupal',
                'Laravel': 'laravel',
                'React': 'react',
                'Vue.js': 'vue',
                'Angular': 'angular',
                'jQuery': 'jquery',
                'Bootstrap': 'bootstrap'
            }
            
            for tech, pattern in tech_patterns.items():
                if pattern in content:
                    technologies.append(tech)
            
            console.print(f"[green]✓ تم كشف {len(technologies)} تقنية[/green]")
        except Exception as e:
            console.print(f"[red]✗ خطأ: {str(e)}[/red]")
        
        return technologies
    
    def _scan_common_ports(self):
        """Scan common ports"""
        console.print("[dim]→ فحص المنافذ الشائعة...[/dim]")
        import socket
        
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        
        open_ports = []
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(f"{port} ({service})")
            except:
                pass
        
        console.print(f"[green]✓ تم العثور على {len(open_ports)} منفذ مفتوح[/green]")
        return open_ports
    
    def _find_emails(self):
        """Find email addresses"""
        console.print("[dim]→ البحث عن عناوين البريد الإلكتروني...[/dim]")
        import re
        
        emails = set()
        try:
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found = re.findall(email_pattern, response.text)
            emails.update(found)
            console.print(f"[green]✓ تم العثور على {len(emails)} بريد إلكتروني[/green]")
        except:
            pass
        
        return list(emails)
    
    def _find_forms(self):
        """Find HTML forms"""
        console.print("[dim]→ البحث عن النماذج...[/dim]")
        import re
        
        forms = []
        try:
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            form_pattern = r'<form[^>]*>(.*?)</form>'
            found = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
            forms = [f"Form {i+1}" for i in range(len(found))]
            console.print(f"[green]✓ تم العثور على {len(forms)} نموذج[/green]")
        except:
            pass
        
        return forms
    
    def _find_javascript_files(self):
        """Find JavaScript files"""
        console.print("[dim]→ البحث عن ملفات JavaScript...[/dim]")
        import re
        
        js_files = set()
        try:
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
            found = re.findall(js_pattern, response.text)
            js_files.update(found)
            console.print(f"[green]✓ تم العثور على {len(js_files)} ملف JS[/green]")
        except:
            pass
        
        return list(js_files)
    
    def _display_results(self):
        """Display attack surface"""
        table = Table(title="[bold cyan]خريطة سطح الهجوم[/bold cyan]")
        table.add_column("العنصر", style="yellow", width=20)
        table.add_column("التفاصيل", style="white", width=60)
        
        table.add_row("التقنيات", ", ".join(self.attack_surface['technologies']) if self.attack_surface['technologies'] else "N/A")
        table.add_row("المنافذ المفتوحة", ", ".join(self.attack_surface['ports']) if self.attack_surface['ports'] else "N/A")
        table.add_row("رسائل البريد", str(len(self.attack_surface['emails'])))
        table.add_row("النماذج", str(len(self.attack_surface['forms'])))
        table.add_row("ملفات JS", str(len(self.attack_surface['javascript'])))
        
        console.print(table)
