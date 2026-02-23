#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import socket
import whois
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()

class DomainInfo:
    """Domain information gathering module"""
    
    def __init__(self, domain, timeout=30, user_agent=None):
        self.domain = domain
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.headers = {'User-Agent': self.user_agent}
        
    def gather_info(self):
        """Gather comprehensive domain information"""
        console.print("[yellow]⟳ جاري جمع معلومات النطاق...[/yellow]")
        
        info = {
            'domain': self.domain,
            'ip_addresses': self._get_ip_addresses(),
            'whois_info': self._get_whois_info(),
            'dns_records': self._get_dns_records(),
            'http_info': self._get_http_info(),
            'ssl_info': self._get_ssl_info()
        }
        
        self._display_info(info)
        return info
    
    def _get_ip_addresses(self):
        """Get IP addresses for domain"""
        try:
            ips = socket.gethostbyname_ex(self.domain)[2]
            console.print(f"[green]✓ عناوين IP: {', '.join(ips)}[/green]")
            return ips
        except Exception as e:
            console.print(f"[red]✗ فشل الحصول على IP: {str(e)}[/red]")
            return []
    
    def _get_whois_info(self):
        """Get WHOIS information"""
        try:
            w = whois.whois(self.domain)
            console.print(f"[green]✓ تم الحصول على معلومات WHOIS[/green]")
            return {
                'registrar': w.registrar if hasattr(w, 'registrar') else 'N/A',
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else 'N/A',
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else 'N/A',
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else []
            }
        except Exception as e:
            console.print(f"[yellow]⚠ معلومات WHOIS غير متاحة: {str(e)}[/yellow]")
            return {}
    
    def _get_dns_records(self):
        """Get DNS records"""
        records = {}
        try:
            import dns.resolver
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except:
                    records[record_type] = []
            console.print(f"[green]✓ تم الحصول على سجلات DNS[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ فشل الحصول على سجلات DNS: {str(e)}[/yellow]")
        return records
    
    def _get_http_info(self):
        """Get HTTP information"""
        info = {}
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{self.domain}"
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
                info[protocol] = {
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'N/A'),
                    'content_type': response.headers.get('Content-Type', 'N/A'),
                    'content_length': response.headers.get('Content-Length', 'N/A'),
                    'headers': dict(response.headers)
                }
                console.print(f"[green]✓ {protocol.upper()}: {response.status_code}[/green]")
            except Exception as e:
                info[protocol] = {'error': str(e)}
        return info
    
    def _get_ssl_info(self):
        """Get SSL certificate information"""
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    console.print(f"[green]✓ تم الحصول على معلومات SSL[/green]")
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            console.print(f"[yellow]⚠ SSL غير متاح: {str(e)}[/yellow]")
            return {}
    
    def _display_info(self, info):
        """Display gathered information in a formatted table"""
        table = Table(title="[bold cyan]معلومات النطاق[/bold cyan]", show_header=True, header_style="bold magenta")
        table.add_column("المعلومة", style="cyan", width=20)
        table.add_column("القيمة", style="white", width=60)
        
        table.add_row("النطاق", info['domain'])
        table.add_row("عناوين IP", ", ".join(info['ip_addresses']) if info['ip_addresses'] else "N/A")
        
        if info['whois_info']:
            table.add_row("المسجل", str(info['whois_info'].get('registrar', 'N/A')))
            table.add_row("تاريخ الإنشاء", str(info['whois_info'].get('creation_date', 'N/A')))
        
        console.print(table)
