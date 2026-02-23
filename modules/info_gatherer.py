#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
import whois
import dns.resolver
import dns.reversename
import requests
import json
import re
from datetime import datetime
from rich.console import Console

console = Console()

class DomainInfo:
    def __init__(self, domain, timeout=30, user_agent=None):
        self.domain = domain
        self.timeout = timeout
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {}

    def get_ip_addresses(self):
        """Get IPv4 and IPv6 addresses"""
        ips = {'ipv4': [], 'ipv6': []}
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            ips['ipv4'] = [str(r) for r in answers]
        except Exception:
            pass
        try:
            answers = dns.resolver.resolve(self.domain, 'AAAA')
            ips['ipv6'] = [str(r) for r in answers]
        except Exception:
            pass
        return ips

    def get_dns_records(self):
        """Get all DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        return records

    def get_whois_info(self):
        """Get WHOIS information"""
        try:
            w = whois.whois(self.domain)
            info = {}
            fields = ['domain_name', 'registrar', 'creation_date', 'expiration_date',
                      'updated_date', 'name_servers', 'status', 'emails',
                      'org', 'country', 'city', 'state']
            for field in fields:
                val = getattr(w, field, None)
                if val:
                    if isinstance(val, list):
                        val = [str(v) for v in val]
                    elif isinstance(val, datetime):
                        val = str(val)
                    info[field] = val
            return info
        except Exception as e:
            return {'error': str(e)}

    def get_ssl_certificate(self):
        """Get SSL certificate details"""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(self.timeout)
                s.connect((self.domain, 443))
                cert = s.getpeercert()

            info = {
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'version': cert.get('version'),
                'serial_number': cert.get('serialNumber'),
                'not_before': cert.get('notBefore'),
                'not_after': cert.get('notAfter'),
                'san': []
            }

            for entry in cert.get('subjectAltName', []):
                if entry[0] == 'DNS':
                    info['san'].append(entry[1])

            # Check expiry
            try:
                exp = datetime.strptime(info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_left = (exp - datetime.utcnow()).days
                info['days_until_expiry'] = days_left
                info['expired'] = days_left < 0
            except Exception:
                pass

            return info
        except Exception as e:
            return {'error': str(e)}

    def get_http_headers(self):
        """Get HTTP headers and detect technologies"""
        headers_info = {}
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{self.domain}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout,
                                    allow_redirects=True, verify=False)
                headers_info = {
                    'status_code': resp.status_code,
                    'final_url': resp.url,
                    'headers': dict(resp.headers),
                    'redirect_chain': [r.url for r in resp.history]
                }

                # Security headers analysis
                security_headers = [
                    'Strict-Transport-Security', 'Content-Security-Policy',
                    'X-Frame-Options', 'X-Content-Type-Options',
                    'Referrer-Policy', 'Permissions-Policy',
                    'X-XSS-Protection'
                ]
                headers_info['security_headers'] = {}
                for sh in security_headers:
                    headers_info['security_headers'][sh] = resp.headers.get(sh, 'MISSING')

                # Technology detection
                tech = []
                server = resp.headers.get('Server', '')
                powered_by = resp.headers.get('X-Powered-By', '')
                if server:
                    tech.append(f"Server: {server}")
                if powered_by:
                    tech.append(f"X-Powered-By: {powered_by}")

                # Detect from body
                body = resp.text[:50000]
                if 'wp-content' in body or 'wp-includes' in body:
                    tech.append('WordPress')
                if 'Joomla' in body or '/components/com_' in body:
                    tech.append('Joomla')
                if 'Drupal' in body:
                    tech.append('Drupal')
                if 'laravel' in body.lower():
                    tech.append('Laravel')
                if 'Django' in body or 'csrfmiddlewaretoken' in body:
                    tech.append('Django')
                if 'React' in body or 'react.min.js' in body:
                    tech.append('React')
                if 'Vue.js' in body or 'vue.min.js' in body:
                    tech.append('Vue.js')
                if 'Angular' in body:
                    tech.append('Angular')
                if 'jquery' in body.lower():
                    tech.append('jQuery')
                if 'bootstrap' in body.lower():
                    tech.append('Bootstrap')
                if 'cloudflare' in body.lower() or 'cloudflare' in server.lower():
                    tech.append('Cloudflare CDN/WAF')

                headers_info['technologies'] = tech
                break
            except Exception as e:
                headers_info['error'] = str(e)
        return headers_info

    def get_geolocation(self):
        """Get IP geolocation"""
        try:
            ip = socket.gethostbyname(self.domain)
            resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=self.timeout)
            data = resp.json()
            return {
                'ip': ip,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'org': data.get('org'),
                'timezone': data.get('timezone'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude')
            }
        except Exception as e:
            return {'error': str(e)}

    def check_dnssec(self):
        """Check DNSSEC status"""
        try:
            answers = dns.resolver.resolve(self.domain, 'DNSKEY')
            return {'enabled': True, 'keys': len(list(answers))}
        except Exception:
            return {'enabled': False}

    def gather_info(self):
        """Gather all domain information"""
        console.print(f"  [cyan]→[/cyan] Resolving IP addresses...")
        self.results['ip_addresses'] = self.get_ip_addresses()

        console.print(f"  [cyan]→[/cyan] Fetching DNS records...")
        self.results['dns_records'] = self.get_dns_records()

        console.print(f"  [cyan]→[/cyan] Querying WHOIS...")
        self.results['whois'] = self.get_whois_info()

        console.print(f"  [cyan]→[/cyan] Checking SSL certificate...")
        self.results['ssl'] = self.get_ssl_certificate()

        console.print(f"  [cyan]→[/cyan] Analyzing HTTP headers...")
        self.results['http'] = self.get_http_headers()

        console.print(f"  [cyan]→[/cyan] Getting geolocation...")
        self.results['geolocation'] = self.get_geolocation()

        console.print(f"  [cyan]→[/cyan] Checking DNSSEC...")
        self.results['dnssec'] = self.check_dnssec()

        # Display summary
        ips = self.results['ip_addresses'].get('ipv4', [])
        console.print(f"  [green]✓[/green] IP: {', '.join(ips) if ips else 'N/A'}")

        whois_data = self.results['whois']
        if 'registrar' in whois_data:
            console.print(f"  [green]✓[/green] Registrar: {whois_data['registrar']}")

        ssl_data = self.results['ssl']
        if 'days_until_expiry' in ssl_data:
            d = ssl_data['days_until_expiry']
            color = 'green' if d > 30 else 'yellow' if d > 0 else 'red'
            console.print(f"  [{color}]✓[/{color}] SSL expires in {d} days")

        return self.results
