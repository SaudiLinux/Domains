#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import logging
import importlib

def check_requirements():
    """Check if all required packages are installed"""
    required = [
        'requests', 'bs4', 'dns', 'whois', 'rich',
        'colorama', 'tqdm', 'aiohttp'
    ]
    missing = []
    for pkg in required:
        try:
            importlib.import_module(pkg)
        except ImportError:
            # Try alternate names
            alt_names = {'bs4': 'beautifulsoup4', 'dns': 'dnspython'}
            missing.append(alt_names.get(pkg, pkg))

    if missing:
        from rich.console import Console
        Console().print(f"[red]Missing packages: {', '.join(missing)}[/red]")
        Console().print("[yellow]Run: pip install -r requirements.txt[/yellow]")
        return False
    return True

def is_valid_domain(domain):
    """Validate a domain name"""
    if not domain:
        return False
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    # Domain pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    # Suppress urllib3 warnings
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    return logging.getLogger('domain_scanner')

def clean_domain(domain):
    """Clean and normalize domain"""
    domain = domain.strip().lower()
    domain = domain.replace('http://', '').replace('https://', '')
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    return domain
