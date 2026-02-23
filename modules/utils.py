#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import logging
from urllib.parse import urlparse

def check_requirements():
    """Check if all required packages are installed"""
    required = [
        'requests', 'bs4', 'dnspython', 'whois', 
        'colorama', 'tqdm', 'rich', 'aiohttp'
    ]
    
    missing = []
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[!] Missing packages: {', '.join(missing)}")
        return False
    return True

def is_valid_domain(domain):
    """Validate domain name format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def clean_domain(domain):
    """Clean and normalize domain name"""
    # Remove protocol
    domain = domain.replace('https://', '').replace('http://', '')
    # Remove trailing slash
    domain = domain.rstrip('/')
    # Remove www
    domain = domain.replace('www.', '')
    # Extract domain from URL if path exists
    if '/' in domain:
        domain = domain.split('/')[0]
    return domain.lower()

def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)

def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def sanitize_filename(filename):
    """Sanitize filename for cross-platform compatibility"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def get_status_color(status_code):
    """Get color code for HTTP status"""
    if status_code >= 200 and status_code < 300:
        return 'green'
    elif status_code >= 300 and status_code < 400:
        return 'yellow'
    elif status_code >= 400 and status_code < 500:
        return 'red'
    elif status_code >= 500:
        return 'bold red'
    return 'white'

def format_size(size_bytes):
    """Format bytes to human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"
