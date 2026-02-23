#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console

console = Console()

class URLDiscovery:
    def __init__(self, domain, threads=10, timeout=30, wordlist=None, delay=0.0):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist
        self.delay = delay
        self.found_urls = set()
        self.lock = threading.Lock()
        self.base_url = f"https://{domain}"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        # Common directories and files
        self.default_paths = [
            # Admin
            'admin', 'administrator', 'admin.php', 'admin.html', 'admin/',
            'wp-admin/', 'wp-login.php', 'wp-config.php',
            # Config files
            '.env', '.env.local', '.env.production', '.env.backup',
            'config.php', 'config.js', 'configuration.php', 'settings.py',
            'web.config', 'app.config', 'database.yml', 'secrets.yml',
            # Backup files
            'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql',
            'db.sql', 'database.sql', 'dump.sql', 'data.sql',
            'site.zip', 'website.zip', 'www.zip', 'html.zip',
            # Info files
            'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'crossdomain.xml',
            'security.txt', '.well-known/security.txt', 'humans.txt',
            'readme.md', 'README.md', 'README.txt', 'CHANGELOG.md',
            # Git/VCS
            '.git/HEAD', '.git/config', '.git/COMMIT_EDITMSG',
            '.gitignore', '.gitmodules', '.svn/entries',
            # PHP
            'phpinfo.php', 'info.php', 'test.php', 'install.php',
            'setup.php', 'upgrade.php', 'xmlrpc.php',
            # Logs
            'error.log', 'access.log', 'debug.log', 'application.log',
            'logs/', 'log/', 'error_log',
            # APIs
            'api/', 'api/v1/', 'api/v2/', 'graphql', 'swagger.json',
            'swagger.yaml', 'openapi.json', 'api-docs', 'docs/api',
            # Panels
            'phpmyadmin/', 'phpmyadmin/index.php', 'pma/', 'mysql/',
            'cpanel/', 'webmail/', 'roundcube/', 'squirrelmail/',
            # Common dirs
            'uploads/', 'upload/', 'files/', 'media/', 'images/',
            'assets/', 'static/', 'css/', 'js/', 'includes/',
            'lib/', 'src/', 'app/', 'tmp/', 'temp/',
            # Server status
            'server-status', 'server-info', '_profiler/',
            # Node.js
            'package.json', 'package-lock.json', 'yarn.lock',
            'node_modules/', '.npmrc',
            # Python
            'requirements.txt', 'Pipfile', 'manage.py',
            # Docker
            'Dockerfile', 'docker-compose.yml', '.dockerignore',
            # CI/CD
            '.travis.yml', '.github/', 'Jenkinsfile', '.circleci/',
            # Other
            'cgi-bin/', 'test/', 'tests/', 'dev/', 'old/',
            'new/', 'backup_old/', 'archive/',
        ]

    def check_path(self, path):
        """Check if a path exists"""
        if self.delay > 0:
            time.sleep(self.delay)
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{self.domain}/{path.lstrip('/')}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout,
                                    allow_redirects=False, verify=False)
                if resp.status_code in [200, 201, 202, 301, 302, 307, 308, 401, 403]:
                    with self.lock:
                        self.found_urls.add((url, resp.status_code, len(resp.content)))
                    return url, resp.status_code
                break
            except Exception:
                pass
        return None, None

    def crawl_page(self, url, depth=0, visited=None, max_depth=2):
        """Crawl a page and extract links"""
        if visited is None:
            visited = set()
        if url in visited or depth > max_depth:
            return set()

        visited.add(url)
        found = set()

        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout,
                                allow_redirects=True, verify=False)
            if 'text/html' not in resp.headers.get('Content-Type', ''):
                return found

            soup = BeautifulSoup(resp.text, 'html.parser')
            base_domain = urlparse(url).netloc

            # Extract all links
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                href = tag.get('href') or tag.get('src') or tag.get('action', '')
                if not href:
                    continue
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)

                # Only same domain
                if parsed.netloc == base_domain or parsed.netloc == '':
                    if parsed.scheme in ['http', 'https']:
                        with self.lock:
                            self.found_urls.add((full_url, 200, 0))
                        found.add(full_url)

            # Extract URLs from JS/inline scripts
            import re
            js_urls = re.findall(r'["\'](/[^"\'<>]+)["\']', resp.text)
            for js_url in js_urls:
                if any(js_url.endswith(ext) for ext in
                       ['.php', '.asp', '.aspx', '.jsp', '.json', '.xml', '.txt', '.html', '.js', '.css']):
                    full_url = urljoin(url, js_url)
                    with self.lock:
                        self.found_urls.add((full_url, 0, 0))

        except Exception:
            pass

        return found

    def discover_via_sitemap(self):
        """Parse sitemap.xml for URLs"""
        console.print(f"  [cyan]→[/cyan] Checking sitemap.xml...")
        found = []
        for sitemap_url in [
            f"https://{self.domain}/sitemap.xml",
            f"https://{self.domain}/sitemap_index.xml",
            f"https://{self.domain}/sitemap-index.xml",
        ]:
            try:
                resp = requests.get(sitemap_url, headers=self.headers, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    import re
                    urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
                    for u in urls:
                        with self.lock:
                            self.found_urls.add((u.strip(), 200, 0))
                        found.append(u.strip())
            except Exception:
                pass
        return found

    def discover_via_robots(self):
        """Parse robots.txt for paths"""
        console.print(f"  [cyan]→[/cyan] Checking robots.txt...")
        found = []
        try:
            resp = requests.get(f"https://{self.domain}/robots.txt",
                                headers=self.headers, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                import re
                paths = re.findall(r'(?:Disallow|Allow):\s*(/.*)', resp.text)
                for path in paths:
                    path = path.strip()
                    if path and path != '/':
                        url = f"https://{self.domain}{path}"
                        with self.lock:
                            self.found_urls.add((url, 0, 0))
                        found.append(url)
        except Exception:
            pass
        return found

    def discover(self):
        """Run all URL discovery methods"""
        # Parse robots.txt and sitemap
        self.discover_via_robots()
        self.discover_via_sitemap()

        # Web crawling
        console.print(f"  [cyan]→[/cyan] Crawling website...")
        self.crawl_page(f"https://{self.domain}", depth=0, max_depth=2)

        # Directory brute forcing
        console.print(f"  [cyan]→[/cyan] Brute-forcing directories and files...")
        paths = self.default_paths
        if self.wordlist:
            try:
                with open(self.wordlist, 'r', errors='ignore') as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception:
                pass

        count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_path, p): p for p in paths}
            for future in as_completed(futures):
                url, status = future.result()
                if url:
                    count += 1

        console.print(f"  [green]✓[/green] Found {len(self.found_urls)} URLs (brute force hits: {count})")

        # Categorize results
        categories = {
            'accessible': [],
            'forbidden': [],
            'redirected': [],
            'other': []
        }
        for item in self.found_urls:
            url, status, size = item
            if status == 200:
                categories['accessible'].append({'url': url, 'status': status, 'size': size})
            elif status == 403:
                categories['forbidden'].append({'url': url, 'status': status, 'size': size})
            elif status in [301, 302, 307, 308]:
                categories['redirected'].append({'url': url, 'status': status, 'size': size})
            else:
                categories['other'].append({'url': url, 'status': status, 'size': size})

        return {
            'total': len(self.found_urls),
            'categories': categories
        }
