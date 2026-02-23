#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console

console = Console()

class AdminFinder:
    def __init__(self, domain, threads=10, timeout=30, wordlist=None, delay=0.0):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist
        self.delay = delay
        self.found_pages = []
        self.lock = threading.Lock()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        # Comprehensive admin paths
        self.admin_paths = [
            # Generic admin panels
            'admin', 'admin/', 'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
            'administrator', 'administrator/', 'administrator.php',
            'adminpanel', 'admin_panel', 'admin-panel',
            'controlpanel', 'control-panel', 'control_panel', 'cp/',
            'dashboard', 'dashboard/', 'manage', 'manage/', 'management/',
            'backend', 'backend/', 'back-end/', 'backoffice/', 'back-office/',
            # Login pages
            'login', 'login/', 'login.php', 'login.html', 'login.asp', 'login.aspx',
            'signin', 'sign-in', 'signin.php', 'sign_in',
            'user/login', 'users/login', 'member/login', 'members/login',
            'account/login', 'accounts/login', 'auth/login', 'auth/signin',
            # WordPress
            'wp-admin/', 'wp-admin/index.php', 'wp-login.php',
            'wp-admin/admin.php', 'wp-admin/edit.php', 'wordpress/wp-admin/',
            # Joomla
            'administrator/index.php', 'joomla/administrator/', 'joomla-admin/',
            # Drupal
            'user/login', 'admin/content', 'admin/config',
            # Magento
            'admin/admin/', 'magento/admin/', 'downloader/', 'admin/dashboard/',
            # OpenCart
            'admin/index.php', 'oc-admin/', 'opencart/admin/',
            # PrestaShop
            'adminshop/', 'admin123/', 'adminprestashop/',
            # cPanel
            ':2082/', ':2083/', ':2086/', ':2087/',
            'cpanel/', 'whm/', 'webadmin/', 'web_admin/',
            # Plesk
            ':8880/', ':8443/',
            # phpMyAdmin
            'phpmyadmin/', 'phpmyadmin/index.php', 'pma/', 'mysql/',
            'phpMyAdmin/', 'PHPMyAdmin/', 'phpma/', 'php-myadmin/',
            'myadmin/', 'mysqladmin/', 'sql/',
            # Webmin
            ':10000/', 'webmin/', 'sysadmin/',
            # Django
            'admin/', 'django-admin/', 'admin/login/',
            # Laravel
            'nova/', 'horizon/', 'telescope/',
            # Other CMSs
            'typo3/', 'typo3/index.php', 'fileadmin/',
            'sitemanager/', 'manager/', 'cms/', 'cms-admin/',
            'siteadmin/', 'site-admin/', 'website-admin/',
            'mainadmin/', 'main-admin/', 'superadmin/', 'super-admin/',
            'root/', 'root/admin/', 'sys/', 'system/', 'sysmanage/',
            'config/', 'configuration/', 'setup/', 'install/',
            'panel/', 'panel/login/', 'panel/admin/',
            'moderator/', 'webmaster/', 'master/',
            'user-admin/', 'useradmin/', 'users/admin/',
            # API admin
            'api/admin/', 'api/v1/admin/', 'api/management/',
            # Common patterns
            '_admin/', '_admin/login/', '__admin/', '~admin/',
            'secure/', 'secure/admin/', 'private/', 'hidden/',
            'secret/', 'internal/', 'staff/', 'staff/login/',
            'employee/', 'employees/', 'portal/', 'portal/login/',
            # Support/ticket systems
            'helpdesk/', 'support/admin/', 'ticket/', 'tickets/',
            # Monitoring
            'grafana/', 'kibana/', 'prometheus/', 'nagios/',
            'zabbix/', 'netdata/', 'munin/',
            # Server status pages
            'server-status', 'server-info', 'nginx_status', 'status/',
            # Other
            'manage.py', 'console/', 'console/login',
        ]

    def check_admin_page(self, path):
        """Check if an admin page exists"""
        if self.delay > 0:
            time.sleep(self.delay)
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{self.domain}/{path.lstrip('/')}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout,
                                    allow_redirects=True, verify=False)

                # Consider page found if status is 200, 401, or 403
                if resp.status_code in [200, 401, 403]:
                    # Check if it looks like a login/admin page
                    content_lower = resp.text.lower()
                    is_admin = any([
                        'login' in content_lower,
                        'password' in content_lower,
                        'username' in content_lower,
                        'admin' in content_lower,
                        'dashboard' in content_lower,
                        'sign in' in content_lower,
                        'authenticate' in content_lower,
                        'control panel' in content_lower,
                        resp.status_code == 401,
                        resp.status_code == 403,
                    ])

                    if is_admin:
                        page_title = ''
                        import re
                        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
                        if title_match:
                            page_title = title_match.group(1).strip()

                        result = {
                            'url': url,
                            'status': resp.status_code,
                            'title': page_title,
                            'size': len(resp.content),
                            'requires_auth': resp.status_code in [401, 403]
                        }
                        with self.lock:
                            self.found_pages.append(result)
                        return result
                break
            except Exception:
                pass
        return None

    def check_default_credentials(self, url):
        """Try common default credentials"""
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('admin', ''),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('test', 'test'),
        ]
        found_creds = []

        for username, password in default_creds:
            try:
                resp = requests.post(
                    url,
                    data={'username': username, 'password': password,
                          'user': username, 'pass': password},
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                # Simple check: redirect after POST often means success
                if resp.status_code in [301, 302] and 'dashboard' in resp.headers.get('Location', '').lower():
                    found_creds.append(f"{username}:{password}")
            except Exception:
                pass

        return found_creds

    def find(self):
        """Find admin pages"""
        paths = self.admin_paths
        if self.wordlist:
            try:
                with open(self.wordlist, 'r', errors='ignore') as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception:
                pass

        console.print(f"  [cyan]→[/cyan] Checking {len(paths)} admin paths...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_admin_page, p): p for p in paths}
            for future in as_completed(futures):
                future.result()

        console.print(f"  [green]✓[/green] Found [bold]{len(self.found_pages)}[/bold] admin/login pages")

        for page in self.found_pages:
            status_color = 'green' if page['status'] == 200 else 'yellow'
            console.print(f"    [{status_color}][{page['status']}][/{status_color}] {page['url']} - {page['title']}")

        return {
            'total': len(self.found_pages),
            'pages': self.found_pages
        }
