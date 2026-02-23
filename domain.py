#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Domain - Advanced Domain Reconnaissance Tool
Author: SayerLinux
Email: SayerLinux@gmail.com
GitHub: https://github.com/SaudiLinux/Domain
'''

import os
import sys
import argparse
import time
import warnings
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich import print as rprint

# Suppress SSL warnings
warnings.filterwarnings('ignore')

# Import modules
from modules.banner import display_banner
from modules.info_gatherer import DomainInfo
from modules.subdomain_enum import SubdomainEnumerator
from modules.url_discovery import URLDiscovery
from modules.admin_finder import AdminFinder
from modules.attack_surface import AttackSurfaceMapper
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.zeroday_scanner import ZeroDayScanner          # ← NEW
from modules.report_generator import ReportGenerator
from modules.utils import check_requirements, is_valid_domain, setup_logging, clean_domain

# Initialize console
console = Console()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Domain - Advanced Domain Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 domain.py -d example.com
  python3 domain.py -d example.com --full
  python3 domain.py -d example.com --info --subdomains
  python3 domain.py -d example.com --vulns --threads 20
  python3 domain.py -d example.com --zeroday
  python3 domain.py -d example.com --zeroday --nvd-key YOUR_KEY
  python3 domain.py -d example.com --full --output results/report
        """
    )

    # Main arguments
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file base name (without extension)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--full', action='store_true', help='Run all scan modules')

    # Module selection
    parser.add_argument('--info',           action='store_true', help='Gather basic domain information')
    parser.add_argument('--subdomains',     action='store_true', help='Enumerate subdomains')
    parser.add_argument('--urls',           action='store_true', help='Discover hidden URLs')
    parser.add_argument('--admin-finder',   action='store_true', help='Find admin pages')
    parser.add_argument('--attack-surface', action='store_true', help='Map attack surface')
    parser.add_argument('--vulns',          action='store_true', help='Scan for vulnerabilities (known)')
    parser.add_argument('--zeroday',        action='store_true',  # ← NEW
                        help='Run zero-day / advanced vulnerability discovery')

    # Advanced options
    parser.add_argument('--threads',    type=int,   default=10,  help='Number of threads (default: 10)')
    parser.add_argument('--timeout',    type=int,   default=30,  help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--user-agent',             help='Custom User-Agent string')
    parser.add_argument('--wordlist',               help='Custom wordlist file for brute forcing')
    parser.add_argument('--delay',      type=float, default=0.0, help='Delay between requests in seconds')
    parser.add_argument('--nvd-key',    default='',              # ← NEW
                        help='NIST NVD API key for higher CVE lookup rate-limit')

    return parser.parse_args()

def main():
    """Main function"""
    # Display banner
    display_banner()

    # Check requirements
    if not check_requirements():
        console.print("[bold red]Error: Missing required dependencies.[/bold red]")
        console.print("[yellow]Run: pip install -r requirements.txt[/yellow]")
        sys.exit(1)

    # Parse arguments
    args = parse_arguments()

    # Check if domain is provided
    if not args.domain:
        console.print("[bold red]Error: Target domain is required.[/bold red]")
        console.print("[yellow]Usage: python3 domain.py -d example.com[/yellow]")
        console.print("[yellow]       python3 domain.py --help[/yellow]")
        sys.exit(1)

    # Clean and validate domain
    domain = clean_domain(args.domain)
    if not is_valid_domain(domain):
        console.print(f"[bold red]Error: '{domain}' is not a valid domain name.[/bold red]")
        sys.exit(1)

    # Setup logging
    logger = setup_logging(args.verbose)

    # Create output directory if not exists
    output_dir = 'results'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generate output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = os.path.join(output_dir, f"{domain.replace('.', '_')}_{timestamp}")

    # Initialize modules
    domain_info    = DomainInfo(domain, args.timeout, args.user_agent)
    subdomain_enum = SubdomainEnumerator(domain, args.threads, args.timeout, args.wordlist, args.delay)
    url_discovery  = URLDiscovery(domain, args.threads, args.timeout, args.wordlist, args.delay)
    admin_finder   = AdminFinder(domain, args.threads, args.timeout, args.wordlist, args.delay)
    attack_surface = AttackSurfaceMapper(domain, args.threads, args.timeout)
    vuln_scanner   = VulnerabilityScanner(domain, args.threads, args.timeout)
    zd_scanner     = ZeroDayScanner(                          # ← NEW
                         domain,
                         threads=args.threads,
                         timeout=args.timeout,
                         user_agent=args.user_agent,
                         nvd_api_key=getattr(args, 'nvd_key', ''),
                     )
    report_gen     = ReportGenerator(domain, args.output + '.txt')

    # Determine which modules to run
    run_info       = args.info or args.full
    run_subdomains = args.subdomains or args.full
    run_urls       = args.urls or args.full
    run_admin      = args.admin_finder or args.full
    run_attack     = args.attack_surface or args.full
    run_vulns      = args.vulns or args.full
    run_zeroday    = args.zeroday or args.full             # ← NEW

    # If no specific module is selected, run basic info gathering
    if not any([run_info, run_subdomains, run_urls, run_admin,
                run_attack, run_vulns, run_zeroday]):
        run_info = True

    # Start scan
    start_time = time.time()
    console.print(Panel.fit(
        f"[bold green]Starting scan on:[/bold green] [bold white]{domain}[/bold white]\n"
        f"[dim]Threads: {args.threads} | Timeout: {args.timeout}s | Delay: {args.delay}s[/dim]",
        title="[bold cyan]Domain Scanner[/bold cyan]",
        border_style="cyan"
    ))

    results = {}

    # Domain Information
    if run_info:
        console.print("\n[bold cyan] [1/7] Domain Information [/bold cyan]")
        results['domain_info'] = domain_info.gather_info()

    # Subdomain Enumeration
    if run_subdomains:
        console.print("\n[bold cyan] [2/7] Subdomain Enumeration [/bold cyan]")
        results['subdomains'] = subdomain_enum.enumerate()

    # URL Discovery
    if run_urls:
        console.print("\n[bold cyan] [3/7] URL Discovery [/bold cyan]")
        results['urls'] = url_discovery.discover()

    # Admin Finder
    if run_admin:
        console.print("\n[bold cyan] [4/7] Admin Page Finder [/bold cyan]")
        results['admin_pages'] = admin_finder.find()

    # Attack Surface Mapping
    if run_attack:
        console.print("\n[bold cyan] [5/7] Attack Surface Mapping [/bold cyan]")
        results['attack_surface'] = attack_surface.map()

    # Vulnerability Scanning (classic)
    if run_vulns:
        console.print("\n[bold cyan] [6/7] Vulnerability Scanning (Classic) [/bold cyan]")
        results['vulnerabilities'] = vuln_scanner.scan()

    # ── Zero-Day Discovery ──────────────────────────────────────────────
    if run_zeroday:
        console.print("\n[bold red] [7/7] Zero-Day Vulnerability Discovery [/bold red]")
        results['zeroday'] = zd_scanner.scan()
    # ───────────────────────────────────────────────────────────────────

    # Generate reports
    console.print("\n[bold cyan] Generating Reports [/bold cyan]")
    report_gen.generate(results)

    # Calculate scan duration
    duration = time.time() - start_time
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)

    # Display scan summary
    zd_count = len(results.get('zeroday', []))
    console.print(Panel.fit(
        f"[bold green] Scan Completed![/bold green]\n\n"
        f"[white]Target:[/white] [bold cyan]{domain}[/bold cyan]\n"
        f"[white]Duration:[/white] {int(hours)}h {int(minutes)}m {int(seconds)}s\n"
        + (f"[bold red]Zero-Day findings:[/bold red] {zd_count}\n" if run_zeroday else "")
        + f"[white]Reports saved to:[/white] [bold]{args.output}.md[/bold]",
        title="[bold green]Scan Complete[/bold green]",
        border_style="green"
    ))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold red] Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Critical Error: {str(e)}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
