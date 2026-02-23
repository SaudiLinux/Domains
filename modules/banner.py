#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

console = Console()

def display_banner():
    """Display tool banner"""
    banner = """
[bold cyan]
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗     ║
║   ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║     ║
║   ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║     ║
║   ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║     ║
║   ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║     ║
║   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝     ║
║                                                           ║
║        [bold yellow]Advanced Domain Reconnaissance Tool[/bold yellow]           ║
║           [bold green]Version 2.0 - Enhanced Edition[/bold green]              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
[/bold cyan]
    [dim]Author: SayerLinux | Enhanced with POC Detection[/dim]
    """
    console.print(banner)
