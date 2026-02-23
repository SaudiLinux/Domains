#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich import print as rprint

console = Console()

def display_banner():
    banner = """
[bold cyan]
██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
[/bold cyan]"""
    console.print(banner)
    console.print(Panel.fit(
        "[bold white]Advanced Domain Reconnaissance Tool[/bold white]\n"
        "[dim]Author: [cyan]SayerLinux[/cyan] | For legal use only[/dim]",
        border_style="cyan"
    ))
    console.print()
