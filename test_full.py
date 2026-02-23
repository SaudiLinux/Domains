#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🧪 ملف اختبار شامل لأداة Domain Scanner
============================================
يقوم باختبار جميع الوحدات والتأكد من عملها
"""

import sys
import os
from datetime import datetime

# إضافة مسار المشروع
sys.path.insert(0, '/mnt/user-data/outputs/domain_scanner')

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def print_header():
    """طباعة رأس الاختبار"""
    console.print(Panel.fit(
        "[bold cyan]🧪 اختبار شامل لأداة Domain Scanner[/bold cyan]\n"
        "[yellow]Testing all modules and functionality[/yellow]",
        border_style="cyan"
    ))

def test_imports():
    """اختبار استيراد الوحدات"""
    console.print("\n[bold]1️⃣ اختبار استيراد الوحدات...[/bold]")
    
    tests = []
    
    try:
        from modules.banner import display_banner
        tests.append(("banner.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("banner.py", "❌", str(e)))
    
    try:
        from modules.info_gatherer import DomainInfo
        tests.append(("info_gatherer.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("info_gatherer.py", "❌", str(e)))
    
    try:
        from modules.subdomain_enum import SubdomainEnumerator
        tests.append(("subdomain_enum.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("subdomain_enum.py", "❌", str(e)))
    
    try:
        from modules.url_discovery import URLDiscovery
        tests.append(("url_discovery.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("url_discovery.py", "❌", str(e)))
    
    try:
        from modules.admin_finder import AdminFinder
        tests.append(("admin_finder.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("admin_finder.py", "❌", str(e)))
    
    try:
        from modules.attack_surface import AttackSurfaceMapper
        tests.append(("attack_surface.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("attack_surface.py", "❌", str(e)))
    
    try:
        from modules.vulnerability_scanner import VulnerabilityScanner
        tests.append(("vulnerability_scanner.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("vulnerability_scanner.py", "❌", str(e)))
    
    try:
        from modules.zeroday_scanner import ZeroDayScanner
        tests.append(("zeroday_scanner.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("zeroday_scanner.py", "❌", str(e)))
    
    try:
        from modules.report_generator import ReportGenerator
        tests.append(("report_generator.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("report_generator.py", "❌", str(e)))
    
    try:
        from modules.utils import check_requirements, is_valid_domain, clean_domain
        tests.append(("utils.py", "✅", "نجح"))
    except Exception as e:
        tests.append(("utils.py", "❌", str(e)))
    
    # عرض النتائج
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("الوحدة", style="yellow")
    table.add_column("الحالة", justify="center")
    table.add_column("الملاحظات", style="dim")
    
    for module, status, note in tests:
        table.add_row(module, status, note)
    
    console.print(table)
    
    # حساب النجاح
    success_count = sum(1 for _, status, _ in tests if status == "✅")
    total_count = len(tests)
    
    return success_count, total_count

def test_dependencies():
    """اختبار المكتبات المطلوبة"""
    console.print("\n[bold]2️⃣ اختبار المكتبات المطلوبة...[/bold]")
    
    deps = []
    
    libs = [
        'requests', 'bs4', 'dns.resolver', 'whois',
        'colorama', 'tqdm', 'rich', 'aiohttp',
        'urllib3', 'pandas', 'OpenSSL'
    ]
    
    for lib in libs:
        try:
            if lib == 'dns.resolver':
                import dns.resolver
            elif lib == 'bs4':
                from bs4 import BeautifulSoup
            elif lib == 'OpenSSL':
                import OpenSSL
            else:
                __import__(lib)
            deps.append((lib, "✅", "مثبتة"))
        except ImportError:
            deps.append((lib, "❌", "غير مثبتة"))
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("المكتبة", style="yellow")
    table.add_column("الحالة", justify="center")
    table.add_column("الملاحظات", style="dim")
    
    for lib, status, note in deps:
        table.add_row(lib, status, note)
    
    console.print(table)
    
    success_count = sum(1 for _, status, _ in deps if status == "✅")
    total_count = len(deps)
    
    return success_count, total_count

def test_utils():
    """اختبار الدوال المساعدة"""
    console.print("\n[bold]3️⃣ اختبار الدوال المساعدة...[/bold]")
    
    from modules.utils import is_valid_domain, clean_domain
    
    tests = []
    
    # اختبار is_valid_domain
    if is_valid_domain("example.com"):
        tests.append(("is_valid_domain('example.com')", "✅", "صحيح"))
    else:
        tests.append(("is_valid_domain('example.com')", "❌", "خطأ"))
    
    if not is_valid_domain("invalid domain"):
        tests.append(("is_valid_domain('invalid domain')", "✅", "صحيح"))
    else:
        tests.append(("is_valid_domain('invalid domain')", "❌", "خطأ"))
    
    # اختبار clean_domain
    cleaned = clean_domain("https://www.example.com/path")
    if cleaned == "example.com":
        tests.append(("clean_domain()", "✅", f"نتيجة: {cleaned}"))
    else:
        tests.append(("clean_domain()", "❌", f"نتيجة خاطئة: {cleaned}"))
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("الاختبار", style="yellow")
    table.add_column("الحالة", justify="center")
    table.add_column("الملاحظات", style="dim")
    
    for test, status, note in tests:
        table.add_row(test, status, note)
    
    console.print(table)
    
    success_count = sum(1 for _, status, _ in tests if status == "✅")
    total_count = len(tests)
    
    return success_count, total_count

def test_file_structure():
    """اختبار بنية الملفات"""
    console.print("\n[bold]4️⃣ اختبار بنية الملفات...[/bold]")
    
    base_path = "/mnt/user-data/outputs/domain_scanner"
    
    files = [
        "domain.py",
        "requirements.txt",
        "modules/__init__.py",
        "modules/banner.py",
        "modules/info_gatherer.py",
        "modules/subdomain_enum.py",
        "modules/url_discovery.py",
        "modules/admin_finder.py",
        "modules/attack_surface.py",
        "modules/vulnerability_scanner.py",
        "modules/zeroday_scanner.py",
        "modules/report_generator.py",
        "modules/utils.py",
    ]
    
    tests = []
    
    for file in files:
        path = os.path.join(base_path, file)
        if os.path.exists(path):
            size = os.path.getsize(path)
            tests.append((file, "✅", f"{size} bytes"))
        else:
            tests.append((file, "❌", "غير موجود"))
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("الملف", style="yellow")
    table.add_column("الحالة", justify="center")
    table.add_column("الملاحظات", style="dim")
    
    for file, status, note in tests:
        table.add_row(file, status, note)
    
    console.print(table)
    
    success_count = sum(1 for _, status, _ in tests if status == "✅")
    total_count = len(tests)
    
    return success_count, total_count

def print_summary(results):
    """طباعة ملخص النتائج"""
    console.print("\n" + "="*60)
    console.print("[bold cyan]📊 ملخص نتائج الاختبار[/bold cyan]")
    console.print("="*60)
    
    total_success = 0
    total_tests = 0
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("الفئة", style="yellow")
    table.add_column("النجاح", justify="center", style="green")
    table.add_column("الإجمالي", justify="center")
    table.add_column("النسبة", justify="center", style="bold")
    
    for category, (success, total) in results.items():
        percentage = (success / total * 100) if total > 0 else 0
        table.add_row(
            category,
            str(success),
            str(total),
            f"{percentage:.1f}%"
        )
        total_success += success
        total_tests += total
    
    console.print(table)
    
    # النتيجة النهائية
    final_percentage = (total_success / total_tests * 100) if total_tests > 0 else 0
    
    if final_percentage == 100:
        status = "[bold green]✅ نجاح كامل! المشروع جاهز للاستخدام[/bold green]"
    elif final_percentage >= 80:
        status = "[bold yellow]⚠️ نجاح جيد مع بعض الملاحظات[/bold yellow]"
    else:
        status = "[bold red]❌ يوجد أخطاء تحتاج إلى إصلاح[/bold red]"
    
    console.print(f"\n[bold]النتيجة النهائية:[/bold] {total_success}/{total_tests} ({final_percentage:.1f}%)")
    console.print(status)

def main():
    """الدالة الرئيسية"""
    print_header()
    
    results = {}
    
    # تشغيل الاختبارات
    results["استيراد الوحدات"] = test_imports()
    results["المكتبات المطلوبة"] = test_dependencies()
    results["الدوال المساعدة"] = test_utils()
    results["بنية الملفات"] = test_file_structure()
    
    # طباعة الملخص
    print_summary(results)
    
    console.print(f"\n[dim]تاريخ الاختبار: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n[bold red]خطأ في التشغيل: {str(e)}[/bold red]")
        import traceback
        traceback.print_exc()
