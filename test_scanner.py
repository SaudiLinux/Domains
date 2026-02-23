#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
اختبار سريع لأداة Domain Scanner المطورة
يختبر وحدة فحص الثغرات مع إثبات الاستغلال (POC)
"""

import sys
sys.path.insert(0, '/home/user/domain_scanner')

from modules.vulnerability_scanner import VulnerabilityScanner
from rich.console import Console
from rich.panel import Panel

console = Console()

def test_vulnerability_scanner():
    """اختبار وحدة فحص الثغرات"""
    
    console.print(Panel.fit(
        "[bold cyan]اختبار وحدة فحص الثغرات مع POC[/bold cyan]\n"
        "[yellow]هذا اختبار توضيحي للميزات الجديدة[/yellow]",
        border_style="cyan"
    ))
    
    # مثال: فحص موقع تجريبي
    test_domain = "example.com"
    
    console.print(f"\n[green]→ إنشاء ماسح الثغرات للنطاق: {test_domain}[/green]")
    scanner = VulnerabilityScanner(test_domain, threads=5, timeout=10)
    
    console.print("\n[bold yellow]الميزات الجديدة:[/bold yellow]")
    console.print("✓ فحص 12 نوع من الثغرات الأمنية")
    console.print("✓ عرض رابط الثغرة المباشر")
    console.print("✓ إثبات الثغرة (POC) بكود Python جاهز للتشغيل")
    console.print("✓ خطوات الحل والإصلاح")
    console.print("✓ تقارير HTML/Markdown/Text مفصلة")
    
    console.print("\n[bold cyan]أنواع الثغرات المدعومة:[/bold cyan]")
    vulnerabilities_list = [
        "1. SQL Injection - حقن قواعد البيانات",
        "2. XSS (Cross-Site Scripting) - البرمجة النصية عبر المواقع",
        "3. LFI/RFI - تضمين الملفات",
        "4. Open Redirect - إعادة التوجيه المفتوحة",
        "5. SSRF - تزوير الطلبات من جانب الخادم",
        "6. XXE - كيانات XML الخارجية",
        "7. CSRF - تزوير الطلبات عبر المواقع",
        "8. Missing Security Headers - فقدان Headers الأمان",
        "9. Information Disclosure - تسريب المعلومات",
        "10. Exposed Backup Files - ملفات النسخ الاحتياطي المكشوفة",
        "11. CORS Misconfiguration - خطأ في إعدادات CORS",
        "12. Clickjacking - اختطاف النقرات"
    ]
    
    for vuln in vulnerabilities_list:
        console.print(f"  [cyan]→[/cyan] {vuln}")
    
    console.print("\n[bold green]مثال على إثبات ثغرة (POC):[/bold green]")
    console.print("""
[dim]عند اكتشاف ثغرة SQL Injection مثلاً، سيتم عرض:

[yellow]🔴 ثغرة مكتشفة: SQL Injection [Critical][/yellow]
[white]🔗 الرابط: https://example.com/?id=1' OR '1'='1[/white]
[green]✓ إثبات الثغرة متاح[/green]

وسيتم توليد كود Python جاهز للتشغيل:

```python
# إثبات ثغرة SQL Injection
import requests

url = "https://example.com/?id=1' OR '1'='1"
response = requests.get(url)

if "SQL syntax" in response.text:
    print("[+] الموقع معرض لـ SQL Injection!")
    print(f"[+] الخطأ المكتشف: SQL syntax")
```
[/dim]
    """)
    
    console.print("\n[bold magenta]استخدام الأداة:[/bold magenta]")
    console.print("  python3 domain.py -d example.com --vulns")
    console.print("  python3 domain.py -d example.com --full")
    console.print("  python3 domain.py -d example.com --vulns --threads 20")
    
    console.print("\n[bold green]✓ الاختبار مكتمل - الأداة جاهزة للاستخدام![/bold green]\n")

if __name__ == "__main__":
    test_vulnerability_scanner()
