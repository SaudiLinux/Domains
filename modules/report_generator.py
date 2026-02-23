#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from datetime import datetime
from rich.console import Console

console = Console()

class ReportGenerator:
    """Enhanced report generator with POC support"""
    
    def __init__(self, domain, output_file):
        self.domain = domain
        self.output_file = output_file
        self.md_file = output_file.replace('.txt', '.md')
        self.html_file = output_file.replace('.txt', '.html')
        
    def generate(self, results):
        """Generate comprehensive reports"""
        console.print(f"[yellow]⟳ جاري إنشاء التقارير...[/yellow]")
        
        self._generate_markdown(results)
        self._generate_text(results)
        self._generate_html(results)
        
        console.print(f"[green]✓ تم حفظ التقرير النصي: {self.output_file}[/green]")
        console.print(f"[green]✓ تم حفظ تقرير Markdown: {self.md_file}[/green]")
        console.print(f"[green]✓ تم حفظ تقرير HTML: {self.html_file}[/green]")
    
    def _generate_markdown(self, results):
        """Generate Markdown report with POC"""
        with open(self.md_file, 'w', encoding='utf-8') as f:
            f.write(f"# تقرير فحص النطاق: {self.domain}\n\n")
            f.write(f"**التاريخ:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            # معلومات النطاق
            if 'domain_info' in results:
                f.write("## 📋 معلومات النطاق\n\n")
                info = results['domain_info']
                f.write(f"- **النطاق:** {info['domain']}\n")
                f.write(f"- **عناوين IP:** {', '.join(info['ip_addresses'])}\n\n")
            
            # النطاقات الفرعية
            if 'subdomains' in results and results['subdomains']:
                f.write(f"## 🌐 النطاقات الفرعية ({len(results['subdomains'])})\n\n")
                for sub in results['subdomains']:
                    f.write(f"- **{sub['subdomain']}**\n")
                    f.write(f"  - الرابط: {sub['url']}\n")
                    f.write(f"  - الحالة: {sub['status_code']}\n")
                    f.write(f"  - العنوان: {sub['title']}\n\n")
            
            # لوحات التحكم
            if 'admin_pages' in results and results['admin_pages']:
                f.write(f"## 🔐 لوحات التحكم ({len(results['admin_pages'])})\n\n")
                for admin in results['admin_pages']:
                    f.write(f"- [{admin['title']}]({admin['url']})\n")
                f.write("\n")
            
            # الثغرات الأمنية - الأهم!
            if 'vulnerabilities' in results and results['vulnerabilities']:
                f.write(f"## 🔴 الثغرات الأمنية ({len(results['vulnerabilities'])})\n\n")
                
                for idx, vuln in enumerate(results['vulnerabilities'], 1):
                    f.write(f"### {idx}. {vuln['type']} [{vuln['severity']}]\n\n")
                    f.write(f"**الوصف:** {vuln['description']}\n\n")
                    f.write(f"**الرابط المصاب:** `{vuln['url']}`\n\n")
                    f.write(f"**الحل:**\n{vuln['remediation']}\n\n")
                    
                    if vuln['poc']:
                        f.write(f"**إثبات الثغرة (Proof of Concept):**\n\n")
                        f.write("```python\n")
                        f.write(vuln['poc'])
                        f.write("\n```\n\n")
                    
                    f.write("---\n\n")
    
    def _generate_text(self, results):
        """Generate text report"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"تقرير فحص النطاق: {self.domain}\n".center(80))
            f.write(f"التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n".center(80))
            f.write("=" * 80 + "\n\n")
            
            # الثغرات
            if 'vulnerabilities' in results and results['vulnerabilities']:
                f.write(f"الثغرات الأمنية المكتشفة: {len(results['vulnerabilities'])}\n")
                f.write("-" * 80 + "\n\n")
                
                for idx, vuln in enumerate(results['vulnerabilities'], 1):
                    f.write(f"[{idx}] {vuln['type']} - {vuln['severity']}\n")
                    f.write(f"الرابط: {vuln['url']}\n")
                    f.write(f"الوصف: {vuln['description']}\n")
                    f.write(f"الحل: {vuln['remediation']}\n")
                    f.write("\n" + "-" * 80 + "\n\n")
    
    def _generate_html(self, results):
        """Generate HTML report with POC"""
        html_content = f"""
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير فحص النطاق - {self.domain}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 30px;
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #667eea;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #667eea;
            margin: 0;
        }}
        .timestamp {{
            color: #666;
            font-size: 14px;
        }}
        .vulnerability {{
            background: #fff;
            border-right: 5px solid #e74c3c;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .vulnerability.critical {{
            border-right-color: #c0392b;
            background: #fee;
        }}
        .vulnerability.high {{
            border-right-color: #e74c3c;
            background: #ffe8e8;
        }}
        .vulnerability.medium {{
            border-right-color: #f39c12;
            background: #fff8e8;
        }}
        .vulnerability.low {{
            border-right-color: #3498db;
            background: #e8f4ff;
        }}
        .vuln-title {{
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .severity {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }}
        .severity.critical {{ background: #c0392b; }}
        .severity.high {{ background: #e74c3c; }}
        .severity.medium {{ background: #f39c12; }}
        .severity.low {{ background: #3498db; }}
        .vuln-url {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: monospace;
            word-break: break-all;
        }}
        .poc-section {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            overflow-x: auto;
        }}
        .poc-section pre {{
            margin: 0;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}
        .remediation {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin-bottom: 30px;
        }}
        .stat-box {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            min-width: 150px;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 تقرير فحص النطاق</h1>
            <h2>{self.domain}</h2>
            <p class="timestamp">تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
"""
        
        # إحصائيات
        vuln_count = len(results.get('vulnerabilities', []))
        subdomain_count = len(results.get('subdomains', []))
        admin_count = len(results.get('admin_pages', []))
        
        html_content += f"""
            <div class="stat-box">
                <div class="stat-number">{vuln_count}</div>
                <div class="stat-label">ثغرات أمنية</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{subdomain_count}</div>
                <div class="stat-label">نطاقات فرعية</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{admin_count}</div>
                <div class="stat-label">لوحات تحكم</div>
            </div>
        </div>
"""
        
        # الثغرات
        if 'vulnerabilities' in results and results['vulnerabilities']:
            html_content += "<h2>🔴 الثغرات الأمنية المكتشفة</h2>\n"
            
            for idx, vuln in enumerate(results['vulnerabilities'], 1):
                severity_class = vuln['severity'].lower()
                html_content += f"""
        <div class="vulnerability {severity_class}">
            <div class="vuln-title">
                [{idx}] {vuln['type']}
                <span class="severity {severity_class}">{vuln['severity']}</span>
            </div>
            <p><strong>📝 الوصف:</strong> {vuln['description']}</p>
            <div class="vuln-url">
                <strong>🔗 الرابط المصاب:</strong><br>
                {vuln['url']}
            </div>
            <div class="remediation">
                <strong>✅ الحل:</strong><br>
                {vuln['remediation']}
            </div>
"""
                
                if vuln['poc']:
                    html_content += f"""
            <div class="poc-section">
                <strong>💡 إثبات الثغرة (Proof of Concept):</strong>
                <pre>{vuln['poc']}</pre>
            </div>
"""
                
                html_content += "        </div>\n"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(self.html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
