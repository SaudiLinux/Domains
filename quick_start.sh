#!/bin/bash

# ═══════════════════════════════════════════════════════════
# Domain Scanner - Quick Start Script
# نص تشغيل سريع لأداة Domain Scanner
# ═══════════════════════════════════════════════════════════

echo "╔════════════════════════════════════════════════════════╗"
echo "║       Domain Scanner - Enhanced Edition v2.0.0         ║"
echo "║       Advanced Reconnaissance & Zero-Day Hunter        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# التحقق من Python
if ! command -v python3 &> /dev/null; then
    echo "❌ خطأ: Python 3 غير مثبت!"
    echo "📦 يرجى تثبيت Python 3.7 أو أحدث"
    exit 1
fi

echo "✅ Python 3 متوفر: $(python3 --version)"
echo ""

# التحقق من المتطلبات
echo "📦 التحقق من المتطلبات..."
if [ -f "requirements.txt" ]; then
    echo "✓ ملف requirements.txt موجود"
else
    echo "⚠️ ملف requirements.txt غير موجود!"
fi

# عرض القائمة
echo ""
echo "═══════════════════════════════════════════════════════"
echo "          أمثلة سريعة للاستخدام"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "1️⃣  فحص أساسي (معلومات النطاق)"
echo "   python3 domain.py -d example.com --info"
echo ""
echo "2️⃣  فحص الثغرات الكلاسيكية"
echo "   python3 domain.py -d example.com --vulns"
echo ""
echo "3️⃣  فحص Zero-Day المتقدم"
echo "   python3 domain.py -d example.com --zeroday"
echo ""
echo "4️⃣  فحص شامل (كل الوحدات)"
echo "   python3 domain.py -d example.com --full"
echo ""
echo "5️⃣  فحص مخصص مع خيارات"
echo "   python3 domain.py -d example.com --info --vulns --zeroday \\"
echo "     --threads 15 --timeout 20 --output my_report"
echo ""
echo "═══════════════════════════════════════════════════════"
echo ""

# سؤال المستخدم
read -p "هل تريد تثبيت المتطلبات الآن؟ (y/n): " install_deps

if [ "$install_deps" = "y" ] || [ "$install_deps" = "Y" ]; then
    echo ""
    echo "📦 جاري تثبيت المتطلبات..."
    pip3 install -r requirements.txt -q
    
    if [ $? -eq 0 ]; then
        echo "✅ تم تثبيت المتطلبات بنجاح!"
    else
        echo "❌ فشل تثبيت المتطلبات"
        echo "💡 حاول: pip3 install -r requirements.txt --user"
        exit 1
    fi
fi

echo ""
read -p "هل تريد تشغيل فحص تجريبي على example.com؟ (y/n): " run_test

if [ "$run_test" = "y" ] || [ "$run_test" = "Y" ]; then
    echo ""
    echo "🚀 جاري تشغيل فحص تجريبي..."
    echo "════════════════════════════════════════════════"
    python3 domain.py -d example.com --info --vulns --zeroday --threads 5 --timeout 15
    echo ""
    echo "════════════════════════════════════════════════"
    echo "✅ اكتمل الفحص التجريبي!"
    echo "📊 التقارير محفوظة في مجلد: results/"
fi

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  للمساعدة: python3 domain.py --help                   ║"
echo "║  للتوثيق الكامل: راجع README_AR.md                    ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
