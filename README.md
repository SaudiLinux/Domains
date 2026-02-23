# 1. فك الضغط وتثبيت
unzip domain_scanner_real.zip
cd domain_tool
pip install -r requirements.txt

# 2. الفحص الأساسي
python3 domain.py -d example.com

# 3. فحص كامل
python3 domain.py -d example.com --full

# 4. وحدات محددة
python3 domain.py -d example.com --info --subdomains --vulns
