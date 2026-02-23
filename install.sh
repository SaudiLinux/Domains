#!/bin/bash

# Domain Scanner - Installation Script
# نسخة محسّنة مع POC

echo "╔═══════════════════════════════════════════════════╗"
echo "║     Domain Scanner - Enhanced with POC           ║"
echo "║              Installation Script                 ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "[*] Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "[!] Python 3 is not installed!"
    echo "[!] Please install Python 3.7 or higher"
    exit 1
fi

echo "[+] Python 3 is installed"
echo ""

# Install dependencies
echo "[*] Installing dependencies..."
pip3 install -r requirements.txt --upgrade

if [ $? -ne 0 ]; then
    echo "[!] Failed to install dependencies"
    echo "[!] Try: pip3 install -r requirements.txt --user"
    exit 1
fi

echo "[+] Dependencies installed successfully"
echo ""

# Make scripts executable
echo "[*] Making scripts executable..."
chmod +x domain.py
chmod +x test_scanner.py

echo "[+] Scripts are now executable"
echo ""

# Create results directory
echo "[*] Creating results directory..."
mkdir -p results

echo "[+] Results directory created"
echo ""

# Test installation
echo "[*] Testing installation..."
python3 test_scanner.py

if [ $? -ne 0 ]; then
    echo "[!] Test failed. Please check the errors above."
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║              Installation Complete!              ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo "[+] Usage Examples:"
echo "    python3 domain.py -d example.com --vulns"
echo "    python3 domain.py -d example.com --full"
echo "    python3 domain.py --help"
echo ""
echo "[+] Documentation:"
echo "    - README.md: Full documentation"
echo "    - QUICK_START.md: Quick start guide"
echo "    - VULNERABILITIES_GUIDE.md: Vulnerability details"
echo ""
echo "[+] Output:"
echo "    - Reports will be saved in: ./results/"
echo "    - HTML report (open in browser)"
echo "    - Markdown report"
echo "    - Text report"
echo ""
echo "⚠️  IMPORTANT: Only scan domains you have permission to test!"
echo ""
