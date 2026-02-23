#!/bin/bash
# Install script for Domain Scanner

echo "[*] Installing Domain Scanner dependencies..."
pip install -r requirements.txt

echo ""
echo "[*] Making domain.py executable..."
chmod +x domain.py

echo ""
echo "[+] Installation complete!"
echo "[+] Usage: python3 domain.py -d example.com"
echo "[+] Full scan: python3 domain.py -d example.com --full"
echo "[+] Help: python3 domain.py --help"
