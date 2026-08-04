#!/bin/bash
# ============================================================
#  WebCTF Suite - Kali Linux Tools Setup Script
#  يقوم بتثبيت جميع أدوات اختبار الاختراق اللازمة
#  التشغيل: sudo bash setup_kali_tools.sh
# ============================================================

set -e

echo "=============================================="
echo "  WebCTF Suite - Kali Tools Installer"
echo "=============================================="

# التحقق من الصلاحيات
if [ "$EUID" -ne 0 ]; then
    echo "❌ يرجى التشغيل بصلاحيات root: sudo bash setup_kali_tools.sh"
    exit 1
fi

echo ""
echo "[1/6] تحديث النظام..."
apt update -y && apt upgrade -y

echo ""
echo "[2/6] تثبيت أدوات فحص الدلائل والملفات..."
apt install -y \
    ffuf \
    gobuster \
    dirb \
    dirsearch \
    wfuzz \
    feroxbuster

echo ""
echo "[3/6] تثبيت أدوات حقن SQL..."
apt install -y \
    sqlmap \
    sqlninja

echo ""
echo "[4/6] تثبيت أدوات الفحص والاستكشاف..."
apt install -y \
    nmap \
    masscan \
    nikto \
    whatweb \
    wpscan \
    dnsrecon \
    sublist3r \
    amass

echo ""
echo "[5/6] تثبيت أدوات إضافية..."
apt install -y \
    curl \
    wget \
    jq \
    python3-pip \
    python3-venv \
    git \
    netcat-openbsd \
    hydra \
    john \
    hashcat \
    burpsuite \
    zaproxy

echo ""
echo "[6/6] تثبيت أدوات Python إضافية..."
pip3 install --break-system-packages \
    requests \
    beautifulsoup4 \
    selenium \
    aiohttp \
    paramiko \
    impacket

echo ""
echo "=============================================="
echo "  ✅ تم تثبيت جميع الأدوات بنجاح!"
echo "=============================================="
echo ""
echo "الأدوات المثبتة:"
echo "  - فحص الدلائل: ffuf, gobuster, dirb, dirsearch, wfuzz, feroxbuster"
echo "  - حقن SQL: sqlmap, sqlninja"
echo "  - الفحص: nmap, masscan, nikto, whatweb, wpscan"
echo "  - DNS: dnsrecon, sublist3r, amass"
echo "  - كلمات المرور: hydra, john, hashcat"
echo "  - الويب: burpsuite, zaproxy"
echo ""
echo "للتحقق من التثبيت:"
echo "  ffuf -h"
echo "  sqlmap --version"
echo "  nmap --version"
