# ============================================================
#  WebCTF Suite - Deploy Tools to Kali VM
#  يقوم بنسخ سكربت التثبيت إلى الـ VM وتشغيله
#  التشغيل: powershell -ExecutionPolicy Bypass -File deploy_to_kali.ps1
# ============================================================

param(
    [string]$VM_IP = "192.168.138.128",
    [string]$VM_USER = "kali"
)

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  WebCTF Suite - Deploy to Kali VM" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target: $VM_USER@$VM_IP" -ForegroundColor Yellow

# التحقق من وجود السكربت
$script = "D:\webpentest\setup_kali_tools.sh"
if (-not (Test-Path $script)) {
    Write-Host "❌ السكربت غير موجود: $script" -ForegroundColor Red
    exit 1
}

# 1. نسخ السكربت إلى الـ VM
Write-Host ""
Write-Host "[1/3] نسخ سكربت التثبيت إلى الـ VM..." -ForegroundColor Cyan
scp $script "${VM_USER}@${VM_IP}:/tmp/setup_kali_tools.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ فشل النسخ. تحقق من كلمة المرور والاتصال." -ForegroundColor Red
    exit 1
}
Write-Host "✅ تم نسخ السكربت بنجاح" -ForegroundColor Green

# 2. تشغيل السكربت على الـ VM
Write-Host ""
Write-Host "[2/3] تشغيل سكربت التثبيت على الـ VM (قد يستغرق عدة دقائق)..." -ForegroundColor Cyan
ssh -t "${VM_USER}@${VM_IP}" "echo 'kali' | sudo -S bash /tmp/setup_kali_tools.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  قد يكون التثبيت لم يكتمل. تحقق من الأخطاء أعلاه." -ForegroundColor Yellow
} else {
    Write-Host "✅ تم تثبيت الأدوات بنجاح" -ForegroundColor Green
}

# 3. التحقق من التثبيت
Write-Host ""
Write-Host "[3/3] التحقق من الأدوات المثبتة..." -ForegroundColor Cyan
ssh "${VM_USER}@${VM_IP}" "echo '=== FFUF ==='; ffuf -V 2>&1 | head -1; echo '=== SQLMAP ==='; sqlmap --version 2>&1 | head -1; echo '=== NMAP ==='; nmap --version 2>&1 | head -1; echo '=== GOBUSTER ==='; gobuster version 2>&1 | head -1; echo '=== NIKTO ==='; nikto -Version 2>&1 | head -1"

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "  ✅ تم تجهيز الـ VM بنجاح!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
