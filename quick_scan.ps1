# Quick Scan Script - PowerShell version
# Adds Nmap to PATH and runs worm scanner

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "ML NETWORK WORM - QUICK SCAN" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Add Nmap to PATH temporarily
$env:PATH += ";C:\Program Files (x86)\Nmap"

# Verify Nmap is accessible
Write-Host "Checking Nmap installation..." -ForegroundColor Yellow
try {
    $nmapVersion = & nmap --version 2>&1
    Write-Host "[OK] Nmap found" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "[ERROR] Nmap not found!" -ForegroundColor Red
    Write-Host "Please install Nmap from https://nmap.org/download.html" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Run scan-only mode
Write-Host "Starting network scan (safe mode - no exploitation)..." -ForegroundColor Yellow
Write-Host ""

python worm_core.py --config config_test.yaml --scan-only

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Scan complete!" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Read-Host "Press Enter to exit"
