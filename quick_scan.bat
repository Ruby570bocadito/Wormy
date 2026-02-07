@echo off
REM Quick Scan Script - Adds Nmap to PATH and runs worm scanner

echo ============================================================
echo ML NETWORK WORM - QUICK SCAN
echo ============================================================
echo.

REM Add Nmap to PATH temporarily
set PATH=%PATH%;C:\Program Files (x86)\Nmap

REM Verify Nmap is accessible
echo Checking Nmap installation...
nmap --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Nmap not found!
    echo Please install Nmap from https://nmap.org/download.html
    pause
    exit /b 1
)

echo [OK] Nmap found
echo.

REM Run scan-only mode
echo Starting network scan (safe mode - no exploitation)...
echo.
python worm_core.py --config config_test.yaml --scan-only

echo.
echo ============================================================
echo Scan complete!
echo ============================================================
pause
