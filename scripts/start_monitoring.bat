@echo off
REM Launch Monitoring Dashboard

echo ============================================================
echo WORM MONITORING DASHBOARD
echo ============================================================
echo.
echo Starting real-time monitoring dashboard...
echo.
echo Dashboard will be available at:
echo   http://localhost:8080
echo.
echo Features:
echo   - Live activity feed
echo   - Device tracking
echo   - Real-time statistics
echo   - Auto-refresh every 2 seconds
echo.
echo Press Ctrl+C to stop
echo ============================================================
echo.

python monitoring/dashboard.py

pause
