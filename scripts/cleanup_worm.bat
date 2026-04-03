@echo off
REM Cleanup Script - Remove all worm traces

echo ============================================================
echo WORM CLEANUP SCRIPT
echo ============================================================
echo.
echo This will:
echo 1. Stop the worm (kill switch)
echo 2. Remove logs
echo 3. Remove exfiltrated data
echo 4. Clean temporary files
echo.
echo ============================================================
echo.

pause

echo.
echo [1/4] Activating kill switch...
python worm_core.py --kill-switch EMERGENCY_STOP_SIMULATION
timeout /t 2 >nul

echo.
echo [2/4] Removing logs...
if exist logs\ (
    del /q logs\*.log 2>nul
    echo Logs removed
) else (
    echo No logs found
)

echo.
echo [3/4] Removing exfiltrated data...
if exist exfil_data\ (
    rmdir /s /q exfil_data 2>nul
    echo Exfiltrated data removed
) else (
    echo No exfiltrated data found
)

echo.
echo [4/4] Cleaning temporary files...
del /q *.pyc 2>nul
del /q __pycache__\*.pyc 2>nul
echo Temporary files cleaned

echo.
echo ============================================================
echo CLEANUP COMPLETE
echo ============================================================
echo.
echo The worm has been stopped and all traces removed.
echo.
echo To verify:
echo - Check Task Manager for python processes
echo - Check logs\ directory (should be empty)
echo - Restart infected hosts (optional)
echo.
echo ============================================================
pause
