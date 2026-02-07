@echo off
REM Monitor Simulation Progress

echo ============================================================
echo MONITORING SIMULATION PROGRESS
echo ============================================================
echo.
echo Press Ctrl+C to stop monitoring (worm will continue running)
echo.

REM Find the latest log file
for /f "delims=" %%i in ('dir /b /od logs\worm_*.log 2^>nul') do set LOGFILE=%%i

if "%LOGFILE%"=="" (
    echo No log file found yet...
    timeout /t 2 >nul
    goto :loop
)

echo Monitoring: logs\%LOGFILE%
echo.

:loop
powershell -Command "Get-Content logs\%LOGFILE% -Tail 20 -Wait | Select-String -Pattern 'INFO|SUCCESS|WARNING|ERROR' | ForEach-Object { if ($_ -match 'SUCCESS') { Write-Host $_ -ForegroundColor Green } elseif ($_ -match 'WARNING') { Write-Host $_ -ForegroundColor Yellow } elseif ($_ -match 'ERROR') { Write-Host $_ -ForegroundColor Red } else { Write-Host $_ -ForegroundColor White } }"
