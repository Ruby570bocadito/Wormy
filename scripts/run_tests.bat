@echo off
REM Comprehensive Test Suite Runner

echo ============================================================
echo COMPREHENSIVE TEST SUITE
echo ============================================================
echo.
echo Running all tests for ML Network Worm V5.0
echo.
echo Test Categories:
echo   - Core Components
echo   - Exploitation
echo   - Infection Engine
echo   - Multi-Agent Swarm
echo   - Self-Healing
echo   - Exploitation Chains
echo   - C2 Infrastructure
echo   - Post-Exploitation
echo   - Evasion
echo   - Network Attacks
echo   - Monitoring
echo   - Integration
echo   - Stress Tests
echo   - Security Validation
echo.
echo ============================================================
echo.

python tests/comprehensive_test_suite.py

echo.
echo ============================================================
echo Test suite completed
echo ============================================================
pause
