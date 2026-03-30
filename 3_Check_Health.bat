@echo off
title CyberShield Diagnostic Center
color 0B

echo ===================================================
echo        CYBERSHIELD ULTIMATE - SYSTEM CHECK
echo ===================================================
echo.

:: 1. Check Server Status in Real Time
echo [1/5] Checking AI Server Status...
netstat -an | find ":5000" | find "LISTENING" >nul
if %errorLevel% equ 0 (
    echo   [OK] SERVER IS ONLINE ^(Running^).
) else (
    echo   [ERROR] SERVER IS OFFLINE! 
    echo   [FIX] Double-click "1_Start_CyberShield.bat" to boot the system.
)

echo.
:: 2. Check Python
echo [2/5] Checking Python Engine...
python --version >nul 2>&1
if %errorLevel% equ 0 (
    echo   [OK] Python Engine is installed correctly.
) else (
    echo   [ERROR] Python is not installed or missing from your PATH!
    echo   [FIX] Install Python 3.9+ from Python.org
)

echo.
:: 3. Check Network Driver
echo [3/5] Checking Network Capture Driver ^(Npcap^)...
if exist "%SystemRoot%\System32\Npcap" (
    echo   [OK] Npcap Core Driver found.
) else if exist "C:\Program Files\Npcap" (
    echo   [OK] Npcap Program Files found.
) else (
    echo   [WARNING] Npcap Driver is missing. Packet capture will use fallback mode.
    echo   [FIX] Download from npcap.com and install with WinPcap API-compatible mode.
)

echo.
:: 4. Check App Files
echo [4/5] Checking Core Application...
cd /d "%~dp0"
if exist "app.py" (
    echo   [OK] Core 'app.py' script is present.
) else (
    echo   [ERROR] 'app.py' is missing! Are you running this in the correct folder?
)

echo.
:: 5. Test Live APIs
echo [5/5] Testing AI API Endpoints...
curl -s http://127.0.0.1:5000/api/system-status >nul
if %errorLevel% equ 0 (
    echo   [OK] Live APIs are responding normally!
) else (
    echo   [WARNING] API Endpoints not available ^(Server might be offline^).
)

echo.
echo ===================================================
echo DIAGNOSTIC COMPLETE
echo ===================================================
pause
