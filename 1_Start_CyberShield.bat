@echo off
title Start CyberShield Ultimate
color 0B

:: Check for Administrator privileges (required for real packet capture)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator Privileges for Network Capture...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo        CYBERSHIELD ULTIMATE - REAL TIME SOC
echo ===================================================
echo.
echo [+] Administrator Privileges Granted.
echo [+] Starting Server...

cd /d "%~dp0"
echo [+] Launching Dashboard in your Web Browser...
start "" "http://127.0.0.1:5000"
python app.py

pause
