@echo off
title Stop CyberShield
color 4F

:: Request Admin strictly so we have permission to kill the background server!
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Admin permissions to shut down background server...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo        CYBERSHIELD ULTIMATE - SHUTDOWN
echo ===================================================
echo.
echo [-] Shutting down CyberShield Server and AI engines...

:: Attempt 1: Target Python processes running the specific app.py script
powershell -Command "Get-WmiObject Win32_Process -Filter \"name='python.exe'\" | Where-Object { $_.CommandLine -match 'app.py' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"

:: Attempt 2: Target exactly the process that has Port 5000 open (Flask Server)
for /f "tokens=5" %%a in ('netstat -aon ^| find ":5000" ^| find "LISTENING"') do taskkill /F /PID %%a >nul 2>&1

echo.
echo [+] CyberShield is officially offline and terminated.
echo.
pause
