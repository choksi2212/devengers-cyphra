@echo off
title Cyphra Backend Server
color 0A

echo =============================================
echo  CYPHRA BACKEND — STARTING
echo =============================================
echo.

REM ── Add firewall rule (silently, needs admin) ──────────────────────────────
netsh advfirewall firewall delete rule name="CyphraPort3001" >nul 2>&1
netsh advfirewall firewall add rule name="CyphraPort3001" dir=in action=allow protocol=TCP localport=3001 >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Firewall rule for port 3001 active
) else (
    echo [!!] Firewall rule failed - run as Administrator if phone cant connect
)

REM ── Kill any stale process on 3001 ────────────────────────────────────────
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3001 ^| findstr LISTENING 2^>nul') do (
    echo [..] Stopping old server PID %%a
    taskkill /PID %%a /F >nul 2>&1
)

echo.
echo [OK] Starting backend on 0.0.0.0:3001
echo [OK] Phone can connect at http://192.168.1.18:3001
echo [OK] Keep this window open while using Cyphra
echo.
echo =============================================

cd /d "k:\craftathon\web-app\backend"
node server.js

echo.
echo [!!] Server stopped. Press any key to restart...
pause >nul
goto :eof
