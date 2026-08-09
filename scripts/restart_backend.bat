@echo off
echo =============================================
echo  CYPHRA BACKEND — RESTART WITH LAN ACCESS
echo =============================================
echo.

REM Add firewall rule (requires admin — if this fails, run script as admin)
echo [1/3] Opening firewall port 3001...
netsh advfirewall firewall delete rule name="CyphraPort3001" >nul 2>&1
netsh advfirewall firewall add rule name="CyphraPort3001" dir=in action=allow protocol=TCP localport=3001
if %ERRORLEVEL% equ 0 (
    echo      Firewall rule added OK
) else (
    echo      WARNING: Firewall rule failed - run this script as Administrator!
    echo      Right-click this .bat and choose "Run as administrator"
)

REM Kill any existing node process on 3001
echo.
echo [2/3] Stopping existing backend...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3001 ^| findstr LISTENING') do (
    echo      Killing PID %%a
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 2 /nobreak >nul

REM Start backend
echo.
echo [3/3] Starting backend on 0.0.0.0:3001...
echo      Phone can connect at http://192.168.1.18:3001
echo.
cd /d "k:\craftathon\web-app\backend"
node server.js
