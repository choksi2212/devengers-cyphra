@echo off
echo ═══════════════════════════════════════════════════════
echo   CYPHRA — LIVE DEMO MODE
echo   SOC: Attack injection (8 attack types, real ML scores)
echo   DOC: Real signal stats from hardware
echo.
echo   Press Ctrl+C to stop and return to normal mode
echo ═══════════════════════════════════════════════════════
echo.
echo [NOTE] Make sure these are running FIRST:
echo   1. veddb-server.exe
echo   2. python main.py (ml-service, as Admin)
echo   3. node server.js (backend)
echo   4. npm run dev (frontend)
echo.
echo Starting demo in 3 seconds...
timeout /t 3 /nobreak >nul

cd /d "%~dp0"
python demo_soc_doc.py

echo.
echo Demo ended. System is back to normal real-time capture.
pause
