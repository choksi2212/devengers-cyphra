@echo off
echo ═══════════════════════════════════════════════════════
echo   CYPHRA Crypto API Server
echo   Port: 5050
echo   Crates: core + protocol + ai + network + mixnet
echo ═══════════════════════════════════════════════════════
echo.

set RUST_LOG=cyphra_server=info,tower_http=info

:: Use pre-built release binary
if exist "%~dp0..\target\release\cyphra-server.exe" (
    "%~dp0..\target\release\cyphra-server.exe"
) else (
    echo ERROR: Binary not found. Run: cargo build --release -p cyphra-server
    pause
)
