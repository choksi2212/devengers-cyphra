@echo off
echo ========================================
echo   Starting Ghost Messenger Backend API
echo ========================================
echo.

REM Check if node_modules exists
if not exist "node_modules" (
    echo [INFO] Installing dependencies...
    call npm install
    echo.
)

echo [INFO] Starting backend server...
echo [INFO] Server will run at http://localhost:3001
echo [INFO] WebSocket at ws://localhost:3001/ws
echo.
echo Press Ctrl+C to stop the server
echo.

npm start

pause

