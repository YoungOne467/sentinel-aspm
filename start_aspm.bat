@echo off
title ASPM Vulnerability Scanner Launcher

echo ==================================================
echo   Starting Autonomous Vulnerability Scanner...
echo ==================================================
echo.

:: ── Step 0: Kill any orphaned processes on our ports ──
echo [0/3] Cleaning up old sessions...
powershell -NoProfile -Command "$ports = 8000,8081,5173,5174; foreach ($p in $ports) { try { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($c in $conns) { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue } } catch {} }"
echo       Ports 8000, 8081, 5173, 5174 cleared.
echo.

:: ── Step 1: Start Backend ──
echo [1/3] Booting up Backend API and DAST Engine...
cd backend
if not exist venv (
    echo       Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
echo       Installing/Checking backend dependencies...
pip install -r requirements.txt -q
start "ASPM Backend Server" cmd /k "title ASPM Backend API && call venv\Scripts\activate && python main.py"
cd ..
echo       Backend launched in a new window!
echo.

:: ── Step 2: Wait for backend to be ACTUALLY ready ──
echo [2/3] Waiting for backend API to become available...
set RETRIES=0
set MAX_RETRIES=30

:wait_loop
if %RETRIES% GEQ %MAX_RETRIES% (
    echo.
    echo   [WARNING] Backend did not respond after %MAX_RETRIES% attempts.
    echo   The frontend will start anyway, but may show proxy errors until
    echo   the backend finishes initializing.
    echo.
    goto start_frontend
)

set /a RETRIES+=1
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/health' -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop; exit 0 } catch { exit 1 }"

if %ERRORLEVEL% EQU 0 (
    echo       Backend is ONLINE! (responded after %RETRIES% checks^)
    goto start_frontend
)

echo       Attempt %RETRIES%/%MAX_RETRIES% - backend not ready yet, retrying in 2s...
timeout /t 2 /nobreak >nul
goto wait_loop

:start_frontend
echo.

:: ── Step 3: Start Frontend ──
echo [3/3] Booting up ARES React Dashboard...
cd aspm-frontend
if not exist node_modules (
    echo       Installing frontend dependencies...
    call npm install
)
start "ASPM Frontend Server" cmd /c "title ASPM Frontend && npm run dev -- --port 5174"
cd ..
echo       Frontend launched on http://localhost:5174!
echo.

echo ==================================================
echo   ALL SYSTEMS GO!
echo   Waiting 5 seconds for Vite to start...
echo ==================================================
timeout /t 5 /nobreak >nul

:: Open Firefox to the Vite dev server
start firefox http://localhost:5174

echo.
echo You can safely close this launcher window now.
echo The servers are running in the separate command windows that popped up!
pause
