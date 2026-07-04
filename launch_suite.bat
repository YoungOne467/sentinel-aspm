@echo off
SETLOCAL EnableDelayedExpansion
TITLE ASPM Expert Suite v3.0 - Control Center

:: ── CONFIGURATION ───────────────────────────────────────────
SET FRONTEND_DIR=aspm-frontend
SET BACKEND_DIR=backend
SET FE_PORT=5174
SET BE_PORT=8000

cls
echo ==========================================================
echo    ASPM EXPERT SUITE v3.0 - AUTONOMOUS INTELLIGENCE
echo ==========================================================
echo.

:: ── CHECK FRONTEND ──────────────────────────────────────────
echo [*] Checking Frontend Environment...
if not exist "%FRONTEND_DIR%\node_modules" (
    echo [!] node_modules not found. Initializing dependencies...
    cd %FRONTEND_DIR%
    call npm install
    cd ..
) else (
    echo [OK] Frontend dependencies verified.
)

:: ── CHECK BACKEND ───────────────────────────────────────────
echo [*] Checking Backend Environment...
set BACKEND_READY=0
if exist "%BACKEND_DIR%\main.py" (
    set BACKEND_READY=1
    echo [OK] Backend engine detected.
    
    if not exist "%BACKEND_DIR%\venv" (
        echo [!] venv not found. Creating virtual environment...
        cd %BACKEND_DIR%
        python -m venv venv
        cd ..
    )
) else (
    echo [!] Backend not found or incomplete. Running in Simulation Mode.
)

echo.
echo ----------------------------------------------------------
echo  [1] Start Frontend (Vite)
if !BACKEND_READY! equ 1 (
    echo  [2] Start Full Stack (FE + BE)
)
echo  [3] Exit
echo ----------------------------------------------------------
echo.

set /p choice="Select Launch Vector [1-3]: "

if "%choice%"=="1" goto :launch_fe
if "%choice%"=="2" (
    if !BACKEND_READY! equ 1 goto :launch_full
    goto :launch_fe
)
if "%choice%"=="3" exit
goto :launch_fe

:launch_fe
echo.
echo [+] Launching Frontend at http://localhost:%FE_PORT%...
cd %FRONTEND_DIR%
start cmd /k "npm run dev -- --port %FE_PORT%"
goto :done

:launch_full
echo.
echo [+] Launching Full Stack Suite...
:: Start Backend
echo [*] Starting Backend Engine (Port %BE_PORT%)...
start cmd /k "title ASPM BACKEND && cd %BACKEND_DIR% && call venv\Scripts\activate && python main.py"
:: Start Frontend
echo [*] Starting Frontend (Port %FE_PORT%)...
cd %FRONTEND_DIR%
start cmd /k "title ASPM FRONTEND && npm run dev -- --port %FE_PORT%"
goto :done

:done
echo.
echo ----------------------------------------------------------
echo  SYSTEMS OPERATIONAL. 
echo  Control windows have been detached. Close them to stop.
echo ----------------------------------------------------------
pause
exit
