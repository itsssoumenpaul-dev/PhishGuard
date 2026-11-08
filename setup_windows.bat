@echo off
title PhishGuard Setup
cd /d "%~dp0"
echo ========================================
echo          PhishGuard - First Setup
echo ========================================
echo.
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.11 or newer and enable "Add Python to PATH".
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv .venv
  if errorlevel 1 goto error
)
echo Installing required packages...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto error
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto error
echo.
echo Setup complete. Run start_windows.bat to launch PhishGuard.
pause
exit /b 0
:error
echo.
echo Setup failed. Check your internet connection and Python installation.
pause
exit /b 1
