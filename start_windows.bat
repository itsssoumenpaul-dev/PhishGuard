@echo off
title PhishGuard
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Please run setup_windows.bat first.
  pause
  exit /b 1
)
echo Starting PhishGuard at http://127.0.0.1:8080
echo Keep this window open while using the app.
".venv\Scripts\python.exe" -m phishguard.app
pause
