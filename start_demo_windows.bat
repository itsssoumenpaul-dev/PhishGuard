@echo off
title PhishGuard Safe Demo
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Please run setup_windows.bat first.
  pause
  exit /b 1
)
echo Starting safe demo at http://127.0.0.1:8080
echo Demo mode uses a canned sample page; it does not scan the URL you type.
".venv\Scripts\python.exe" -m gunicorn --bind 127.0.0.1:8080 render_app:app
pause
