@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install Python 3.8+ from https://www.python.org/downloads/
  echo         and check "Add Python to PATH" during setup.
  pause
  exit /b 1
)

python -X utf8 ctbu_wired_login.py %*
echo.
pause
