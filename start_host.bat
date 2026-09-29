@echo off
title REALSAFE - Host Server & Cloudflare Tunnel
color 0B
echo ========================================================================
echo   REALSAFE - Digital Real Estate Scam Prevention Platform
echo   Launching Host Server on your laptop...
echo ========================================================================
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not detected in PATH.
    echo Please ensure Python is installed and added to PATH.
    pause
    exit /b 1
)

REM Run the orchestrator
python host_server.py

pause
