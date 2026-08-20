@echo off
setlocal enabledelayedexpansion

REM HTTP/HTTPS Traffic Analyzer - Windows launcher
REM This script installs dependencies and runs the application

echo Checking for Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.9+ and add it to PATH.
    pause
    exit /b 1
)

echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Starting HTTP/HTTPS Traffic Analyzer...
echo.
python main.py %*

pause
