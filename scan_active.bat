@echo off
chcp 65001 >nul
color 0C
title FiveM Backdoor Scanner - ACTIVE MODE

cls
echo.
echo  ███████╗██╗██╗   ██╗███████╗███╗   ███╗
echo  ██╔════╝██║██║   ██║██╔════╝████╗ ████║
echo  █████╗  ██║██║   ██║█████╗  ██╔████╔██║
echo  ██╔══╝  ██║╚██╗ ██╔╝██╔══╝  ██║╚██╔╝██║
echo  ██║     ██║ ╚████╔╝ ███████╗██║ ╚═╝ ██║
echo  ╚═╝     ╚═╝  ╚═══╝  ╚══════╝╚═╝     ╚═╝
echo.
echo  ==========================================
echo      FiveM Backdoor Scanner (ACTIVE MODE)
echo  ==========================================
echo.
echo  Author : KRONOX
echo  Mode   : ACTIVE (FILES WILL BE MODIFIED)
echo.
echo  ------------------------------------------
echo  WARNING:
echo  - Suspicious lines will be commented out
echo  - .bak backups will be created
echo  - Review audit_report.html after run
echo  ------------------------------------------
echo.

choice /C YN /M "Do you want to continue?"

if errorlevel 2 (
    echo.
    echo Operation cancelled by user.
    echo.
    pause
    exit /b
)

echo.
echo  ------------------------------------------
echo  Status : Running ACTIVE scan...
echo  ------------------------------------------
echo.

REM Move to script directory
cd /d "%~dp0"

echo  Scanning folder defined in script...
echo  Please do not close this window.
echo.

REM Run the Python scanner (ACTIVE MODE)
python fivem_backdoor_scanner_ultra.py

echo.
echo  ------------------------------------------
echo  ACTIVE SCAN COMPLETED
echo  ------------------------------------------
echo.
echo  Output  : audit_report.html
echo  Backups : .bak files created
echo.
echo  ==========================================
echo     Scan performed by KRONOX
echo  ==========================================
echo.
pause
