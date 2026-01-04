@echo off
chcp 65001 >nul
color 0A
title FiveM Backdoor Scanner - SAFE MODE

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
echo      FiveM Backdoor Scanner (SAFE MODE)
echo  ==========================================
echo.
echo  Author : KRONOX
echo  Purpose: Scan FiveM scripts for backdoors
echo.
echo  ------------------------------------------
echo  Status : Initializing...
echo  ------------------------------------------
echo.

REM Move to script directory
cd /d "%~dp0"

echo  Scanning folder defined in script...
echo  Please wait. This may take a moment.
echo.

REM Run the Python scanner
python fivem_backdoor_scanner_ultra.py --safe

echo.
echo  ------------------------------------------
echo  Scan Completed Successfully
echo  ------------------------------------------
echo.
echo  Output  : audit_report.html
echo  Mode    : SAFE (No files modified)
echo.
echo  ==========================================
echo     Scan performed by KRONOX
echo  ==========================================
echo.
pause
