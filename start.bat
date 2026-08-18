@echo off
chcp 65001 > nul
title SNMP Security Alert
cd /d "e:\tanchuang"

echo ============================================
echo   SNMP Security Alert - Launcher
echo   Encoding: UTF-8 (chcp 65001)
echo   Chinese logs will display correctly
echo ============================================
echo.
echo Starting Electron...
echo (Close this window to stop the app)
echo.

node_modules\.bin\electron.cmd .

pause
