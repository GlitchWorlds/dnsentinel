@echo off
title DNSentinel Desktop GUI
cd /d "%~dp0electron"
if not exist node_modules (
    echo [INFO] Installing Electron dependencies...
    call npm install
)
echo [INFO] Starting DNSentinel Electron GUI...
call npm start
