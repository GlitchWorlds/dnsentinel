#!/bin/bash
cd "$(dirname "$0")/electron"
if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing Electron dependencies..."
    npm install
fi
echo "[INFO] Starting DNSentinel Electron GUI..."
npm start
