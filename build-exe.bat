@echo off
pip install -r requirements-build.txt
pyinstaller --noconfirm --onefile --windowed --name DNSentinel --add-data agent.py;. --add-data config.yaml;. --add-data blocklist.txt;. gui.py
pause
