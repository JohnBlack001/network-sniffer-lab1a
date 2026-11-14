@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py
) else (
    python main.py
)
if errorlevel 1 (
    echo.
    echo Start failed. Install Python and run: python -m pip install -r requirements.txt
    echo Live capture also requires Npcap matching your Python architecture.
    pause
)
endlocal
