@echo off
title Vexora Shield Launcher
color 0A

echo.
echo  ========================================================================
echo   Vexora: Multi-Layered Prompt Injection Defense Framework
echo   Starting Flask backend + Edge with extension
echo  ========================================================================
echo.

REM Step 1: Start Flask backend in background
echo  [1/2] Starting Flask security server...
start "" /min cmd /c "cd /d C:\Users\ss988\OneDrive\LLM-Based-Prompt-Injection-main && python app.py"

REM Wait 3 seconds for Flask to boot
timeout /t 3 /nobreak > nul

REM Step 2: Launch Edge with extension pre-loaded + open ChatGPT
echo  [2/2] Launching Edge with Vexora extension...
start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" ^
  --load-extension="C:\Users\ss988\OneDrive\LLM-Based-Prompt-Injection-main\browser-extension" ^
  --no-first-run ^
  --no-default-browser-check ^
  "https://chatgpt.com"

echo.
echo  Done! Edge is opening with Vexora active.
echo  - Look for the shield badge when you type on ChatGPT
echo  - Also works on gemini.google.com and claude.ai
echo.
echo  Press any key to exit this window...
pause > nul
