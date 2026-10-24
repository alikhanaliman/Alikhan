@echo off
cd /d "%~dp0"
echo Installing Python packages for PhysiX...
py -m pip install -r requirements.txt
if errorlevel 1 (
 echo Python/pip error. Install Python from python.org and retry.
 pause
 exit /b 1
)
echo.
echo Open http://127.0.0.1:5000 in your browser.
py app.py
pause
