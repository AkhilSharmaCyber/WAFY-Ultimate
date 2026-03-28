@echo off
echo ============================================
echo   WAFinity WAF - Setup ^& Launch
echo ============================================
echo.

cd /d "%~dp0"

echo [1/3] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed. Make sure Python 3.8+ is installed.
    pause
    exit /b 1
)

echo.
echo [2/3] Creating log directory...
if not exist logs mkdir logs

echo.
echo [3/3] Starting WAFinity backend on http://127.0.0.1:5000
echo.
echo  ^> Dashboard : http://127.0.0.1:5000/stats
echo  ^> API check : POST http://127.0.0.1:5000/check_request
echo  ^> Live feed : http://127.0.0.1:5000/live_attacks
echo.
echo  Now load the Chrome extension:
echo    1. Open chrome://extensions
echo    2. Enable Developer mode
echo    3. Click "Load unpacked"
echo    4. Select the  Wafy-Extension  folder
echo.
python app.py
pause
