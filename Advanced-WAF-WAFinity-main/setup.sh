#!/usr/bin/env bash
set -e
echo "============================================"
echo "  WAFinity WAF - Setup & Launch"
echo "============================================"
echo ""

cd "$(dirname "$0")"

echo "[1/3] Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "[2/3] Creating log directory..."
mkdir -p logs

echo ""
echo "[3/3] Starting WAFinity backend on http://127.0.0.1:5000"
echo ""
echo "  > Dashboard : http://127.0.0.1:5000/stats"
echo "  > API check : POST http://127.0.0.1:5000/check_request"
echo "  > Live feed : http://127.0.0.1:5000/live_attacks"
echo ""
echo "  Load the Chrome extension:"
echo "    1. Open chrome://extensions"
echo "    2. Enable Developer mode"
echo "    3. Click 'Load unpacked'"
echo "    4. Select the  Wafy-Extension  folder"
echo ""
python app.py
