#!/usr/bin/env bash
cd "$(dirname "$0")"
python3 -m pip install -r requirements.txt >/dev/null 2>&1 || echo "Run: pip install -r requirements.txt"
exec python3 app.py
