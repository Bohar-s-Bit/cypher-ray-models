#!/bin/bash
# Fast restart script - clears Python cache and restarts server

echo "🔄 Stopping server..."
pkill -9 -f "python.*main.py" 2>/dev/null
pkill -9 -f "uvicorn" 2>/dev/null
sleep 1

echo "🧹 Clearing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
find . -name "*.pyo" -delete 2>/dev/null

echo "✅ Cache cleared"
echo "🚀 Starting server..."
python main.py
