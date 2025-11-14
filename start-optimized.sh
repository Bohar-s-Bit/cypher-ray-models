#!/bin/bash
# Optimized startup script for Render - faster cold starts

# Set production environment
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

# Start with optimized uvicorn settings
exec uvicorn main:app \
  --host 0.0.0.0 \
  --port $PORT \
  --workers 1 \
  --timeout-keep-alive 65 \
  --log-level info \
  --no-access-log
