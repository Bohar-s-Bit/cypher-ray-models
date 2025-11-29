#!/bin/bash

# Cache cleanup script for production
# Run this after deploying v4.2 to clear malformed cached responses

echo "🧹 CypherRay Cache Cleanup - v4.2"
echo "=================================="
echo ""

# Get cache directory
CACHE_DIR="cache"

if [ ! -d "$CACHE_DIR" ]; then
    echo "❌ Cache directory not found: $CACHE_DIR"
    echo "   Are you in the correct directory?"
    exit 1
fi

# Count cache files
COUNT=$(find "$CACHE_DIR" -name "*.json" -type f | wc -l | tr -d ' ')

if [ "$COUNT" -eq 0 ]; then
    echo "✅ Cache is already empty (0 files)"
    exit 0
fi

echo "📊 Found $COUNT cached responses"
echo ""
echo "⚠️  This will delete ALL cached analysis results."
echo "   They will be regenerated with v4.2 improvements:"
echo "   - Robust JSON parser with repair strategies"
echo "   - Stricter JSON formatting validation"
echo "   - Better error logging"
echo ""

# Ask for confirmation (skip if --force flag)
if [ "$1" != "--force" ]; then
    read -p "Continue? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Aborted"
        exit 0
    fi
fi

# Delete cache files
echo "🗑️  Deleting cache files..."
rm -rf "$CACHE_DIR"/*.json

# Verify deletion
NEW_COUNT=$(find "$CACHE_DIR" -name "*.json" -type f 2>/dev/null | wc -l | tr -d ' ')

if [ "$NEW_COUNT" -eq 0 ]; then
    echo "✅ Successfully cleared $COUNT cached responses"
    echo ""
    echo "📌 Next steps:"
    echo "   1. Restart the service (if not auto-restarting)"
    echo "   2. New analyses will use v4.2 improvements"
    echo "   3. Monitor logs/json_parse_error_*.txt for any issues"
else
    echo "⚠️  Warning: $NEW_COUNT files remain"
    echo "   You may need to manually check permissions"
fi

echo ""
echo "✅ Cache cleanup complete!"
