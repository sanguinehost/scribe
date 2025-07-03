#!/bin/bash
# Quick disk usage checker for Rust projects

# Check for --clean flag
if [ "$1" = "--clean" ]; then
    echo "🧹 Cleaning up Rust artifacts..."
    cargo clean
    rm -rf target/*
    echo "✅ Cleanup complete!"
    echo ""
fi

echo "🔍 Checking disk usage..."
echo ""

# Check target directory
if [ -d "target" ]; then
    TARGET_SIZE=$(du -sh target/ 2>/dev/null | cut -f1)
    echo "📁 target/ directory: $TARGET_SIZE"
else
    echo "📁 target/ directory: Not found"
fi

# Check available disk space
AVAILABLE=$(df -h . | tail -1 | awk '{print $4}')
USED_PERCENT=$(df -h . | tail -1 | awk '{print $5}')
echo "💾 Available space: $AVAILABLE (${USED_PERCENT} used)"

# Check if we're running low on space
USED_NUM=$(echo $USED_PERCENT | sed 's/%//')
if [ "$USED_NUM" -gt 85 ]; then
    echo "⚠️  WARNING: Disk usage is above 85%!"
    echo "💡 Consider running: cargo clean"
fi

echo ""
echo "🧹 To clean up:"
echo "  cargo clean              # Standard cleanup"
echo "  rm -rf target/*          # Aggressive cleanup"
echo "🎯 For selective tests: cargo test --no-run <test_name>"
echo "📊 For release tests: cargo test --release"

# Offer automatic cleanup if target is large
if [ -d "target" ]; then
    TARGET_SIZE_MB=$(du -sm target/ 2>/dev/null | cut -f1)
    if [ "$TARGET_SIZE_MB" -gt 1000 ]; then
        echo ""
        echo "⚠️  Target directory is ${TARGET_SIZE_MB}MB!"
        echo "💡 Run this script with --clean to automatically clean up"
    fi
fi