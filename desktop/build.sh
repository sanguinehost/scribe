#!/usr/bin/env bash

set -e

echo "Building Scribe Desktop..."

# Build frontend for desktop
echo "Building frontend..."
cd ../frontend
pnpm run build:desktop

# Run Tauri dev server
echo "Starting Tauri dev server..."
cd ../desktop
cargo tauri dev
