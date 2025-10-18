#!/usr/bin/env bash

set -e

echo "Building frontend for desktop..."

# Backup original svelte.config.js
cp svelte.config.js svelte.config.js.bak

# Use desktop config
cp svelte.config.desktop.js svelte.config.js

# Build
pnpm run build

# Restore original config
mv svelte.config.js.bak svelte.config.js

echo "Desktop frontend build complete!"
