#!/usr/bin/env bash

set -e

echo "Building frontend for desktop..."

# Backup configs
cp svelte.config.js svelte.config.js.bak
cp .env.production .env.production.bak 2>/dev/null || true

# Use desktop configs
cp svelte.config.desktop.js svelte.config.js
cp .env.production.desktop .env.production

# Build
NODE_ENV=production pnpm run build

# Restore original configs
mv svelte.config.js.bak svelte.config.js
mv .env.production.bak .env.production 2>/dev/null || true

echo "Desktop frontend build complete!"
