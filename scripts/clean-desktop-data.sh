#!/usr/bin/env bash
#
# Clean Desktop App Data
# Removes all local storage files created by the Scribe desktop app
# USE WITH CAUTION: This deletes the database, tokens, and all user data!

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==> Scribe Desktop Data Cleanup${NC}"
echo

# Determine OS-specific app data directory
if [[ "$OSTYPE" == "darwin"* ]]; then
    APP_DATA_DIR="$HOME/Library/Application Support/scribe"
    PLATFORM="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    APP_DATA_DIR="$HOME/.local/share/scribe"
    PLATFORM="Linux"
else
    echo -e "${RED}✗ Unsupported platform: $OSTYPE${NC}"
    exit 1
fi

echo -e "${BLUE}Platform: ${PLATFORM}${NC}"
echo -e "${BLUE}App Data Directory: ${APP_DATA_DIR}${NC}"
echo

# Check if directory exists
if [ ! -d "$APP_DATA_DIR" ]; then
    echo -e "${YELLOW}⚠  Directory doesn't exist - nothing to clean${NC}"
    echo -e "${GREEN}✓ Clean slate confirmed${NC}"
    exit 0
fi

# List files that will be deleted
echo -e "${YELLOW}⚠  WARNING: The following files will be PERMANENTLY DELETED:${NC}"
echo
find "$APP_DATA_DIR" -type f -exec echo "  - {}" \; 2>/dev/null || echo "  (no files found)"
echo

# Calculate total size
TOTAL_SIZE=$(du -sh "$APP_DATA_DIR" 2>/dev/null | cut -f1 || echo "0B")
echo -e "${BLUE}Total size: ${TOTAL_SIZE}${NC}"
echo

# Confirmation prompt
read -p "Are you sure you want to delete all desktop app data? (yes/no): " -r CONFIRM
echo

if [[ ! "$CONFIRM" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${BLUE}Cleanup cancelled${NC}"
    exit 0
fi

# Delete the directory
echo -e "${BLUE}==> Deleting app data directory...${NC}"
rm -rf "$APP_DATA_DIR"

if [ -d "$APP_DATA_DIR" ]; then
    echo -e "${RED}✗ Failed to delete directory${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Desktop app data cleaned successfully${NC}"
echo
echo -e "${BLUE}Deleted files:${NC}"
echo "  - scribe.db (SQLite database)"
echo "  - scribe.db-shm, scribe.db-wal (SQLite journal files)"
echo "  - session.key (Cookie signing key)"
echo "  - .tokens.dat (JWT tokens, ECDSA keys, DEK)"
echo
echo -e "${GREEN}✓ Clean slate ready - migrations will run on next launch${NC}"
