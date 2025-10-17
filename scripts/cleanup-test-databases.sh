#!/usr/bin/env bash
# scripts/cleanup-test-databases.sh
# Cleans up orphaned test databases and reclaims disk space

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CONTAINER_NAME="${POSTGRES_CONTAINER:-scribe_postgres}"
DB_USER="${POSTGRES_USER:-devuser}"
DB_NAME="${POSTGRES_DB:-postgres}"
MIN_AGE_HOURS="${MIN_AGE_HOURS:-1}"  # Only drop databases older than this

echo -e "${GREEN}🧹 PostgreSQL Test Database Cleanup${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if container is running
if ! podman ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}❌ Error: Container '${CONTAINER_NAME}' is not running${NC}"
    exit 1
fi

echo -e "${YELLOW}📊 Current database status:${NC}"

# Get current stats
TOTAL_DBS=$(podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT COUNT(*) FROM pg_database WHERE datname LIKE 'test_db_%';")
TOTAL_SIZE=$(podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT pg_size_pretty(SUM(pg_database_size(datname))) FROM pg_database WHERE datname LIKE 'test_db_%';")

echo "  Test databases: ${TOTAL_DBS}"
echo "  Total size: ${TOTAL_SIZE}"

if [ "${TOTAL_DBS}" -eq 0 ]; then
    echo -e "${GREEN}✅ No test databases to clean up!${NC}"
    exit 0
fi

# List databases to be dropped (older than MIN_AGE_HOURS)
echo ""
echo -e "${YELLOW}🔍 Finding test databases older than ${MIN_AGE_HOURS} hour(s)...${NC}"

# Get list of test databases with their ages
TEST_DBS=$(podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT datname FROM pg_database
     WHERE datname LIKE 'test_db_%'
     AND (pg_stat_file('base/'||oid||'/PG_VERSION')).modification < NOW() - INTERVAL '${MIN_AGE_HOURS} hours'
     ORDER BY datname;")

DB_COUNT=$(echo "${TEST_DBS}" | grep -c "test_db_" || true)

if [ "${DB_COUNT}" -eq 0 ]; then
    echo -e "${GREEN}✅ No test databases older than ${MIN_AGE_HOURS} hour(s) found${NC}"
    echo -e "${YELLOW}💡 Tip: Set MIN_AGE_HOURS=0 to drop all test databases${NC}"
    exit 0
fi

echo "  Found ${DB_COUNT} database(s) to drop"

# Confirm deletion unless FORCE is set
if [ "${FORCE:-false}" != "true" ]; then
    echo ""
    echo -e "${YELLOW}⚠️  This will DROP ${DB_COUNT} test database(s)!${NC}"
    echo -ne "${YELLOW}Continue? [y/N]: ${NC}"
    read -r response
    if [[ ! "${response}" =~ ^[Yy]$ ]]; then
        echo -e "${RED}❌ Cleanup cancelled${NC}"
        exit 0
    fi
fi

# Drop test databases
echo ""
echo -e "${GREEN}🗑️  Dropping test databases...${NC}"

DROPPED_COUNT=0
FAILED_COUNT=0

while IFS= read -r db; do
    if [ -n "${db}" ]; then
        echo -n "  Dropping ${db}... "
        if podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -c \
            "DROP DATABASE IF EXISTS \"${db}\" WITH (FORCE);" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
            ((DROPPED_COUNT++))
        else
            echo -e "${RED}✗${NC}"
            ((FAILED_COUNT++))
        fi
    fi
done <<< "${TEST_DBS}"

# Run CHECKPOINT to clean up WAL logs
echo ""
echo -e "${GREEN}📝 Running CHECKPOINT to clean WAL logs...${NC}"
podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -c "CHECKPOINT;" > /dev/null

# Run VACUUM to reclaim disk space
echo -e "${GREEN}🧹 Running VACUUM to reclaim disk space...${NC}"
podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -c "VACUUM;" > /dev/null

# Get final stats
echo ""
echo -e "${GREEN}📊 Final database status:${NC}"

REMAINING_DBS=$(podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT COUNT(*) FROM pg_database WHERE datname LIKE 'test_db_%';")
REMAINING_SIZE=$(podman exec "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -tAc \
    "SELECT pg_size_pretty(COALESCE(SUM(pg_database_size(datname)), 0)) FROM pg_database WHERE datname LIKE 'test_db_%';")

echo "  Test databases remaining: ${REMAINING_DBS}"
echo "  Total size: ${REMAINING_SIZE}"

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✅ Cleanup complete!${NC}"
echo "  Dropped: ${DROPPED_COUNT} database(s)"
if [ "${FAILED_COUNT}" -gt 0 ]; then
    echo -e "  ${RED}Failed: ${FAILED_COUNT} database(s)${NC}"
fi

# Check WAL size
WAL_SIZE=$(sudo du -sh /home/socol/.local/share/containers/storage/volumes/compose_postgres_data/_data/pg_wal 2>/dev/null | cut -f1 || echo "unknown")
echo "  WAL size: ${WAL_SIZE}"

echo ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo "  • Run this script regularly to prevent database bloat"
echo "  • Set MIN_AGE_HOURS=0 to drop all test databases: MIN_AGE_HOURS=0 $0"
echo "  • Skip confirmation with: FORCE=true $0"
echo "  • Add to cron for automatic cleanup"
