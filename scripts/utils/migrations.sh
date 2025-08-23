#!/bin/bash

# Database Migration Utility
# Handles migrations for different deployment scenarios

set -euo pipefail

COMMAND="${1:-run}"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Database Migration Utility"
    echo "Usage: $0 {run|status|redo|generate} [migration_name]"
    echo ""
    echo "Commands:"
    echo "  run              - Run pending migrations"
    echo "  status           - Check migration status"
    echo "  redo             - Redo last migration"
    echo "  generate <name>  - Generate new migration"
    echo ""
    echo "Environment variables:"
    echo "  DATABASE_URL     - Override default database URL"
    exit 1
}

check_diesel() {
    if ! command -v diesel &>/dev/null; then
        echo -e "${YELLOW}Diesel CLI not found.${NC}"
        echo "Install with: cargo install diesel_cli --no-default-features --features postgres"
        exit 1
    fi
}

get_database_url() {
    if [[ -n "${DATABASE_URL:-}" ]]; then
        echo "$DATABASE_URL"
    else
        echo "postgres://devuser:devpassword@localhost:5432/sanguine_scribe_dev"
    fi
}

case "$COMMAND" in
    run)
        echo -e "${GREEN}🗃️  Running database migrations...${NC}"
        check_diesel
        
        DATABASE_URL=$(get_database_url)
        echo -e "${BLUE}Database: $DATABASE_URL${NC}"
        
        cd "$PROJECT_ROOT/backend"
        DATABASE_URL="$DATABASE_URL" diesel migration run
        
        echo -e "${GREEN}✅ Migrations completed${NC}"
        ;;
        
    status)
        echo -e "${GREEN}📊 Checking migration status...${NC}"
        check_diesel
        
        DATABASE_URL=$(get_database_url)
        echo -e "${BLUE}Database: $DATABASE_URL${NC}"
        
        cd "$PROJECT_ROOT/backend"
        DATABASE_URL="$DATABASE_URL" diesel migration list
        ;;
        
    redo)
        echo -e "${GREEN}🔄 Redoing last migration...${NC}"
        check_diesel
        
        DATABASE_URL=$(get_database_url)
        echo -e "${BLUE}Database: $DATABASE_URL${NC}"
        
        cd "$PROJECT_ROOT/backend"
        DATABASE_URL="$DATABASE_URL" diesel migration redo
        
        echo -e "${GREEN}✅ Migration redo completed${NC}"
        ;;
        
    generate)
        MIGRATION_NAME="${2:-}"
        if [[ -z "$MIGRATION_NAME" ]]; then
            echo "Error: Migration name required"
            echo "Usage: $0 generate <migration_name>"
            exit 1
        fi
        
        echo -e "${GREEN}📝 Generating new migration: $MIGRATION_NAME${NC}"
        check_diesel
        
        cd "$PROJECT_ROOT/backend"
        diesel migration generate "$MIGRATION_NAME"
        
        echo -e "${GREEN}✅ Migration generated${NC}"
        ;;
        
    help|--help|-h)
        usage
        ;;
        
    *)
        echo "Error: Unknown command '$COMMAND'"
        usage
        ;;
esac