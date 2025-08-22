#!/bin/bash

# Modern Podman development utility script for Sanguine Scribe
# Uses podman compose (not deprecated podman-compose) with docker-compose backend
# Supports TLS-enabled PostgreSQL and Qdrant containers

set -euo pipefail

COMMAND="${1:-help}"

# Project paths
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$PROJECT_ROOT/infrastructure/containers/compose"
CERTS_DIR="$PROJECT_ROOT/.certs"

# Function to print usage
usage() {
    echo "Modern Podman Development Environment"
    echo "Usage: $0 {up|down|reset|logs|ps|certs|help}"
    echo ""
    echo "Commands:"
    echo "  up      : Start PostgreSQL and Qdrant with TLS enabled"
    echo "  down    : Stop containers"
    echo "  reset   : Stop containers and remove volumes"
    echo "  logs    : Follow logs for all services"
    echo "  ps      : List running containers"
    echo "  certs   : Generate TLS certificates if missing"
    echo "  help    : Show this help message"
    echo ""
    echo "This script uses 'podman compose' with docker-compose backend for"
    echo "rootless, secure container management with TLS encryption."
    exit 1
}

# Setup podman environment for docker-compose compatibility
setup_podman_env() {
    if ! command -v podman &>/dev/null; then
        echo "Error: podman not found. Please install podman." >&2
        exit 1
    fi

    # Start podman socket for docker-compose compatibility
    echo "Ensuring podman socket is active..."
    systemctl --user start podman.socket
    
    # Set DOCKER_HOST to use podman socket
    export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
    
    # Clean up any problematic networks from previous runs
    podman network rm compose_default 2>/dev/null || true
}

# Check dependencies
check_deps() {
    setup_podman_env

    # Set compose provider preference
    if command -v docker-compose &>/dev/null; then
        export PODMAN_COMPOSE_PROVIDER="docker-compose"
    elif command -v podman-compose &>/dev/null; then
        export PODMAN_COMPOSE_PROVIDER="podman-compose"
        echo "Warning: Using deprecated podman-compose. Consider installing docker-compose." >&2
    else
        echo "Error: No compose provider found. Install docker-compose or podman-compose." >&2
        exit 1
    fi
}

# Ensure certificates exist
ensure_certs() {
    if [[ ! -f "$CERTS_DIR/cert.pem" || ! -f "$CERTS_DIR/key.pem" ]]; then
        echo "TLS certificates not found. Generating..."
        "$PROJECT_ROOT/scripts/dev_certs.sh" generate
    fi
}

# Database URL for migrations
DATABASE_URL="postgres://devuser:devpassword@localhost:5432/sanguine_scribe_dev"

# Change to project root
cd "$PROJECT_ROOT"

case "$COMMAND" in
    up)
        echo "Starting Podman development environment..."
        check_deps
        ensure_certs
        
        echo "Using compose provider: ${PODMAN_COMPOSE_PROVIDER}"
        echo "Starting PostgreSQL and Qdrant with TLS enabled..."
        
        podman compose \
            -f "$COMPOSE_DIR/podman-compose.yml" \
            -f "$COMPOSE_DIR/podman-compose.local.yml" \
            up -d postgres qdrant
        
        echo "Waiting for database to initialize..."
        sleep 5
        
        echo "Running database migrations..."
        if command -v diesel &>/dev/null; then
            (cd "$PROJECT_ROOT/backend" && DATABASE_URL="$DATABASE_URL" diesel migration run)
        else
            echo "Warning: diesel not found. Skipping migrations."
            echo "Install diesel-cli: cargo install diesel_cli --no-default-features --features postgres"
        fi
        
        echo ""
        echo "✅ Development environment ready!"
        echo "📊 PostgreSQL: localhost:5432 (TLS enabled)"
        echo "🔍 Qdrant: https://localhost:6333, gRPC: https://localhost:6334"
        ;;
        
    down)
        echo "Stopping development environment..."
        check_deps
        
        podman compose \
            -f "$COMPOSE_DIR/podman-compose.yml" \
            -f "$COMPOSE_DIR/podman-compose.local.yml" \
            down
        ;;
        
    reset)
        echo "Resetting development environment (removing volumes)..."
        check_deps
        
        podman compose \
            -f "$COMPOSE_DIR/podman-compose.yml" \
            -f "$COMPOSE_DIR/podman-compose.local.yml" \
            down -v
        ;;
        
    logs)
        echo "Following logs (Ctrl+C to stop)..."
        check_deps
        
        podman compose \
            -f "$COMPOSE_DIR/podman-compose.yml" \
            -f "$COMPOSE_DIR/podman-compose.local.yml" \
            logs -f
        ;;
        
    ps)
        echo "Container status:"
        check_deps
        
        podman compose \
            -f "$COMPOSE_DIR/podman-compose.yml" \
            -f "$COMPOSE_DIR/podman-compose.local.yml" \
            ps
        ;;
        
    certs)
        echo "Generating TLS certificates..."
        "$PROJECT_ROOT/scripts/dev_certs.sh" generate
        ;;
        
    help|--help|-h)
        usage
        ;;
        
    *)
        echo "Error: Unknown command '$COMMAND'"
        echo ""
        usage
        ;;
esac

echo "Done."