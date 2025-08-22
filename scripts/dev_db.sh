#!/bin/bash

# Container management utility script for development
# Prefers Podman (modern, rootless, secure) with Docker as fallback

COMMAND=$1

# Function to print usage
usage() {
  echo "Container Development Environment Manager"
  echo "Usage: $0 {up|down|reset|reset-up|logs|ps}"
  echo ""
  echo "Commands:"
  echo "  up      : Start containers and run database migrations"
  echo "  down    : Stop containers"
  echo "  reset   : Stop containers and remove volumes"
  echo "  reset-up: Reset containers and volumes, then start them up again"
  echo "  logs    : Follow logs for all services"
  echo "  ps      : List running containers"
  echo ""
  echo "Runtime Detection (in order of preference):"
  echo "  1. podman compose (modern, rootless, secure)"
  echo "  2. docker compose (fallback)"
  echo "  3. docker-compose (legacy fallback)"
  echo ""
  echo "Recommendation: Use './scripts/podman-dev.sh' for modern Podman workflow"
  exit 1
}

# Detect container runtime and compose tool (prefer podman)
detect_runtime() {
    if command -v podman &> /dev/null; then
        RUNTIME="podman"
        
        # Setup podman environment for docker-compose compatibility
        echo "Setting up podman environment..."
        systemctl --user start podman.socket
        export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
        
        # Clean up any problematic networks from previous runs
        podman network rm compose_default 2>/dev/null || true
        
        # Check for compose providers
        if command -v docker-compose &> /dev/null; then
            export PODMAN_COMPOSE_PROVIDER="docker-compose"
            DC_CMD="podman compose"
            RUNTIME_DESC="podman compose (with docker-compose backend)"
        elif command -v podman-compose &> /dev/null; then
            export PODMAN_COMPOSE_PROVIDER="podman-compose"
            DC_CMD="podman compose"
            RUNTIME_DESC="podman compose (with podman-compose backend - deprecated)"
            echo "Warning: Using deprecated podman-compose. Consider installing docker-compose."
        else
            echo "Error: Podman found but no compose provider available."
            echo "Install: docker-compose or podman-compose"
            exit 1
        fi
    elif command -v docker &> /dev/null && docker compose version &> /dev/null; then
        RUNTIME="docker"
        DC_CMD="docker compose"
        RUNTIME_DESC="docker compose"
    elif command -v docker-compose &> /dev/null; then
        RUNTIME="docker"
        DC_CMD="docker-compose"
        RUNTIME_DESC="docker-compose (legacy)"
    else
        echo "Error: No container runtime found."
        echo "Install: podman (recommended) or docker"
        exit 1
    fi
    
    echo "Using runtime: $RUNTIME_DESC"
}

# Change to the project root directory (one level up from scripts) 
PROJECT_ROOT="$(dirname "$0")/.."
cd "$PROJECT_ROOT" || exit

# Detect runtime first
detect_runtime

# Define Database URL - consistent with compose configurations
DATABASE_URL="postgres://devuser:devpassword@localhost:5432/sanguine_scribe_dev"

# Set compose files based on runtime
if [ "$RUNTIME" = "podman" ]; then
    COMPOSE_FILES="-f infrastructure/containers/compose/podman-compose.yml -f infrastructure/containers/compose/podman-compose.local.yml"
    SERVICES="postgres qdrant"  # Only start these services for local development
else
    COMPOSE_FILES=""  # Use default docker-compose.yml
    SERVICES=""       # Start all services
fi

case "$COMMAND" in
  up)
    echo "Starting services in detached mode..."
    $DC_CMD $COMPOSE_FILES up -d $SERVICES
    UP_STATUS=$?
    if [ $UP_STATUS -ne 0 ]; then
        echo "Container startup failed!"
        exit $UP_STATUS
    fi

    # Wait for services to initialize
    echo "Waiting for database to initialize..."
    sleep 5

    echo "Running database migrations..."
    if command -v diesel &> /dev/null; then
        (cd "$PROJECT_ROOT/backend" && DATABASE_URL="$DATABASE_URL" diesel migration run) 
        MIGRATION_STATUS=$?
    else 
        echo "Warning: 'diesel' command not found. Skipping migrations."
        echo "Install: cargo install diesel_cli --no-default-features --features postgres"
        MIGRATION_STATUS=0
    fi

    if [ $MIGRATION_STATUS -ne 0 ]; then
        echo "Database migrations failed!"
        exit $MIGRATION_STATUS
    fi
    
    if [ "$RUNTIME" = "podman" ]; then
        echo ""
        echo "✅ Podman development environment ready!"
        echo "📊 PostgreSQL: localhost:5432 (TLS enabled)"
        echo "🔍 Qdrant: https://localhost:6333, gRPC: https://localhost:6334"
        echo ""
        echo "💡 Consider using './scripts/podman-dev.sh' for enhanced Podman workflow"
    fi
    ;;
  down)
    echo "Stopping services..."
    $DC_CMD $COMPOSE_FILES down
    ;;
  reset)
    echo "Stopping services and removing volumes (clearing data)..."
    $DC_CMD $COMPOSE_FILES down -v
    ;;
  reset-up)
    echo "Stopping services and removing volumes (clearing data)..."
    $DC_CMD $COMPOSE_FILES down -v
    
    echo "Starting services in detached mode..."
    $DC_CMD $COMPOSE_FILES up -d $SERVICES
    UP_STATUS=$?
    if [ $UP_STATUS -ne 0 ]; then
        echo "Container startup failed!"
        exit $UP_STATUS
    fi

    echo "Waiting for database to initialize..."
    sleep 5

    echo "Running database migrations..."
    if command -v diesel &> /dev/null; then
        (cd "$PROJECT_ROOT/backend" && DATABASE_URL="$DATABASE_URL" diesel migration run) 
        MIGRATION_STATUS=$?
    else 
        echo "Warning: 'diesel' command not found. Skipping migrations."
        echo "Install: cargo install diesel_cli --no-default-features --features postgres"
        MIGRATION_STATUS=0
    fi

    if [ $MIGRATION_STATUS -ne 0 ]; then
        echo "Database migrations failed!"
        exit $MIGRATION_STATUS
    fi
    ;;
  logs)
    echo "Following logs (Ctrl+C to stop)..."
    $DC_CMD $COMPOSE_FILES logs -f
    ;;
  ps)
    echo "Listing container status..."
    $DC_CMD $COMPOSE_FILES ps
    ;;
  *)
    usage
    ;;
esac

echo "Done."
exit 0
