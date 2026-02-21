#!/bin/bash
set -euo pipefail

# Unified Local Deployment Script using Podman
# Orchestrates the full stack (Infra + App) locally.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 [up|down|reset|build|help]"
    echo ""
    echo "Commands:"
    echo "  up      Start the full stack locally (Infra + App)"
    echo "  down    Stop all local services"
    echo "  reset   Stop and remove all volumes/data"
    echo "  build   Build backend and frontend images locally"
    echo ""
}

check_runtime() {
    if ! command -v podman &> /dev/null; then
        log_error "Podman is not installed."
        exit 1
    fi
}

start_infra() {
    log_info "Starting infrastructure (PostgreSQL, Qdrant)..."
    "$PROJECT_ROOT/scripts/podman-dev.sh" up
}

build_app() {
    log_info "Building application images..."
    cd "$PROJECT_ROOT"

    # Build Backend (Desktop features for local dev usually, but cloud for full container test)
    log_info "Building Backend..."
    podman build -f infrastructure/containers/backend/Containerfile -t scribe-backend:local .

    # Build Frontend
    log_info "Building Frontend..."
    podman build -f infrastructure/containers/frontend/Containerfile -t scribe-frontend:local .
}

run_app() {
    log_info "Starting application services..."
    # Note: In a real scenario, we might use podman-compose for the app too,
    # but for now we interact with the existing dev infrastructure.

    # Check if network exists
    if ! podman network inspect scribe_network &>/dev/null; then
        log_info "Creating scribe_network..."
        podman network create scribe_network
    fi

    log_info "Application services should be configured to connect to infra on 'scribe_network'."
    log_info "Running backend..."
    podman run -d --name scribe_backend_local \
        --replace \
        --network scribe_network \
        -p 8080:8080 \
        -e DATABASE_URL="postgres://devuser:devpassword@scribe_postgres:5432/sanguine_scribe_dev" \
        scribe-backend:local

    log_info "Running frontend..."
    podman run -d --name scribe_frontend_local \
        --replace \
        --network scribe_network \
        -p 3000:3000 \
        -e PUBLIC_API_URL="http://localhost:8080" \
        scribe-frontend:local
}

main() {
    check_runtime
    COMMAND="${1:-help}"

    case "$COMMAND" in
        up)
            start_infra
            build_app
            run_app
            log_success "🚀 Local full stack is up!"
            ;;
        down)
            log_info "Stopping services..."
            podman stop scribe_backend_local scribe_frontend_local 2>/dev/null || true
            podman rm scribe_backend_local scribe_frontend_local 2>/dev/null || true
            "$PROJECT_ROOT/scripts/podman-dev.sh" down
            ;;
        reset)
            log_info "Resetting everything..."
            podman stop scribe_backend_local scribe_frontend_local 2>/dev/null || true
            podman rm scribe_backend_local scribe_frontend_local 2>/dev/null || true
            "$PROJECT_ROOT/scripts/podman-dev.sh" reset
            ;;
        build)
            build_app
            ;;
        *) usage; exit 1 ;;
    esac
}

main "$@"
