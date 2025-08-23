#!/bin/bash

# Docker Development Environment Setup
# One-command Docker deployment for Sanguine Scribe

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Docker Development Environment for Sanguine Scribe"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --build-only              Only build backend, don't start services"
    echo "  --no-build               Skip building backend image"
    echo "  --clean                  Clean existing containers and volumes"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "This script will:"
    echo "  1. Generate TLS certificates for Docker runtime"
    echo "  2. Build the backend Docker image"
    echo "  3. Start all services with docker-compose"
    exit 1
}

# Configuration
BUILD_BACKEND=true
START_SERVICES=true
CLEAN_FIRST=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            START_SERVICES=false
            shift
            ;;
        --no-build)
            BUILD_BACKEND=false
            shift
            ;;
        --clean)
            CLEAN_FIRST=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate Docker is available
if ! command -v docker &> /dev/null; then
    log_error "Docker not found. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    log_error "docker-compose not found. Please install docker-compose first."
    exit 1
fi

# Set up paths
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(realpath "$SCRIPT_DIR/..")"

# Change to project root
cd "$PROJECT_ROOT"

log_info "🚀 Starting Docker development environment setup..."
log_info "Project root: $PROJECT_ROOT"

# Clean existing setup if requested
if [ "$CLEAN_FIRST" = true ]; then
    log_info "🧹 Cleaning existing containers and volumes..."
    docker-compose down --volumes --remove-orphans || log_warn "No containers to remove"
    docker system prune -f || log_warn "System prune failed"
fi

# Step 1: Generate certificates for Docker runtime
log_info "🔐 Setting up TLS certificates for Docker..."
if ! scripts/certs/manage.sh container init --runtime=docker; then
    log_error "Failed to generate certificates"
    exit 1
fi
log_success "TLS certificates ready for Docker runtime"

# Step 2: Build backend image if requested
if [ "$BUILD_BACKEND" = true ]; then
    log_info "🔨 Building backend Docker image..."
    if ! scripts/docker/build-backend.sh; then
        log_error "Failed to build backend image"
        exit 1
    fi
    log_success "Backend image built successfully"
fi

# Step 3: Start services with docker-compose if requested
if [ "$START_SERVICES" = true ]; then
    log_info "🚀 Starting all services with docker-compose..."
    
    # Start services
    if ! docker-compose up -d; then
        log_error "Failed to start services with docker-compose"
        exit 1
    fi
    
    log_success "All services started successfully!"
    
    # Show status
    log_info "📊 Service status:"
    docker-compose ps
    
    log_info "🌐 Access points:"
    log_info "  Backend API: https://localhost:8080"
    log_info "  PostgreSQL: localhost:5432"
    log_info "  Qdrant: https://localhost:6334"
    log_info ""
    log_info "📝 Logs:"
    log_info "  All services: docker-compose logs -f"
    log_info "  Backend only: docker-compose logs -f backend"
    log_info ""
    log_info "🛑 To stop services:"
    log_info "  docker-compose down"
fi

log_success "🎉 Docker development environment setup complete!"