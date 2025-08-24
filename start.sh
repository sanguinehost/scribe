#!/bin/bash

# Sanguine Scribe Intelligent Development Environment Starter
# One-command setup with auto-detection and smart defaults

set -euo pipefail

# Project paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
CERTS_SCRIPT="$SCRIPTS_DIR/certs/manage.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
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

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

log_header() {
    echo -e "${BOLD}${CYAN}$1${NC}"
}

# Configuration
RUNTIME=""
MODE=""
SKIP_BUILD=false
CLEAN=false
NO_CACHE=false
START_FRONTEND=false
HELP=false
QUIET=false

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --runtime=*)
                RUNTIME="${1#*=}"
                shift
                ;;
            --mode=*)
                MODE="${1#*=}"
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --clean)
                CLEAN=true
                shift
                ;;
            --no-cache)
                NO_CACHE=true
                shift
                ;;
            --frontend)
                START_FRONTEND=true
                shift
                ;;
            --quiet|-q)
                QUIET=true
                shift
                ;;
            --help|-h)
                HELP=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << 'EOF'
🚀 Sanguine Scribe Intelligent Development Environment Starter

USAGE:
    ./start.sh [OPTIONS]

DESCRIPTION:
    One-command setup that auto-detects your environment and starts the complete
    development stack with smart defaults. Perfect for new developers and daily use.

OPTIONS:
    --runtime=<docker|podman>    Force specific container runtime
    --mode=<local|container>     Force deployment mode
        local      - PostgreSQL + Qdrant in containers, backend via 'cargo run'
        container  - All services (PostgreSQL + Qdrant + backend) in containers
    --skip-build                 Skip container image building
    --clean                      Clean start: remove volumes and regenerate certificates
    --no-cache                   Force rebuild container images without cache
    --frontend                   Also start frontend development server
    --quiet, -q                  Minimal output
    --help, -h                   Show this help message

EXAMPLES:
    ./start.sh                   # Smart defaults: detect runtime, local mode
    ./start.sh --clean           # Fresh start with clean volumes and new certificates
    ./start.sh --mode=container  # Run all services in containers
    ./start.sh --runtime=docker  # Force Docker instead of Podman
    ./start.sh --frontend        # Start backend services + frontend dev server

WHAT THIS DOES:
    1. 🔍 Auto-detect container runtime (Podman preferred, Docker fallback)
    2. 🔒 Generate TLS certificates if missing
    3. 🏗️  Build container images if needed
    4. 🚀 Start services based on detected/specified mode:
       • Local mode: PostgreSQL + Qdrant (for 'cargo run' backend)
       • Container mode: PostgreSQL + Qdrant + Backend
    5. ✅ Health checks to ensure services are ready
    6. 📋 Display connection info and next steps

DEPLOYMENT MODES:
    Local Development (default)     - Best for active Rust development
    Full Container                  - Best for testing complete deployments

For more advanced options, use the underlying scripts:
    ./scripts/podman-dev.sh     - Advanced Podman management
    ./scripts/docker-dev.sh     - Advanced Docker management  
    ./scripts/certs/manage.sh   - Certificate management

EOF
}

# Auto-detect container runtime
detect_runtime() {
    if [[ -n "$RUNTIME" ]]; then
        log_info "Using specified runtime: $RUNTIME"
        return
    fi
    
    if command -v podman &> /dev/null; then
        RUNTIME="podman"
        log_info "Auto-detected runtime: Podman (preferred)"
    elif command -v docker &> /dev/null; then
        RUNTIME="docker" 
        log_info "Auto-detected runtime: Docker (fallback)"
    else
        log_error "No container runtime found. Please install Podman or Docker."
        log_info "Podman: https://podman.io/getting-started/installation"
        log_info "Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
}

# Auto-detect deployment mode
detect_mode() {
    if [[ -n "$MODE" ]]; then
        log_info "Using specified mode: $MODE"
        return
    fi
    
    # Check if backend container image exists
    local backend_exists=false
    if [[ "$RUNTIME" == "podman" ]] && podman image exists localhost/scribe-backend:latest 2>/dev/null; then
        backend_exists=true
    elif [[ "$RUNTIME" == "docker" ]] && docker image inspect localhost/scribe-backend:latest &> /dev/null; then
        backend_exists=true
    fi
    
    if $backend_exists; then
        MODE="container"
        log_info "Auto-detected mode: container (backend image found)"
    else
        MODE="local"
        log_info "Auto-detected mode: local (backend image not found, use 'cargo run')"
    fi
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if .env exists
    if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
        if [[ -f "$PROJECT_ROOT/.env.example" ]]; then
            log_warn ".env file not found, copying from .env.example"
            cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
            log_info "Please edit .env with your API keys (especially GEMINI_API_KEY)"
        else
            log_error ".env.example not found. Cannot create .env file."
            exit 1
        fi
    fi
    
    # Check for required tools based on runtime
    if [[ "$RUNTIME" == "podman" ]]; then
        if ! command -v podman &> /dev/null; then
            log_error "Podman not found but was selected as runtime"
            exit 1
        fi
        # For container mode, ensure compose support
        if [[ "$MODE" == "container" ]] && ! podman compose --help &> /dev/null; then
            log_error "Podman compose not available. Please update Podman to 4.0+"
            exit 1
        fi
    elif [[ "$RUNTIME" == "docker" ]]; then
        if ! command -v docker &> /dev/null; then
            log_error "Docker not found but was selected as runtime"
            exit 1
        fi
        if [[ "$MODE" == "container" ]] && ! command -v docker-compose &> /dev/null; then
            log_error "docker-compose not found. Please install docker-compose."
            exit 1
        fi
    fi
    
    # Check for Rust/Cargo in local mode
    if [[ "$MODE" == "local" ]] && ! command -v cargo &> /dev/null; then
        log_warn "Cargo not found. You'll need Rust installed to run 'cargo run' for the backend."
        log_info "Install Rust: https://rustup.rs/"
    fi
    
    log_success "Prerequisites check completed"
}

# Ensure certificates exist
ensure_certificates() {
    log_step "Checking TLS certificates..."
    
    if $CLEAN; then
        log_info "Clean mode: checking for existing certificates to remove"
        local cert_dirs=($(find "$PROJECT_ROOT" -maxdepth 1 -type d -name ".certs*" 2>/dev/null))
        if [[ ${#cert_dirs[@]} -gt 0 ]]; then
            log_warn "Found existing certificate directories that need to be removed for clean mode:"
            for dir in "${cert_dirs[@]}"; do
                echo "  $(basename "$dir")"
            done
            log_error "Please remove the certificate directories manually and re-run:"
            log_info "  rm -rf .certs*"
            log_info "  ./start.sh --clean"
            exit 1
        fi
    fi
    
    # Determine certificate mode based on deployment mode
    local cert_mode
    if [[ "$MODE" == "local" ]]; then
        cert_mode="local"
    else
        cert_mode="container"
    fi
    
    # Check if certificates exist
    local certs_exist=false
    if [[ "$cert_mode" == "local" ]]; then
        # For local mode, check for the main .certs directory
        if [[ -f "$PROJECT_ROOT/.certs/cert.pem" ]]; then
            certs_exist=true
        fi
    else
        # For container mode, check all service-specific cert directories
        if [[ -f "$PROJECT_ROOT/.certs-backend/cert.pem" && \
              -f "$PROJECT_ROOT/.certs-postgres/cert.pem" && \
              -f "$PROJECT_ROOT/.certs-qdrant/cert.pem" ]]; then
            certs_exist=true
        fi
    fi
    
    if ! $certs_exist; then
        log_info "Generating TLS certificates for $cert_mode mode..."
        if ! "$CERTS_SCRIPT" "$cert_mode" init --runtime="$RUNTIME"; then
            log_error "Certificate generation failed"
            exit 1
        fi
    else
        log_success "TLS certificates already exist"
    fi
}

# Build container images if needed
build_images() {
    if [[ "$MODE" == "local" ]] && ! $SKIP_BUILD; then
        log_info "Local mode: skipping backend image build (use 'cargo run')"
        return
    fi
    
    if $SKIP_BUILD; then
        log_info "Skipping image build as requested"
        return
    fi
    
    log_step "Building container images..."
    
    # Check if backend image exists
    local backend_exists=false
    if [[ "$RUNTIME" == "podman" ]] && podman image exists localhost/scribe-backend:latest 2>/dev/null; then
        backend_exists=true
    elif [[ "$RUNTIME" == "docker" ]] && docker image inspect localhost/scribe-backend:latest &> /dev/null; then
        backend_exists=true
    fi
    
    if $backend_exists && ! $NO_CACHE; then
        log_info "Backend image already exists, skipping build"
        return
    fi
    
    log_info "Building backend image with $RUNTIME..."
    local build_script
    if [[ "$RUNTIME" == "podman" ]]; then
        build_script="$PROJECT_ROOT/infrastructure/scripts/podman/build-backend.sh"
    else
        build_script="$PROJECT_ROOT/scripts/docker/build-backend.sh"
    fi
    
    local build_args=""
    if $NO_CACHE; then
        build_args="--no-cache"
    fi
    
    if ! $QUIET; then
        log_info "This may take several minutes on first build..."
    fi
    
    if ! bash "$build_script" --local-only $build_args; then
        log_error "Backend image build failed"
        exit 1
    fi
    
    log_success "Backend image built successfully"
}

# Start services based on mode
start_services() {
    log_step "Starting services in $MODE mode..."
    
    if [[ "$MODE" == "local" ]]; then
        start_local_services
    else
        start_container_services
    fi
}

# Start services for local development
start_local_services() {
    log_info "Starting PostgreSQL and Qdrant containers for local development..."
    
    if [[ "$RUNTIME" == "podman" ]]; then
        if ! bash "$SCRIPTS_DIR/podman-dev.sh" up; then
            log_error "Failed to start Podman services"
            exit 1
        fi
    else
        log_error "Local mode with Docker not yet implemented. Use --mode=container or switch to Podman."
        exit 1
    fi
    
    log_success "Database services started"
    log_info "Run 'cargo run --bin scribe-backend' to start the backend"
}

# Start all services in containers
start_container_services() {
    log_info "Starting all services in containers..."
    
    if $CLEAN; then
        log_info "Clean mode: removing existing containers and volumes"
        if [[ "$RUNTIME" == "podman" ]]; then
            podman-compose -f docker-compose.yml down -v 2>/dev/null || true
        else
            docker-compose down -v 2>/dev/null || true  
        fi
    fi
    
    if [[ "$RUNTIME" == "podman" ]]; then
        # Use podman-compose with docker-compose.yml
        export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
        systemctl --user start podman.socket 2>/dev/null || true
        if ! podman-compose -f "$PROJECT_ROOT/docker-compose.yml" up -d; then
            log_error "Failed to start Podman container services"
            exit 1
        fi
    else
        if ! bash "$SCRIPTS_DIR/docker-dev.sh" --no-build; then
            log_error "Failed to start Docker container services"  
            exit 1
        fi
    fi
    
    log_success "All services started in containers"
}

# Health check services
health_check() {
    log_step "Performing health checks..."
    
    # Wait for PostgreSQL
    log_info "Waiting for PostgreSQL..."
    local pg_ready=false
    for i in {1..30}; do
        if pg_isready -h localhost -p 5432 &> /dev/null; then
            pg_ready=true
            break
        fi
        sleep 1
        [[ ! $QUIET ]] && echo -n "."
    done
    echo
    
    if $pg_ready; then
        log_success "PostgreSQL is ready"
    else
        log_warn "PostgreSQL health check timed out (may still be starting)"
    fi
    
    # Wait for Qdrant
    log_info "Waiting for Qdrant..."
    local qdrant_ready=false
    for i in {1..30}; do
        if curl -k -s https://localhost:6334/health &> /dev/null; then
            qdrant_ready=true
            break
        fi
        sleep 1
        [[ ! $QUIET ]] && echo -n "."
    done
    echo
    
    if $qdrant_ready; then
        log_success "Qdrant is ready"
    else
        log_warn "Qdrant health check timed out (may still be starting)"
    fi
    
    # Check backend if in container mode
    if [[ "$MODE" == "container" ]]; then
        log_info "Waiting for backend API..."
        local backend_ready=false
        for i in {1..60}; do
            if curl -k -s https://localhost:8080/api/health &> /dev/null; then
                backend_ready=true
                break
            fi
            sleep 2
            [[ ! $QUIET ]] && echo -n "."
        done
        echo
        
        if $backend_ready; then
            log_success "Backend API is ready"
        else
            log_warn "Backend API health check timed out (check logs with: docker logs scribe_backend_dev)"
        fi
    fi
}

# Start frontend development server
start_frontend() {
    if ! $START_FRONTEND; then
        return
    fi
    
    log_step "Starting frontend development server..."
    
    if [[ ! -d "$PROJECT_ROOT/frontend" ]]; then
        log_warn "Frontend directory not found, skipping frontend startup"
        return
    fi
    
    cd "$PROJECT_ROOT/frontend"
    
    # Check if node_modules exists
    if [[ ! -d "node_modules" ]]; then
        log_info "Installing frontend dependencies..."
        if command -v pnpm &> /dev/null; then
            pnpm install
        elif command -v npm &> /dev/null; then
            npm install
        else
            log_error "No Node.js package manager found. Please install pnpm or npm."
            return
        fi
    fi
    
    log_info "Starting frontend dev server in background..."
    if command -v pnpm &> /dev/null; then
        pnpm dev > /dev/null 2>&1 &
    else
        npm run dev > /dev/null 2>&1 &
    fi
    
    log_success "Frontend development server started"
    echo "   Frontend URL: https://localhost:5173"
    
    cd "$PROJECT_ROOT"
}

# Display final status and next steps
show_status() {
    log_header "🎉 Sanguine Scribe Development Environment Ready!"
    echo
    
    log_info "Services started in $MODE mode using $RUNTIME"
    echo
    
    # Service URLs
    log_success "Service URLs:"
    echo "   PostgreSQL: localhost:5432 (devuser/devpassword/sanguine_scribe_dev)"
    echo "   Qdrant:     https://localhost:6334"
    
    if [[ "$MODE" == "container" ]]; then
        echo "   Backend:    https://localhost:8080/api/health"
    fi
    
    if $START_FRONTEND; then
        echo "   Frontend:   https://localhost:5173"
    fi
    
    echo
    
    # Next steps based on mode
    if [[ "$MODE" == "local" ]]; then
        log_info "Next steps for local development:"
        echo "   1. In another terminal: cd $PROJECT_ROOT"
        echo "   2. cargo run --bin scribe-backend"
        if ! $START_FRONTEND; then
            echo "   3. Optional: ./start.sh --frontend (to start frontend)"
        fi
    else
        log_info "All services running in containers!"
        echo "   Backend API: https://localhost:8080/api/health"
        if ! $START_FRONTEND; then
            echo "   Frontend: ./start.sh --frontend (to start frontend)"
        fi
    fi
    
    echo
    log_info "Useful commands:"
    echo "   View logs: docker-compose logs -f"
    if [[ "$RUNTIME" == "podman" ]]; then
        echo "   Stop services: ./scripts/podman-dev.sh down"
    else
        echo "   Stop services: docker-compose down"
    fi
    echo "   Clean restart: ./start.sh --clean"
}

# Main execution flow
main() {
    parse_args "$@"
    
    if $HELP; then
        show_help
        exit 0
    fi
    
    if ! $QUIET; then
        log_header "🚀 Sanguine Scribe Intelligent Development Environment Starter"
        echo
    fi
    
    detect_runtime
    detect_mode
    check_prerequisites
    ensure_certificates
    build_images
    start_services
    
    # Small delay for services to initialize
    sleep 2
    
    health_check
    start_frontend
    
    if ! $QUIET; then
        echo
        show_status
    fi
}

# Run main function with all arguments
main "$@"