#!/bin/bash

# Build script for backend using Docker
# Docker-specific build without Podman dependencies

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --tag TAG             Image tag (default: latest)"
    echo "  --no-cache                Build without cache"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CONTAINER_TAG             Override default tag"
    echo "  NO_CACHE                  Set to true to disable cache"
    exit 1
}

# Configuration
TAG=${CONTAINER_TAG:-latest}
NO_CACHE=${NO_CACHE:-false}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE=true
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

# Set up paths
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(realpath "$SCRIPT_DIR/../..")"
CONTAINERFILE="$PROJECT_ROOT/infrastructure/containers/backend/Containerfile"
BUILD_CONTEXT="$PROJECT_ROOT"

# Validate paths
if [ ! -f "$CONTAINERFILE" ]; then
    log_error "Containerfile not found at $CONTAINERFILE"
    exit 1
fi

if [ ! -d "$BUILD_CONTEXT" ]; then
    log_error "Build context not found at $BUILD_CONTEXT"
    exit 1
fi

# Set image name
LOCAL_IMAGE="localhost/scribe-backend:$TAG"

log_info "Docker build configuration:"
log_info "  Image: $LOCAL_IMAGE"
log_info "  Build context: $BUILD_CONTEXT"
log_info "  Containerfile: $CONTAINERFILE"
log_info "  No cache: $NO_CACHE"

# Build command
BUILD_CMD="docker build"
BUILD_CMD="$BUILD_CMD -f $CONTAINERFILE"
BUILD_CMD="$BUILD_CMD -t $LOCAL_IMAGE"

if [ "$NO_CACHE" = true ]; then
    BUILD_CMD="$BUILD_CMD --no-cache"
fi

BUILD_CMD="$BUILD_CMD $BUILD_CONTEXT"

# Execute build
log_info "Building backend image with Docker..."
log_info "Command: $BUILD_CMD"

if eval "$BUILD_CMD"; then
    log_info "Build completed successfully!"
else
    log_error "Build failed!"
    exit 1
fi

# Show final image info
log_info "Available images:"
docker images | grep scribe-backend || true

log_info "Build process completed!"
log_info "Image ready: $LOCAL_IMAGE"