#!/bin/bash

# Build script for backend using Podman
# Supports both local and registry builds

set -euo pipefail

# Configuration
RUNTIME=${CONTAINER_RUNTIME:-podman}
REGISTRY=${CONTAINER_REGISTRY:-quay.io}
NAMESPACE=${CONTAINER_NAMESPACE:-sanguine-scribe}
TAG=${CONTAINER_TAG:-latest}
NO_CACHE=${NO_CACHE:-false}

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
    echo "  -r, --registry REGISTRY    Container registry (default: quay.io)"
    echo "  -n, --namespace NAMESPACE  Registry namespace (default: sanguine-scribe)"
    echo "  -t, --tag TAG             Image tag (default: latest)"
    echo "  --no-cache                Build without cache"
    echo "  --local-only              Build for local use only (no registry push)"
    echo "  --runtime RUNTIME         Container runtime (podman|docker, default: podman)"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CONTAINER_RUNTIME         Override default runtime"
    echo "  CONTAINER_REGISTRY        Override default registry"
    echo "  CONTAINER_NAMESPACE       Override default namespace"
    echo "  CONTAINER_TAG             Override default tag"
    echo "  NO_CACHE                  Set to true to disable cache"
    exit 1
}

# Parse command line arguments
LOCAL_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --local-only)
            LOCAL_ONLY=true
            shift
            ;;
        --runtime)
            RUNTIME="$2"
            shift 2
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

# Validate runtime
if ! command -v "$RUNTIME" &> /dev/null; then
    log_error "Runtime '$RUNTIME' not found. Please install it first."
    exit 1
fi

# Set up paths
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(realpath "$SCRIPT_DIR/../../..")"
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

# Set image names
LOCAL_IMAGE="scribe-backend:$TAG"
if [ "$LOCAL_ONLY" = false ]; then
    REGISTRY_IMAGE="$REGISTRY/$NAMESPACE/scribe-backend:$TAG"
else
    REGISTRY_IMAGE=""
fi

log_info "Build configuration:"
log_info "  Runtime: $RUNTIME"
log_info "  Local image: $LOCAL_IMAGE"
if [ -n "$REGISTRY_IMAGE" ]; then
    log_info "  Registry image: $REGISTRY_IMAGE"
fi
log_info "  Build context: $BUILD_CONTEXT"
log_info "  Containerfile: $CONTAINERFILE"
log_info "  No cache: $NO_CACHE"

# Build command
BUILD_CMD="$RUNTIME build"
BUILD_CMD="$BUILD_CMD --format docker"  # Ensure Docker format for compatibility
BUILD_CMD="$BUILD_CMD -f $CONTAINERFILE"
BUILD_CMD="$BUILD_CMD -t $LOCAL_IMAGE"

if [ -n "$REGISTRY_IMAGE" ]; then
    BUILD_CMD="$BUILD_CMD -t $REGISTRY_IMAGE"
fi

if [ "$NO_CACHE" = true ]; then
    BUILD_CMD="$BUILD_CMD --no-cache"
fi

BUILD_CMD="$BUILD_CMD $BUILD_CONTEXT"

# Execute build
log_info "Building backend image..."
log_info "Command: $BUILD_CMD"

if eval "$BUILD_CMD"; then
    log_info "Build completed successfully!"
else
    log_error "Build failed!"
    exit 1
fi

# Push to registry if requested
if [ "$LOCAL_ONLY" = false ] && [ -n "$REGISTRY_IMAGE" ]; then
    log_info "Pushing to registry..."
    if $RUNTIME push "$REGISTRY_IMAGE"; then
        log_info "Push completed successfully!"
        log_info "Image available at: $REGISTRY_IMAGE"
    else
        log_error "Push failed!"
        exit 1
    fi
fi

# Show final image info
log_info "Available images:"
$RUNTIME images | grep scribe-backend || true

log_info "Build process completed!"