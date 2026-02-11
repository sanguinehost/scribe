#!/bin/bash
set -euo pipefail

# Deploy frontend to AWS ECS
# This script builds, pushes, and deploys the frontend Docker image

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION=${AWS_REGION:-ap-southeast-4}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-058264339990}
ECR_FRONTEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/staging-scribe-frontend"
ECS_CLUSTER="staging-scribe-cluster"
FRONTEND_SERVICE="staging-scribe-frontend" # Assuming this service name based on standard naming

# Auto-detect container runtime (prefer Podman)
if command -v podman &> /dev/null; then
    RUNTIME="podman"
else
    RUNTIME="docker"
fi

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Login to ECR
ecr_login() {
    log_info "Logging in to Amazon ECR..."
    aws ecr get-login-password --region $AWS_REGION | $RUNTIME login --username AWS --password-stdin $ECR_FRONTEND_REPO
    log_success "ECR login successful"
}

# Build frontend image
build_frontend() {
    log_info "Building frontend image with $RUNTIME..."
    cd "$PROJECT_ROOT"

    # Build command using the frontend Containerfile
    # Note: The Context is PROJECT_ROOT because the Containerfile copies from frontend/
    BUILD_CMD="$RUNTIME build -f infrastructure/containers/frontend/Containerfile"

    if [[ "${NO_CACHE:-false}" == "true" ]]; then
        BUILD_CMD="$BUILD_CMD --no-cache"
    fi

    # Tag as latest
    BUILD_CMD="$BUILD_CMD -t scribe-frontend:latest -t $ECR_FRONTEND_REPO:latest ."

    log_info "Build command: $BUILD_CMD"
    if eval "$BUILD_CMD"; then
        log_success "Frontend image built successfully"
    else
        log_error "Frontend build failed"
        exit 1
    fi
}

# Push frontend image
push_frontend() {
    log_info "Pushing frontend image to ECR..."
    $RUNTIME push $ECR_FRONTEND_REPO:latest
    log_success "Frontend image pushed successfully"
}

# Update ECS service
update_service() {
    log_info "Updating ECS service..."
    aws ecs update-service \
        --cluster $ECS_CLUSTER \
        --service $FRONTEND_SERVICE \
        --force-new-deployment \
        --region $AWS_REGION
    log_success "ECS service updated"
}

main() {
    log_info "Starting frontend deployment..."

    ecr_login
    build_frontend
    push_frontend
    update_service

    log_success "🚀 Frontend deployment completed!"
}

main "$@"
