#!/bin/bash
set -euo pipefail

# Deploy frontend to AWS ECS using Podman
# This script builds, pushes, and deploys the frontend container image

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONTAINERFILE="$PROJECT_ROOT/infrastructure/containers/frontend/Containerfile"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-podman}
AWS_REGION=${AWS_REGION:-ap-southeast-4}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-058264339990}
ENVIRONMENT=${ENVIRONMENT:-staging}
ECR_FRONTEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ENVIRONMENT-scribe-frontend"
ECS_CLUSTER="$ENVIRONMENT-scribe-cluster"
FRONTEND_SERVICE="$ENVIRONMENT-scribe-frontend"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    if ! command -v "$CONTAINER_RUNTIME" &> /dev/null; then
        log_error "Runtime '$CONTAINER_RUNTIME' not found."
        exit 1
    fi
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed."
        exit 1
    fi
    if [ ! -f "$CONTAINERFILE" ]; then
        log_error "Containerfile not found at $CONTAINERFILE"
        exit 1
    fi
    log_success "Prerequisites check passed"
}

# ECR login
ecr_login() {
    log_info "Logging in to Amazon ECR..."
    aws ecr get-login-password --region $AWS_REGION | $CONTAINER_RUNTIME login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
    log_success "ECR login successful"
}

# Build frontend image
build_frontend() {
    log_info "Building frontend container image (Podman)..."
    cd "$PROJECT_ROOT"

    BUILD_CMD="$CONTAINER_RUNTIME build"
    BUILD_CMD="$BUILD_CMD --format docker"
    BUILD_CMD="$BUILD_CMD -f $CONTAINERFILE"
    BUILD_CMD="$BUILD_CMD -t scribe-frontend:latest"
    BUILD_CMD="$BUILD_CMD -t $ECR_FRONTEND_REPO:latest"

    if [ "${NO_CACHE:-false}" = true ]; then
        BUILD_CMD="$BUILD_CMD --no-cache"
        log_info "Building with --no-cache option"
    fi

    BUILD_CMD="$BUILD_CMD ."

    log_info "Build command: $BUILD_CMD"
    if eval "$BUILD_CMD"; then
        log_success "Frontend image built successfully"
    else
        log_error "Frontend build failed"
        exit 1
    fi
}

# Push frontend image to ECR
push_frontend() {
    log_info "Pushing frontend image to ECR..."
    if $CONTAINER_RUNTIME push --compression-format gzip --remove-signatures $ECR_FRONTEND_REPO:latest; then
        log_success "Frontend image pushed successfully"
    else
        log_error "Frontend push failed"
        exit 1
    fi
}

# Deploy service to ECS
deploy_service() {
    log_info "Deploying $FRONTEND_SERVICE to ECS..."
    aws ecs update-service \
        --cluster $ECS_CLUSTER \
        --service $FRONTEND_SERVICE \
        --force-new-deployment \
        --region $AWS_REGION

    log_success "Frontend deployment initiated"

    log_info "Waiting for service to stabilize..."
    aws ecs wait services-stable \
        --cluster $ECS_CLUSTER \
        --services $FRONTEND_SERVICE \
        --region $AWS_REGION
    log_success "Frontend deployment completed"
}

# Main execution
main() {
    log_info "Starting frontend deployment process..."

    # Parse --no-cache flag
    for arg in "$@"; do
        if [[ "$arg" == "--no-cache" ]]; then
            export NO_CACHE=true
            log_info "No-cache build enabled"
            break
        fi
    done

    check_prerequisites
    ecr_login
    build_frontend
    push_frontend
    deploy_service

    log_success "🚀 Frontend deployment process completed successfully!"
}

main "$@"
