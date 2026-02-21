#!/bin/bash
set -euo pipefail

# Unified Deployment Script for AWS ECS (Sanguine Scribe)
# Supports backend, frontend, and qdrant services.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration (Defaults for Staging)
AWS_REGION=${AWS_REGION:-ap-southeast-4}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-058264339990}
ENVIRONMENT=${ENVIRONMENT:-staging}
FEATURES=${FEATURES:-"cloud,payment"}

# ECR Repositories
ECR_BACKEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ENVIRONMENT-scribe-backend"
ECR_FRONTEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ENVIRONMENT-scribe-frontend"
ECR_QDRANT_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ENVIRONMENT-scribe-qdrant"

# ECS Cluster and Services
ECS_CLUSTER="$ENVIRONMENT-scribe-cluster"
BACKEND_SERVICE="$ENVIRONMENT-scribe-backend"
FRONTEND_SERVICE="$ENVIRONMENT-scribe-frontend"
QDRANT_SERVICE="$ENVIRONMENT-scribe-qdrant"

# Auto-detect container runtime (prefer podman)
if command -v podman &> /dev/null; then
    RUNTIME="podman"
    PUSH_OPTS="--compression-format gzip --remove-signatures"
else
    RUNTIME="docker"
    PUSH_OPTS=""
fi

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_prerequisites() {
    log_info "Checking prerequisites..."
    if ! command -v "$RUNTIME" &> /dev/null; then
        log_error "$RUNTIME is not installed."
        exit 1
    fi
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed."
        exit 1
    fi
    log_success "Prerequisites check passed (Runtime: $RUNTIME)"
}

ecr_login() {
    local registry="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
    log_info "Logging in to Amazon ECR: $registry..."
    $RUNTIME logout "$registry" 2>/dev/null || true
    aws ecr get-login-password --region $AWS_REGION | $RUNTIME login --username AWS --password-stdin "$registry"
}

deploy_backend() {
    log_info "Deploying Backend..."
    cd "$PROJECT_ROOT"

    local build_args=("-f" "infrastructure/containers/backend/Containerfile" "-t" "scribe-backend:latest" "-t" "$ECR_BACKEND_REPO:latest")
    if [ -n "$FEATURES" ]; then
        build_args+=("--build-arg" "FEATURES=$FEATURES")
    fi

    $RUNTIME build "${build_args[@]}" .

    log_info "Pushing backend image to ECR..."
    if [ "$RUNTIME" = "podman" ]; then
        $RUNTIME push $PUSH_OPTS --creds "AWS:$(aws ecr get-login-password --region $AWS_REGION)" $ECR_BACKEND_REPO:latest
    else
        ecr_login
        $RUNTIME push $ECR_BACKEND_REPO:latest
    fi

    aws ecs update-service --cluster $ECS_CLUSTER --service $BACKEND_SERVICE --force-new-deployment --region $AWS_REGION
    log_success "Backend deployment initiated"
}

deploy_frontend() {
    log_info "Deploying Frontend..."
    local build_args=("-f" "infrastructure/containers/frontend/Containerfile" "-t" "scribe-frontend:latest" "-t" "$ECR_FRONTEND_REPO:latest")

    $RUNTIME build "${build_args[@]}" .

    log_info "Pushing frontend image to ECR..."
    if [ "$RUNTIME" = "podman" ]; then
        $RUNTIME push $PUSH_OPTS --creds "AWS:$(aws ecr get-login-password --region $AWS_REGION)" $ECR_FRONTEND_REPO:latest
    else
        ecr_login
        $RUNTIME push $ECR_FRONTEND_REPO:latest
    fi

    aws ecs update-service --cluster $ECS_CLUSTER --service $FRONTEND_SERVICE --force-new-deployment --region $AWS_REGION
    log_success "Frontend deployment initiated"
}

deploy_qdrant() {
    log_info "Deploying Qdrant..."
    $RUNTIME pull docker.io/qdrant/qdrant:latest
    $RUNTIME tag docker.io/qdrant/qdrant:latest $ECR_QDRANT_REPO:latest

    log_info "Pushing Qdrant image to ECR..."
    if [ "$RUNTIME" = "podman" ]; then
        $RUNTIME push $PUSH_OPTS --creds "AWS:$(aws ecr get-login-password --region $AWS_REGION)" $ECR_QDRANT_REPO:latest
    else
        ecr_login
        $RUNTIME push $ECR_QDRANT_REPO:latest
    fi

    aws ecs update-service --cluster $ECS_CLUSTER --service $QDRANT_SERVICE --force-new-deployment --region $AWS_REGION
    log_success "Qdrant deployment initiated"
}

wait_for_stable() {
    local service=$1
    log_info "Waiting for $service to stabilize..."
    aws ecs wait services-stable --cluster $ECS_CLUSTER --services $service --region $AWS_REGION
    log_success "$service is stable"
}

usage() {
    echo "Usage: $0 [backend|frontend|qdrant|all] [options]"
    echo ""
    echo "Options:"
    echo "  --features FEATURES    Rust features for backend (default: cloud,payment)"
    echo "  --environment ENV      Target environment (default: staging)"
    echo "  --wait                 Wait for services to stabilize"
    echo ""
}

main() {
    TARGET="${1:-all}"
    shift || true

    WAIT_FOR_STABILITY=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --features) FEATURES="$2"; shift 2 ;;
            --environment) ENVIRONMENT="$2"; shift 2 ;;
            --wait) WAIT_FOR_STABILITY=true; shift ;;
            *) log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    check_prerequisites
    ecr_login

    case "$TARGET" in
        backend)
            deploy_backend
            if [ "$WAIT_FOR_STABILITY" = true ]; then wait_for_stable $BACKEND_SERVICE; fi
            ;;
        frontend)
            deploy_frontend
            if [ "$WAIT_FOR_STABILITY" = true ]; then wait_for_stable $FRONTEND_SERVICE; fi
            ;;
        qdrant)
            deploy_qdrant
            if [ "$WAIT_FOR_STABILITY" = true ]; then wait_for_stable $QDRANT_SERVICE; fi
            ;;
        all)
            deploy_backend
            deploy_frontend
            deploy_qdrant
            if [ "$WAIT_FOR_STABILITY" = true ]; then
                wait_for_stable $BACKEND_SERVICE
                wait_for_stable $FRONTEND_SERVICE
                wait_for_stable $QDRANT_SERVICE
            fi
            ;;
        *) usage; exit 1 ;;
    esac

    log_success "🚀 Cloud deployment task completed!"
}

main "$@"
