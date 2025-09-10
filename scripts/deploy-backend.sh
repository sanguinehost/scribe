#!/bin/bash
set -euo pipefail

# Deploy backend to AWS ECS
# This script builds, pushes, and deploys the backend Docker image

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION=${AWS_REGION:-ap-southeast-4}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-058264339990}
ECR_BACKEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/staging-scribe-backend"
ECR_QDRANT_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/staging-scribe-qdrant"
ECS_CLUSTER="staging-scribe-cluster"
BACKEND_SERVICE="staging-scribe-backend"
QDRANT_SERVICE="staging-scribe-qdrant"
FEATURES=${FEATURES:-""}

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

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    log_info "Detected container runtime: $RUNTIME"
    
    if ! command -v "$RUNTIME" &> /dev/null; then
        log_error "$RUNTIME is not installed. Please install $RUNTIME first."
        log_info "Podman: https://podman.io/getting-started/installation"
        log_info "Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Login to ECR
ecr_login() {
    log_info "Logging in to Amazon ECR..."
    aws ecr get-login-password --region $AWS_REGION | $RUNTIME login --username AWS --password-stdin $ECR_BACKEND_REPO
    log_success "ECR login successful"
}

# Build backend image
build_backend() {
    log_info "Building backend image with $RUNTIME..."
    cd "$PROJECT_ROOT"  # Build from project root, not backend dir
    
    # Prepare build command
    BUILD_CMD="$RUNTIME build -f infrastructure/containers/backend/Containerfile"
    
    # Add features if specified
    if [ -n "$FEATURES" ]; then
        BUILD_CMD="$BUILD_CMD --build-arg FEATURES='$FEATURES'"
        log_info "Building with features: $FEATURES"
    fi
    
    # Add no-cache flag if requested
    if [[ "${NO_CACHE:-false}" == "true" ]]; then
        BUILD_CMD="$BUILD_CMD --no-cache"
        log_info "Building with --no-cache option"
    fi
    
    # Add tags and build context
    BUILD_CMD="$BUILD_CMD -t scribe-backend:latest -t $ECR_BACKEND_REPO:latest ."
    
    # Execute build
    log_info "Build command: $BUILD_CMD"
    if eval "$BUILD_CMD"; then
        log_success "Backend image built successfully"
    else
        log_error "Backend build failed"
        exit 1
    fi
}

# Push backend image
push_backend() {
    log_info "Pushing backend image to ECR..."
    $RUNTIME push $ECR_BACKEND_REPO:latest
    log_success "Backend image pushed successfully"
}

# Deploy Qdrant
deploy_qdrant() {
    log_info "Deploying Qdrant image..."
    
    # Pull official Qdrant image
    $RUNTIME pull qdrant/qdrant:latest
    
    # Tag for ECR
    $RUNTIME tag qdrant/qdrant:latest $ECR_QDRANT_REPO:latest
    
    # Push to ECR
    $RUNTIME push $ECR_QDRANT_REPO:latest
    
    log_success "Qdrant image deployed"
}

# Update ECS services
update_ecs_services() {
    log_info "Updating ECS services..."
    
    # Force new deployment for backend
    log_info "Updating backend service..."
    aws ecs update-service \
        --cluster $ECS_CLUSTER \
        --service $BACKEND_SERVICE \
        --force-new-deployment \
        --region $AWS_REGION
    
    # Force new deployment for Qdrant
    log_info "Updating Qdrant service..."
    aws ecs update-service \
        --cluster $ECS_CLUSTER \
        --service $QDRANT_SERVICE \
        --force-new-deployment \
        --region $AWS_REGION
    
    log_success "ECS services updated"
}

# Wait for services to stabilize
wait_for_services() {
    log_info "Waiting for services to stabilize..."
    
    # Wait for backend service
    log_info "Waiting for backend service..."
    aws ecs wait services-stable \
        --cluster $ECS_CLUSTER \
        --services $BACKEND_SERVICE \
        --region $AWS_REGION
    
    # Wait for Qdrant service
    log_info "Waiting for Qdrant service..."
    aws ecs wait services-stable \
        --cluster $ECS_CLUSTER \
        --services $QDRANT_SERVICE \
        --region $AWS_REGION
    
    log_success "All services are stable"
}

# Check service health
check_service_health() {
    log_info "Checking service health..."
    
    # Get service details
    aws ecs describe-services \
        --cluster $ECS_CLUSTER \
        --services $BACKEND_SERVICE $QDRANT_SERVICE \
        --region $AWS_REGION \
        --query 'services[*].[serviceName,runningCount,desiredCount,status]' \
        --output table
    
    log_success "Service health check complete"
}

# Main execution
main() {
    log_info "Starting backend deployment..."
    
    # Parse arguments
    TARGET="${1:-all}"
    
    # Parse all arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-cache)
                export NO_CACHE=true
                log_info "No-cache build enabled"
                shift
                ;;
            --features)
                export FEATURES="$2"
                log_info "Features enabled: $FEATURES"
                shift 2
                ;;
            backend|qdrant|all)
                TARGET="$1"
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    
    check_prerequisites
    ecr_login
    
    case "$TARGET" in
        "backend")
            build_backend
            push_backend
            aws ecs update-service --cluster $ECS_CLUSTER --service $BACKEND_SERVICE --force-new-deployment --region $AWS_REGION
            ;;
        "qdrant")
            deploy_qdrant
            aws ecs update-service --cluster $ECS_CLUSTER --service $QDRANT_SERVICE --force-new-deployment --region $AWS_REGION
            ;;
        "all")
            build_backend
            push_backend
            deploy_qdrant
            update_ecs_services
            wait_for_services
            check_service_health
            ;;
        *)
            echo "Usage: $0 [backend|qdrant|all] [--no-cache] [--features FEATURES]"
            echo ""
            echo "Arguments:"
            echo "  backend           Deploy only backend service"
            echo "  qdrant            Deploy only Qdrant service"  
            echo "  all               Deploy both services (default)"
            echo ""
            echo "Options:"
            echo "  --no-cache        Build without cache"
            echo "  --features FEATURES   Enable Rust features (e.g., 'payment')"
            echo ""
            echo "Examples:"
            echo "  $0                        # Deploy all services"
            echo "  $0 backend --features payment  # Deploy backend with payment features"
            echo "  $0 --no-cache --features payment  # Full deployment with payment, no cache"
            exit 1
            ;;
    esac
    
    log_success "🚀 Deployment completed successfully!"
    log_info "Next steps:"
    echo "1. Run database migrations if needed: ./scripts/run-migrations.sh"
    echo "2. Test the API endpoint: curl https://staging.scribe.sanguinehost.com/api/health"
    echo "3. Deploy frontend to Vercel: cd frontend && pnpm build && pnpm vercel deploy --prebuilt --prod"
}

# Run main with all arguments
main "$@"