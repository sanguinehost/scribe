#!/bin/bash
set -euo pipefail

# Deploy backend to AWS ECS using Podman
# This script builds, pushes, and deploys the backend container image

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
CONTAINERFILE="$PROJECT_ROOT/infrastructure/containers/backend/Containerfile"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration with environment variable overrides
CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-podman}
AWS_REGION=${AWS_REGION:-us-east-1}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "UNKNOWN")}
ENVIRONMENT=${ENVIRONMENT:-staging}
ECR_BACKEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ENVIRONMENT-scribe-backend"
ECR_QDRANT_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ENVIRONMENT-scribe-qdrant"
ECS_CLUSTER="$ENVIRONMENT-scribe-cluster"
BACKEND_SERVICE="$ENVIRONMENT-scribe-backend"
QDRANT_SERVICE="$ENVIRONMENT-scribe-qdrant"
NO_CACHE=${NO_CACHE:-false}

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

# Print usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --runtime RUNTIME     Container runtime (podman|docker, default: podman)"
    echo "  --environment ENV     Environment (staging|production, default: staging)"
    echo "  --region REGION       AWS region (default: us-east-1)"
    echo "  --account-id ID       AWS account ID (auto-detected if not provided)"
    echo "  --no-cache            Build without cache"
    echo "  --backend-only        Deploy only the backend service"
    echo "  --qdrant-only         Deploy only the Qdrant service"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CONTAINER_RUNTIME     Override default runtime"
    echo "  AWS_REGION            Override default region"
    echo "  AWS_ACCOUNT_ID        Override AWS account ID"
    echo "  ENVIRONMENT           Override environment"
    echo "  NO_CACHE              Set to true to disable cache"
    exit 1
}

# Parse command line arguments
BACKEND_ONLY=false
QDRANT_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --runtime)
            CONTAINER_RUNTIME="$2"
            shift 2
            ;;
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --region)
            AWS_REGION="$2"
            shift 2
            ;;
        --account-id)
            AWS_ACCOUNT_ID="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --backend-only)
            BACKEND_ONLY=true
            shift
            ;;
        --qdrant-only)
            QDRANT_ONLY=true
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

# Validate runtime
if ! command -v "$CONTAINER_RUNTIME" &> /dev/null; then
    log_error "Runtime '$CONTAINER_RUNTIME' not found. Please install it first."
    exit 1
fi

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    if [ "$AWS_ACCOUNT_ID" = "UNKNOWN" ]; then
        log_error "Could not determine AWS account ID. Please set AWS_ACCOUNT_ID environment variable."
        exit 1
    fi
    
    # Validate paths
    if [ ! -f "$CONTAINERFILE" ]; then
        log_error "Containerfile not found at $CONTAINERFILE"
        exit 1
    fi
    
    if [ ! -d "$BACKEND_DIR" ]; then
        log_error "Backend directory not found at $BACKEND_DIR"
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

# Build backend image
build_backend() {
    log_info "Building backend container image..."
    cd "$PROJECT_ROOT"
    
    BUILD_CMD="$CONTAINER_RUNTIME build"
    BUILD_CMD="$BUILD_CMD --format docker"  # Ensure Docker format for ECR compatibility
    BUILD_CMD="$BUILD_CMD -f $CONTAINERFILE"
    BUILD_CMD="$BUILD_CMD -t scribe-backend:latest"
    BUILD_CMD="$BUILD_CMD -t $ECR_BACKEND_REPO:latest"
    
    if [ "$NO_CACHE" = true ]; then
        BUILD_CMD="$BUILD_CMD --no-cache"
        log_info "Building with --no-cache option"
    fi
    
    BUILD_CMD="$BUILD_CMD $BACKEND_DIR"
    
    log_info "Build command: $BUILD_CMD"
    if eval "$BUILD_CMD"; then
        log_success "Backend image built successfully"
    else
        log_error "Backend build failed"
        exit 1
    fi
}

# Push backend image to ECR
push_backend() {
    log_info "Pushing backend image to ECR..."
    if $CONTAINER_RUNTIME push $ECR_BACKEND_REPO:latest; then
        log_success "Backend image pushed successfully"
    else
        log_error "Backend push failed"
        exit 1
    fi
}

# Build and push Qdrant image
build_push_qdrant() {
    log_info "Pulling and pushing Qdrant image..."
    
    # Pull official Qdrant image
    $CONTAINER_RUNTIME pull docker.io/qdrant/qdrant:v1.14.0
    
    # Tag for ECR
    $CONTAINER_RUNTIME tag docker.io/qdrant/qdrant:v1.14.0 $ECR_QDRANT_REPO:latest
    
    # Push to ECR
    $CONTAINER_RUNTIME push $ECR_QDRANT_REPO:latest
    
    log_success "Qdrant image pushed successfully"
}

# Deploy service to ECS
deploy_service() {
    local service_name=$1
    log_info "Deploying $service_name to ECS..."
    
    aws ecs update-service \
        --cluster $ECS_CLUSTER \
        --service $service_name \
        --force-new-deployment \
        --region $AWS_REGION
    
    log_success "$service_name deployment initiated"
    
    # Wait for deployment to complete
    log_info "Waiting for $service_name deployment to complete..."
    aws ecs wait services-stable \
        --cluster $ECS_CLUSTER \
        --services $service_name \
        --region $AWS_REGION
    
    log_success "$service_name deployment completed"
}

# Main execution
main() {
    log_info "Starting deployment process..."
    log_info "Configuration:"
    log_info "  Runtime: $CONTAINER_RUNTIME"
    log_info "  Environment: $ENVIRONMENT"
    log_info "  AWS Region: $AWS_REGION"
    log_info "  AWS Account ID: $AWS_ACCOUNT_ID"
    log_info "  Backend only: $BACKEND_ONLY"
    log_info "  Qdrant only: $QDRANT_ONLY"
    
    check_prerequisites
    ecr_login
    
    if [ "$QDRANT_ONLY" != true ]; then
        build_backend
        push_backend
        deploy_service $BACKEND_SERVICE
    fi
    
    if [ "$BACKEND_ONLY" != true ]; then
        build_push_qdrant
        deploy_service $QDRANT_SERVICE
    fi
    
    log_success "Deployment process completed successfully!"
    log_info "Check the ECS console for service status: https://console.aws.amazon.com/ecs/home?region=$AWS_REGION#/clusters/$ECS_CLUSTER/services"
}

# Run main function
main "$@"