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
AWS_REGION=${AWS_REGION:-us-east-1}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-058264339990}
ECR_BACKEND_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/staging-scribe-backend"
ECR_QDRANT_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/staging-scribe-qdrant"
ECS_CLUSTER="staging-scribe-cluster"
BACKEND_SERVICE="staging-scribe-backend"
QDRANT_SERVICE="staging-scribe-qdrant"

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
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
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
    aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_BACKEND_REPO
    log_success "ECR login successful"
}

# Build backend image
build_backend() {
    log_info "Building backend Docker image..."
    cd "$BACKEND_DIR"
    
    # Build the image (with optional --no-cache flag)
    if [[ "${NO_CACHE:-false}" == "true" ]]; then
        log_info "Building with --no-cache option"
        docker build --no-cache -t scribe-backend:latest .
    else
        docker build -t scribe-backend:latest .
    fi
    
    # Tag for ECR
    docker tag scribe-backend:latest $ECR_BACKEND_REPO:latest
    
    log_success "Backend image built successfully"
}

# Push backend image
push_backend() {
    log_info "Pushing backend image to ECR..."
    docker push $ECR_BACKEND_REPO:latest
    log_success "Backend image pushed successfully"
}

# Deploy Qdrant
deploy_qdrant() {
    log_info "Deploying Qdrant image..."
    
    # Pull official Qdrant image
    docker pull qdrant/qdrant:latest
    
    # Tag for ECR
    docker tag qdrant/qdrant:latest $ECR_QDRANT_REPO:latest
    
    # Push to ECR
    docker push $ECR_QDRANT_REPO:latest
    
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
    
    # Check for --no-cache flag in remaining arguments
    for arg in "$@"; do
        if [[ "$arg" == "--no-cache" ]]; then
            export NO_CACHE=true
            log_info "No-cache build enabled"
            break
        fi
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
            echo "Usage: $0 [backend|qdrant|all] [--no-cache]"
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