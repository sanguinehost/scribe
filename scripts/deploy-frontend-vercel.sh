#!/bin/bash
set -euo pipefail

# Deploy frontend to Vercel with payment features
# This script builds and deploys the SvelteKit frontend with payment support

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration with environment variable overrides
ENVIRONMENT=${ENVIRONMENT:-staging}
ENABLE_PAYMENTS=${ENABLE_PAYMENTS:-true}
VERCEL_ORG=${VERCEL_ORG:-sanguinehost}
VERCEL_PROJECT=${VERCEL_PROJECT:-sanguine-scribe-frontend}

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
    echo "  --environment ENV     Environment (staging|production, default: staging)"
    echo "  --enable-payments     Enable payment features (default: true)"
    echo "  --disable-payments    Disable payment features"
    echo "  --preview             Deploy as preview build"
    echo "  --production          Deploy to production (requires --environment production)"
    echo "  --org ORG             Vercel organization (default: sanguinehost)"
    echo "  --project PROJECT     Vercel project name"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  ENVIRONMENT           Override environment"
    echo "  ENABLE_PAYMENTS       Override payment feature flag"
    echo "  VERCEL_ORG            Override Vercel organization"
    echo "  VERCEL_PROJECT        Override Vercel project name"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Deploy staging with payments"
    echo "  $0 --disable-payments                # Deploy without payments"
    echo "  $0 --environment production --production  # Deploy to production"
    exit 1
}

# Parse command line arguments
DEPLOY_TYPE="preview"
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --enable-payments)
            ENABLE_PAYMENTS=true
            shift
            ;;
        --disable-payments)
            ENABLE_PAYMENTS=false
            shift
            ;;
        --preview)
            DEPLOY_TYPE="preview"
            shift
            ;;
        --production)
            DEPLOY_TYPE="production"
            shift
            ;;
        --org)
            VERCEL_ORG="$2"
            shift 2
            ;;
        --project)
            VERCEL_PROJECT="$2"
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v pnpm &> /dev/null; then
        log_error "PNPM is not installed. Please install PNPM first."
        exit 1
    fi
    
    if ! command -v vercel &> /dev/null; then
        log_error "Vercel CLI is not installed. Please install with: pnpm install -g vercel"
        exit 1
    fi
    
    # Check Vercel authentication
    if ! vercel whoami &> /dev/null; then
        log_error "Not logged in to Vercel. Please run 'vercel login' first."
        exit 1
    fi
    
    # Validate directory
    if [ ! -d "$FRONTEND_DIR" ]; then
        log_error "Frontend directory not found at $FRONTEND_DIR"
        exit 1
    fi
    
    if [ ! -f "$FRONTEND_DIR/package.json" ]; then
        log_error "package.json not found in frontend directory"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Set environment variables for the build
setup_environment() {
    log_info "Setting up build environment..."
    
    # Export environment variables for the build process
    export PUBLIC_ENABLE_PAYMENTS="$ENABLE_PAYMENTS"
    export VITE_BUILD_SKIP_TYPE_CHECK="true"
    
    log_info "Build configuration:"
    log_info "  Environment: $ENVIRONMENT"
    log_info "  Payment features: $ENABLE_PAYMENTS"
    log_info "  Deploy type: $DEPLOY_TYPE"
    log_info "  Vercel org: $VERCEL_ORG"
    log_info "  Vercel project: ${VERCEL_PROJECT:-'auto-detected'}"
    
    log_success "Environment setup complete"
}

# Install dependencies
install_dependencies() {
    log_info "Installing frontend dependencies..."
    cd "$FRONTEND_DIR"
    
    if ! pnpm install; then
        log_error "Failed to install dependencies"
        exit 1
    fi
    
    log_success "Dependencies installed"
}

# Build the frontend
build_frontend() {
    log_info "Building frontend..."
    cd "$FRONTEND_DIR"
    
    # Set build environment variables
    export PUBLIC_ENABLE_PAYMENTS="$ENABLE_PAYMENTS"
    export VITE_BUILD_SKIP_TYPE_CHECK="true"
    
    if ! pnpm build; then
        log_error "Frontend build failed"
        exit 1
    fi
    
    log_success "Frontend build completed"
}

# Deploy to Vercel
deploy_to_vercel() {
    log_info "Deploying to Vercel..."
    cd "$FRONTEND_DIR"
    
    # Prepare Vercel command
    VERCEL_CMD="vercel"
    
    # Add deployment type
    if [ "$DEPLOY_TYPE" = "production" ]; then
        VERCEL_CMD="$VERCEL_CMD --prod"
        log_info "Deploying to production"
    else
        log_info "Deploying as preview"
    fi
    
    # Add organization if specified
    if [ -n "$VERCEL_ORG" ]; then
        VERCEL_CMD="$VERCEL_CMD --scope $VERCEL_ORG"
    fi
    
    # Set environment variables for Vercel
    VERCEL_CMD="$VERCEL_CMD --env PUBLIC_ENABLE_PAYMENTS=$ENABLE_PAYMENTS"
    
    # Use prebuilt if build directory exists
    if [ -d "build" ]; then
        VERCEL_CMD="$VERCEL_CMD --prebuilt"
        log_info "Using prebuilt deployment"
    fi
    
    # Execute deployment
    log_info "Vercel command: $VERCEL_CMD"
    if eval "$VERCEL_CMD"; then
        log_success "Vercel deployment completed"
    else
        log_error "Vercel deployment failed"
        exit 1
    fi
}

# Check deployment health
check_deployment_health() {
    log_info "Deployment health check..."
    
    # Get deployment URL from Vercel
    local DEPLOYMENT_URL=""
    if [ "$ENVIRONMENT" = "production" ]; then
        case "$ENVIRONMENT" in
            "staging")
                DEPLOYMENT_URL="https://staging.scribe.sanguinehost.com"
                ;;
            "production")
                DEPLOYMENT_URL="https://scribe.sanguinehost.com"
                ;;
            *)
                log_warning "Unknown environment, skipping health check"
                return 0
                ;;
        esac
    fi
    
    if [ -n "$DEPLOYMENT_URL" ]; then
        log_info "Checking deployment at: $DEPLOYMENT_URL"
        sleep 5  # Give deployment a moment to propagate
        
        # Basic health check
        if curl -f -s "$DEPLOYMENT_URL" > /dev/null; then
            log_success "Deployment is healthy"
        else
            log_warning "Deployment health check failed - this may be normal for preview deployments"
        fi
    fi
}

# Main execution
main() {
    log_info "Starting frontend deployment..."
    
    check_prerequisites
    setup_environment
    install_dependencies
    build_frontend
    deploy_to_vercel
    check_deployment_health
    
    log_success "🚀 Frontend deployment completed successfully!"
    log_info "Next steps:"
    
    if [ "$DEPLOY_TYPE" = "production" ]; then
        echo "1. Test the application at: https://${ENVIRONMENT}.scribe.sanguinehost.com"
        echo "2. Verify payment features are working correctly"
        echo "3. Check Vercel dashboard for deployment logs"
    else
        echo "1. Check the preview URL provided by Vercel above"
        echo "2. Test payment features in the preview environment"
        echo "3. If satisfied, deploy to production with --production flag"
    fi
}

# Run main with all arguments
main "$@"