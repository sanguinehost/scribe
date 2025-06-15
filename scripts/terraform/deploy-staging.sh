#!/bin/bash
set -euo pipefail

# Deploy Scribe staging environment to AWS
# This script handles the complete deployment of the staging environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TERRAFORM_DIR="$PROJECT_ROOT/terraform/environments/staging"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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
    
    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed. Please install Terraform first."
        exit 1
    fi
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials are not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    # Check if terraform.tfvars exists
    if [ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]; then
        log_error "terraform.tfvars not found in $TERRAFORM_DIR"
        log_info "Please copy terraform.tfvars.example to terraform.tfvars and customize the values."
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Initialize Terraform
init_terraform() {
    log_info "Initializing Terraform..."
    cd "$TERRAFORM_DIR"
    terraform init
    log_success "Terraform initialized"
}

# Plan deployment
plan_deployment() {
    log_info "Planning deployment..."
    cd "$TERRAFORM_DIR"
    terraform plan -out=staging.tfplan
    
    echo
    log_warning "Please review the plan above before proceeding."
    read -p "Do you want to continue with the deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deployment cancelled by user."
        exit 0
    fi
}

# Apply deployment
apply_deployment() {
    log_info "Applying deployment..."
    cd "$TERRAFORM_DIR"
    terraform apply staging.tfplan
    log_success "Deployment completed successfully"
}

# Show outputs
show_outputs() {
    log_info "Deployment outputs:"
    cd "$TERRAFORM_DIR"
    terraform output
    
    echo
    log_info "Getting additional information..."
    
    # Get ALB DNS name for DNS configuration
    ALB_DNS=$(terraform output -raw alb_dns_name 2>/dev/null || echo "Not available")
    ALB_ZONE_ID=$(terraform output -raw alb_zone_id 2>/dev/null || echo "Not available")
    DOMAIN_NAME=$(terraform output -raw api_endpoint 2>/dev/null | sed 's|https://||' || echo "Not available")
    
    echo
    log_info "DNS Configuration Required:"
    echo "1. Create a CNAME record in Route 53 for $DOMAIN_NAME pointing to $ALB_DNS"
    echo "   Or create an ALIAS record with zone ID: $ALB_ZONE_ID"
    echo
    echo "2. SSL Certificate validation:"
    echo "   Check the SSL certificate validation DNS records and add them to Route 53."
    echo "   You can find these in the AWS Console under Certificate Manager."
    echo
    log_info "ECR Repository URLs (for CI/CD):"
    terraform output -raw backend_ecr_repository_url 2>/dev/null || echo "Backend ECR: Not available"
    echo
    
    log_success "Deployment information displayed above"
}

# Main execution
main() {
    log_info "Starting Scribe staging deployment..."
    
    check_prerequisites
    init_terraform
    plan_deployment
    apply_deployment
    show_outputs
    
    echo
    log_success "🎉 Staging environment deployed successfully!"
    log_info "Next steps:"
    echo "1. DNS records are auto-configured if using Route 53 for sanguinehost.com"
    echo "2. Build and deploy backend: ./scripts/deploy-backend.sh"
    echo "3. Run database migrations: ./scripts/run-migrations.sh"  
    echo "4. Deploy frontend: cd frontend && pnpm build && pnpm vercel deploy --prebuilt --prod"
    echo "5. Test the complete application at: https://staging.scribe.sanguinehost.com"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "plan")
        check_prerequisites
        init_terraform
        plan_deployment
        ;;
    "destroy")
        log_warning "This will destroy the entire staging environment!"
        read -p "Are you sure you want to destroy the staging environment? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cd "$TERRAFORM_DIR"
            terraform destroy
            log_success "Staging environment destroyed"
        else
            log_info "Destroy cancelled by user"
        fi
        ;;
    "output")
        cd "$TERRAFORM_DIR"
        terraform output
        ;;
    *)
        echo "Usage: $0 [deploy|plan|destroy|output]"
        echo "  deploy  - Deploy the staging environment (default)"
        echo "  plan    - Plan the deployment without applying"
        echo "  destroy - Destroy the staging environment"
        echo "  output  - Show terraform outputs"
        exit 1
        ;;
esac