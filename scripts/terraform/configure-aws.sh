#!/bin/bash
set -euo pipefail

# Configure AWS CLI for Scribe deployment
# This script helps set up AWS credentials and region for the deployment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed."
        log_info "Please install AWS CLI first:"
        echo "  macOS: brew install awscli"
        echo "  Linux: sudo apt-get install awscli"
        echo "  Or download from: https://aws.amazon.com/cli/"
        exit 1
    fi
    log_success "AWS CLI is installed"
}

# Check current AWS configuration
check_current_config() {
    log_info "Checking current AWS configuration..."
    
    if aws sts get-caller-identity &> /dev/null; then
        log_info "Current AWS configuration:"
        aws sts get-caller-identity --output table
        
        CURRENT_REGION=$(aws configure get region 2>/dev/null || echo "Not set")
        echo "Current region: $CURRENT_REGION"
        
        echo
        read -p "Do you want to use the current configuration? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            configure_aws
        else
            log_success "Using current AWS configuration"
            verify_permissions
        fi
    else
        log_warning "AWS credentials not configured or invalid"
        configure_aws
    fi
}

# Configure AWS credentials
configure_aws() {
    log_info "Configuring AWS credentials..."
    
    echo
    log_info "You'll need:"
    echo "1. AWS Access Key ID"
    echo "2. AWS Secret Access Key"
    echo "3. Default region (recommended: us-east-1)"
    echo "4. Default output format (recommended: json)"
    echo
    
    log_warning "Make sure your AWS user has the following permissions:"
    echo "- EC2 (for VPC, security groups, load balancers)"
    echo "- ECS (for container services)"
    echo "- RDS (for PostgreSQL database)"
    echo "- ElastiCache (for Redis)"
    echo "- Route 53 (for DNS management)"
    echo "- Certificate Manager (for SSL certificates)"
    echo "- Secrets Manager (for credential storage)"
    echo "- CloudWatch (for monitoring)"
    echo "- IAM (for role and policy management)"
    echo
    
    read -p "Press Enter to continue with AWS configuration..."
    aws configure
    
    verify_permissions
}

# Verify AWS permissions
verify_permissions() {
    log_info "Verifying AWS permissions..."
    
    # Test basic permissions
    if aws sts get-caller-identity &> /dev/null; then
        log_success "✓ Basic AWS access works"
    else
        log_error "✗ Cannot access AWS with current credentials"
        exit 1
    fi
    
    # Test EC2 permissions
    if aws ec2 describe-regions --region us-east-1 &> /dev/null; then
        log_success "✓ EC2 permissions verified"
    else
        log_warning "⚠ EC2 permissions may be insufficient"
    fi
    
    # Test ECS permissions
    if aws ecs list-clusters --region us-east-1 &> /dev/null; then
        log_success "✓ ECS permissions verified"
    else
        log_warning "⚠ ECS permissions may be insufficient"
    fi
    
    # Test RDS permissions
    if aws rds describe-db-instances --region us-east-1 &> /dev/null; then
        log_success "✓ RDS permissions verified"
    else
        log_warning "⚠ RDS permissions may be insufficient"
    fi
    
    # Test Secrets Manager permissions
    if aws secretsmanager list-secrets --region us-east-1 &> /dev/null; then
        log_success "✓ Secrets Manager permissions verified"
    else
        log_warning "⚠ Secrets Manager permissions may be insufficient"
    fi
    
    log_info "Permission verification completed"
}

# Show recommended IAM policy
show_iam_policy() {
    log_info "Recommended IAM policy for Terraform deployment:"
    
    cat << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "ecs:*",
                "rds:*",
                "elasticache:*",
                "elasticloadbalancing:*",
                "route53:*",
                "acm:*",
                "secretsmanager:*",
                "cloudwatch:*",
                "logs:*",
                "iam:*",
                "ecr:*",
                "application-autoscaling:*",
                "servicediscovery:*",
                "wafv2:*",
                "cloudtrail:*",
                "sns:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF
    
    echo
    log_warning "Note: This is a broad policy for development. For production, use more restrictive permissions."
}

# Main function
main() {
    log_info "AWS CLI Configuration for Scribe Deployment"
    echo "=============================================="
    
    check_aws_cli
    check_current_config
    
    echo
    log_success "AWS CLI configuration completed!"
    log_info "You can now proceed with Terraform deployment using:"
    echo "  ./scripts/terraform/deploy-staging.sh"
    echo
    log_info "Current AWS identity:"
    aws sts get-caller-identity --output table
}

# Handle script arguments
case "${1:-configure}" in
    "configure")
        main
        ;;
    "verify")
        check_aws_cli
        verify_permissions
        ;;
    "policy")
        show_iam_policy
        ;;
    "check")
        check_aws_cli
        if aws sts get-caller-identity &> /dev/null; then
            log_success "AWS CLI is configured and working"
            aws sts get-caller-identity --output table
        else
            log_error "AWS CLI is not properly configured"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [configure|verify|policy|check]"
        echo "  configure - Configure AWS CLI (default)"
        echo "  verify    - Verify AWS permissions"
        echo "  policy    - Show recommended IAM policy"
        echo "  check     - Check current AWS configuration"
        exit 1
        ;;
esac