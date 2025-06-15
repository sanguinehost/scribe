#!/bin/bash
set -euo pipefail

# Apply Terraform changes to add COOKIE_DOMAIN environment variable
# This fixes cross-subdomain cookie sharing for staging environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TERRAFORM_DIR="$PROJECT_ROOT/terraform/environments/staging"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[INFO]${NC} Applying Terraform changes to add COOKIE_DOMAIN for staging..."

cd "$TERRAFORM_DIR"

# Initialize Terraform if needed
echo -e "${BLUE}[INFO]${NC} Initializing Terraform..."
terraform init

# Plan the changes
echo -e "${BLUE}[INFO]${NC} Planning Terraform changes..."
terraform plan -out=tfplan

# Show what will change
echo -e "${YELLOW}[WARNING]${NC} The following changes will be applied:"
terraform show tfplan | grep -A5 -B5 "COOKIE_DOMAIN" || true

# Ask for confirmation
read -p "Do you want to apply these changes? (yes/no): " confirm
if [[ "$confirm" != "yes" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} Terraform apply cancelled"
    exit 0
fi

# Apply the changes
echo -e "${BLUE}[INFO]${NC} Applying Terraform changes..."
terraform apply tfplan

echo -e "${GREEN}[SUCCESS]${NC} Terraform changes applied successfully!"
echo -e "${BLUE}[INFO]${NC} The ECS service will automatically redeploy with the new environment variable."
echo -e "${BLUE}[INFO]${NC} Monitor the deployment with: aws ecs describe-services --cluster staging-scribe-cluster --services staging-scribe-backend --region us-east-1"