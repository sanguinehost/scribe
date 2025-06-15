#!/bin/bash
set -euo pipefail

# Script to completely delete and recreate the RDS instance
# This will DESTROY ALL DATA but fix any database issues

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Configuration
AWS_REGION="us-east-1"
DB_INSTANCE_ID="staging-scribe-postgres"

main() {
    log_error "⚠️  THIS WILL COMPLETELY DESTROY THE DATABASE AND ALL DATA ⚠️"
    echo
    log_warning "This script will:"
    echo "  1. Delete the RDS instance: $DB_INSTANCE_ID"
    echo "  2. Wait for deletion to complete"
    echo "  3. Run terraform apply to recreate it"
    echo
    log_error "ALL DATA WILL BE PERMANENTLY LOST!"
    echo
    
    read -p "Type 'NUKE' to confirm complete database destruction: " confirm
    if [ "$confirm" != "NUKE" ]; then
        echo "Cancelled."
        exit 0
    fi
    
    echo
    log_warning "Deleting RDS instance..."
    
    # Delete the RDS instance without final snapshot (faster)
    aws rds delete-db-instance \
        --db-instance-identifier "$DB_INSTANCE_ID" \
        --skip-final-snapshot \
        --region "$AWS_REGION" || {
        log_error "Failed to delete RDS instance. It might not exist."
    }
    
    log_warning "Waiting for RDS instance to be deleted..."
    log_warning "This can take 5-10 minutes..."
    
    # Wait for deletion to complete
    aws rds wait db-instance-deleted \
        --db-instance-identifier "$DB_INSTANCE_ID" \
        --region "$AWS_REGION" || {
        log_warning "Wait command failed, but continuing..."
    }
    
    log_success "RDS instance deleted!"
    
    # Change to terraform directory and recreate
    cd terraform/environments/staging
    
    log_warning "Running terraform apply to recreate database..."
    terraform apply -auto-approve
    
    if [ $? -eq 0 ]; then
        log_success "Database recreated successfully!"
        log_success "You can now register with any credentials."
    else
        log_error "Terraform apply failed. Check the output above."
        exit 1
    fi
}

main "$@"