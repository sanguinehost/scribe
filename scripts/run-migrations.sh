#!/bin/bash
set -euo pipefail

# Run database migrations for Scribe staging environment
# This script connects to the staging RDS instance and runs Diesel migrations

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
SECRET_ID="staging/scribe/database"

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
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    if ! command -v diesel &> /dev/null; then
        log_error "Diesel CLI is not installed. Please install with: cargo install diesel_cli --features postgres"
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials are not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Get database URL from AWS Secrets Manager
get_database_url() {
    log_info "Retrieving database credentials from AWS Secrets Manager..."
    
    local secret_value
    secret_value=$(aws secretsmanager get-secret-value \
        --secret-id "$SECRET_ID" \
        --region "$AWS_REGION" \
        --query 'SecretString' \
        --output text 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        log_error "Failed to retrieve database credentials from Secrets Manager"
        log_info "Make sure the secret '$SECRET_ID' exists and you have permission to access it"
        exit 1
    fi
    
    # Extract the database URL from the JSON
    DATABASE_URL=$(echo "$secret_value" | jq -r '.url')
    
    if [ "$DATABASE_URL" = "null" ] || [ -z "$DATABASE_URL" ]; then
        log_error "Database URL not found in secret"
        exit 1
    fi
    
    log_success "Database credentials retrieved"
}

# Run migrations
run_migrations() {
    log_info "Running database migrations..."
    
    cd "$BACKEND_DIR"
    
    # Export the database URL for Diesel
    export DATABASE_URL
    
    # Run migrations
    diesel migration run
    
    if [ $? -eq 0 ]; then
        log_success "Database migrations completed successfully"
    else
        log_error "Database migrations failed"
        exit 1
    fi
}

# Show migration status
show_migration_status() {
    log_info "Checking migration status..."
    
    cd "$BACKEND_DIR"
    export DATABASE_URL
    
    # List applied migrations
    diesel migration list
}

# Main execution
main() {
    case "${1:-run}" in
        "run")
            log_info "Running database migrations for staging environment..."
            check_prerequisites
            get_database_url
            run_migrations
            log_success "🎉 Migrations completed successfully!"
            ;;
        "status")
            log_info "Checking migration status..."
            check_prerequisites
            get_database_url
            show_migration_status
            ;;
        "help")
            echo "Usage: $0 [run|status|help]"
            echo "  run    - Run pending migrations (default)"
            echo "  status - Show migration status"
            echo "  help   - Show this help message"
            ;;
        *)
            echo "Usage: $0 [run|status|help]"
            exit 1
            ;;
    esac
}

# Run main with all arguments
main "$@"