#!/bin/bash
set -euo pipefail

# Certificate Initialization Script for Sanguine Scribe
# Handles certificate setup for different deployment environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERTS_DIR="$PROJECT_ROOT/.certs"

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

show_usage() {
    cat << EOF
Certificate Initialization Script for Sanguine Scribe

USAGE:
    $0 <environment> [action]

ENVIRONMENTS:
    local       - Local development with cargo backend
    container   - Containerized local development  
    staging     - AWS ECS staging environment
    production  - AWS ECS production environment

ACTIONS:
    init        - Initialize certificates (default)
    check       - Check certificate status
    clean       - Clean existing certificates
    help        - Show this help message

EXAMPLES:
    $0 local init          # Setup certificates for local development
    $0 container check     # Check container certificate status
    $0 staging clean       # Clean staging certificates from AWS

EOF
}

detect_environment() {
    if [[ -n "${ENVIRONMENT:-}" ]]; then
        echo "$ENVIRONMENT"
    elif [[ -n "${AWS_EXECUTION_ENV:-}" ]]; then
        echo "aws"
    elif [[ -n "${CONTAINER:-}" ]] || [[ -f /.dockerenv ]]; then
        echo "container"
    else
        echo "local"
    fi
}

init_local_certs() {
    log_info "Initializing certificates for local development..."
    
    # Check if mkcert is available
    if ! command -v mkcert &> /dev/null; then
        log_error "mkcert is not installed. Please install it first:"
        log_info "  macOS: brew install mkcert"
        log_info "  Linux: See https://github.com/FiloSottile/mkcert#installation"
        exit 1
    fi
    
    # Use the certificate generation script
    if [[ -f "$SCRIPT_DIR/generate.sh" ]]; then
        log_info "Using certificate generation script..."
        "$SCRIPT_DIR/generate.sh" generate
    else
        log_error "Certificate generation script not found!"
        exit 1
    fi
    
    # Ensure certificates have correct permissions for local development
    if [[ -d "$CERTS_DIR" ]]; then
        chmod 755 "$CERTS_DIR"
        chmod 644 "$CERTS_DIR/cert.pem" 2>/dev/null || true
        chmod 600 "$CERTS_DIR/key.pem" 2>/dev/null || true
        
        log_success "Local certificates initialized with correct permissions"
        log_info "Certificates location: $CERTS_DIR"
    else
        log_error "Certificate directory not created!"
        exit 1
    fi
}

init_container_certs() {
    log_info "Initializing certificates for container development..."
    
    # For container development, we need certificates accessible by containers
    if [[ ! -d "$CERTS_DIR" ]]; then
        log_info "No local certificates found, generating them first..."
        init_local_certs
    fi
    
    # Create service-specific certificate directories
    POSTGRES_CERTS_DIR="$PROJECT_ROOT/.certs-postgres"
    QDRANT_CERTS_DIR="$PROJECT_ROOT/.certs-qdrant"
    BACKEND_CERTS_DIR="$PROJECT_ROOT/.certs-backend"
    
    log_info "Creating service-specific certificate directories..."
    mkdir -p "$POSTGRES_CERTS_DIR" "$QDRANT_CERTS_DIR" "$BACKEND_CERTS_DIR"
    
    # Copy certificates to each service directory
    if [[ -f "$CERTS_DIR/cert.pem" ]] && [[ -f "$CERTS_DIR/key.pem" ]]; then
        # PostgreSQL certificates (needs specific UID/permissions)
        cp "$CERTS_DIR/cert.pem" "$POSTGRES_CERTS_DIR/cert.pem"
        cp "$CERTS_DIR/key.pem" "$POSTGRES_CERTS_DIR/key.pem"
        # Copy CA certificate if it exists
        if [[ -f "$CERTS_DIR/ca.pem" ]]; then
            cp "$CERTS_DIR/ca.pem" "$POSTGRES_CERTS_DIR/ca.pem"
        fi
        
        # Set PostgreSQL permissions using podman unshare for correct UID mapping
        log_info "Setting PostgreSQL certificate permissions (UID 999)..."
        podman unshare chown -R 999:999 "$POSTGRES_CERTS_DIR"
        podman unshare chmod 644 "$POSTGRES_CERTS_DIR/cert.pem"
        podman unshare chmod 600 "$POSTGRES_CERTS_DIR/key.pem"
        if [[ -f "$POSTGRES_CERTS_DIR/ca.pem" ]]; then
            podman unshare chmod 644 "$POSTGRES_CERTS_DIR/ca.pem"
        fi
        
        # Qdrant certificates (more permissive)
        cp "$CERTS_DIR/cert.pem" "$QDRANT_CERTS_DIR/cert.pem"
        cp "$CERTS_DIR/key.pem" "$QDRANT_CERTS_DIR/key.pem"
        # Copy CA certificate if it exists
        if [[ -f "$CERTS_DIR/ca.pem" ]]; then
            cp "$CERTS_DIR/ca.pem" "$QDRANT_CERTS_DIR/ca.pem"
        fi
        chmod 644 "$QDRANT_CERTS_DIR/cert.pem"
        chmod 644 "$QDRANT_CERTS_DIR/key.pem"
        if [[ -f "$QDRANT_CERTS_DIR/ca.pem" ]]; then
            chmod 644 "$QDRANT_CERTS_DIR/ca.pem"
        fi
        
        # Backend certificates (user ownership)
        cp "$CERTS_DIR/cert.pem" "$BACKEND_CERTS_DIR/cert.pem"
        cp "$CERTS_DIR/key.pem" "$BACKEND_CERTS_DIR/key.pem"
        # Copy CA certificate if it exists
        if [[ -f "$CERTS_DIR/ca.pem" ]]; then
            cp "$CERTS_DIR/ca.pem" "$BACKEND_CERTS_DIR/ca.pem"
        fi
        chmod 644 "$BACKEND_CERTS_DIR/cert.pem"
        chmod 600 "$BACKEND_CERTS_DIR/key.pem"
        if [[ -f "$BACKEND_CERTS_DIR/ca.pem" ]]; then
            chmod 644 "$BACKEND_CERTS_DIR/ca.pem"
        fi
        
        log_success "Service-specific certificates prepared"
        log_info "PostgreSQL certificates: $POSTGRES_CERTS_DIR (UID 999, mode 600 key)"
        log_info "Qdrant certificates: $QDRANT_CERTS_DIR (permissive)"
        log_info "Backend certificates: $BACKEND_CERTS_DIR (user ownership)"
        
        if [[ -f "$CERTS_DIR/ca.pem" ]]; then
            log_success "CA certificate included for container trust"
        else
            log_warning "CA certificate not found - containers may have trust issues"
        fi
    else
        log_error "Source certificates not found!"
        exit 1
    fi
}

init_aws_certs() {
    local environment="$1"
    log_info "Checking certificates for AWS $environment environment..."
    
    # For AWS environments, certificates should be in Secrets Manager
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if certificates exist in Secrets Manager
    local secret_name="${environment}/scribe/app"
    
    if aws secretsmanager get-secret-value --secret-id "$secret_name" --query 'SecretString' --output text >/dev/null 2>&1; then
        local cert_exists=$(aws secretsmanager get-secret-value \
            --secret-id "$secret_name" \
            --query 'SecretString' \
            --output text | jq -r '.tls_cert_pem' 2>/dev/null)
            
        if [[ -n "$cert_exists" ]] && [[ "$cert_exists" != "null" ]]; then
            log_success "TLS certificates found in AWS Secrets Manager ($secret_name)"
        else
            log_warning "Secrets Manager entry exists but TLS certificates not found"
            log_info "You may need to update the secret with certificate data"
        fi
    else
        log_error "Cannot access AWS Secrets Manager secret: $secret_name"
        log_info "Please ensure:"
        log_info "  1. AWS credentials are configured"
        log_info "  2. The secret exists in Secrets Manager" 
        log_info "  3. You have the necessary permissions"
        exit 1
    fi
}

check_certificates() {
    local environment="$1"
    
    case "$environment" in
        local)
            if [[ -f "$CERTS_DIR/cert.pem" ]] && [[ -f "$CERTS_DIR/key.pem" ]]; then
                log_success "Local certificates exist"
                log_info "Certificate: $CERTS_DIR/cert.pem"
                log_info "Private key: $CERTS_DIR/key.pem"
                
                # Show certificate validity
                if command -v openssl &> /dev/null; then
                    local expiry=$(openssl x509 -in "$CERTS_DIR/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
                    log_info "Certificate expires: $expiry"
                fi
            else
                log_warning "Local certificates not found"
                log_info "Run: $0 local init"
            fi
            ;;
        container)
            check_certificates local  # Container certs are based on local
            
            local container_certs_dir="$PROJECT_ROOT/.container-certs"
            if [[ -f "$container_certs_dir/cert.pem" ]] && [[ -f "$container_certs_dir/key.pem" ]]; then
                log_success "Container certificates exist"
                log_info "Container certs: $container_certs_dir"
            else
                log_warning "Container certificates not found"
                log_info "Run: $0 container init"
            fi
            ;;
        staging|production)
            init_aws_certs "$environment"
            ;;
        *)
            log_error "Unknown environment: $environment"
            show_usage
            exit 1
            ;;
    esac
}

clean_certificates() {
    local environment="$1"
    
    case "$environment" in
        local)
            if [[ -d "$CERTS_DIR" ]]; then
                log_info "Cleaning local certificates..."
                rm -rf "$CERTS_DIR"
                log_success "Local certificates cleaned"
            else
                log_info "No local certificates to clean"
            fi
            ;;
        container)
            local container_certs_dir="$PROJECT_ROOT/.container-certs"
            if [[ -d "$container_certs_dir" ]]; then
                log_info "Cleaning container certificates..."
                rm -rf "$container_certs_dir"
                log_success "Container certificates cleaned"
            else
                log_info "No container certificates to clean"
            fi
            ;;
        staging|production)
            log_warning "AWS certificate cleanup must be done manually"
            log_info "Certificates are stored in AWS Secrets Manager"
            log_info "Secret name: ${environment}/scribe/app"
            ;;
        *)
            log_error "Unknown environment: $environment"
            show_usage
            exit 1
            ;;
    esac
}

main() {
    local environment="${1:-}"
    local action="${2:-init}"
    
    # Handle help as first argument
    if [[ "$environment" == "help" ]]; then
        show_usage
        return 0
    fi
    
    if [[ -z "$environment" ]]; then
        environment=$(detect_environment)
        log_info "Auto-detected environment: $environment"
    fi
    
    case "$action" in
        init)
            case "$environment" in
                local)
                    init_local_certs
                    ;;
                container)
                    init_container_certs
                    ;;
                staging|production)
                    init_aws_certs "$environment"
                    ;;
                *)
                    log_error "Unknown environment: $environment"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        check)
            check_certificates "$environment"
            ;;
        clean)
            clean_certificates "$environment"
            ;;
        help)
            show_usage
            ;;
        *)
            log_error "Unknown action: $action"
            show_usage
            exit 1
            ;;
    esac
}

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi