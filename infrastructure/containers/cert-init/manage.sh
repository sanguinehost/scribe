#!/bin/bash
set -euo pipefail

# Unified Certificate Management Script for Sanguine Scribe
# Consolidates functionality from generate.sh, init.sh, and setup-certs.sh
# Supports all deployment scenarios: local, container, and AWS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
Unified Certificate Management for Sanguine Scribe

USAGE:
    $0 <mode> [action] [options]

MODES:
    local       - Local development with cargo backend + containerized services
    container   - Fully containerized local development (backend + services)
    aws         - AWS ECS deployment (env vars to files)

ACTIONS:
    init        - Initialize certificates (default)
    check       - Check certificate status
    clean       - Clean existing certificates
    help        - Show this help message

OPTIONS:
    --runtime=<docker|podman>  - Force specific container runtime
    --environment=<env>        - AWS environment (staging/production)

EXAMPLES:
    $0 local init              # Setup certificates for local development
    $0 container init          # Setup service-specific certificates for containers
    $0 container init --runtime=docker  # Force Docker-compatible permissions
    $0 aws init --environment=staging   # Setup AWS staging certificates
    $0 check                   # Check all certificate configurations

DEPLOYMENT SCENARIOS:
    1. Local backend + containerized services: Use 'local' mode
    2. Fully containerized deployment: Use 'container' mode
    3. AWS ECS with environment variables: Use 'aws' mode

EOF
}

# Parse command line arguments
MODE="${1:-}"
ACTION="${2:-init}"
RUNTIME=""
AWS_ENVIRONMENT="staging"

# Parse options
for arg in "${@:3}"; do
    case $arg in
        --runtime=*)
            RUNTIME="${arg#*=}"
            ;;
        --environment=*)
            AWS_ENVIRONMENT="${arg#*=}"
            ;;
        *)
            log_error "Unknown option: $arg"
            show_usage
            exit 1
            ;;
    esac
done

# Auto-detect environment if not specified
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

# Auto-detect container runtime
detect_runtime() {
    if [[ -n "$RUNTIME" ]]; then
        echo "$RUNTIME"
    elif command -v podman &> /dev/null; then
        echo "podman"
    elif command -v docker &> /dev/null; then
        echo "docker"
    else
        echo "none"
    fi
}

# Certificate directories
MAIN_CERTS_DIR="$PROJECT_ROOT/.certs"
POSTGRES_CERTS_DIR="$PROJECT_ROOT/.certs-postgres"
QDRANT_CERTS_DIR="$PROJECT_ROOT/.certs-qdrant"
BACKEND_CERTS_DIR="$PROJECT_ROOT/.certs-backend"

#############################################
# Local Development Mode
#############################################

generate_local_certs() {
    log_info "Generating certificates for local development..."
    
    # Check if mkcert is available
    if ! command -v mkcert &> /dev/null; then
        log_error "mkcert is not installed. Please install it first:"
        log_info "  macOS: brew install mkcert"
        log_info "  Linux: See https://github.com/FiloSottile/mkcert#installation"
        exit 1
    fi
    
    log_info "Ensuring local CA is installed (may require password)..."
    if ! mkcert -install; then
        log_error "Failed to install mkcert local CA."
        exit 1
    fi

    log_info "Generating certificate and key files..."
    mkdir -p "$MAIN_CERTS_DIR"
    
    local key_file="$MAIN_CERTS_DIR/key.pem"
    local cert_file="$MAIN_CERTS_DIR/cert.pem"
    local ca_file="$MAIN_CERTS_DIR/ca.pem"
    
    if ! mkcert -key-file "$key_file" -cert-file "$cert_file" \
        localhost 127.0.0.1 ::1 qdrant postgres backend; then
        log_error "Failed to generate certificates with mkcert."
        rm -f "$key_file" "$cert_file"
        exit 1
    fi

    # Copy the mkcert CA certificate
    log_info "Copying mkcert CA certificate..."
    local ca_root="$(mkcert -CAROOT)"
    local ca_cert_source="$ca_root/rootCA.pem"
    
    if [[ -f "$ca_cert_source" ]]; then
        cp "$ca_cert_source" "$ca_file"
        log_success "mkcert CA certificate copied to $ca_file"
    else
        log_warning "mkcert CA certificate not found - containers may have trust issues"
    fi
    
    # Set proper permissions
    chmod 755 "$MAIN_CERTS_DIR"
    chmod 644 "$cert_file"
    chmod 600 "$key_file"
    [[ -f "$ca_file" ]] && chmod 644 "$ca_file"
    
    log_success "Local certificates generated:"
    log_info "  Certificate: $cert_file"
    log_info "  Private key: $key_file"
    [[ -f "$ca_file" ]] && log_info "  CA certificate: $ca_file"
}

init_local_mode() {
    log_info "Initializing certificates for local development mode..."
    log_info "Mode: Local backend + containerized PostgreSQL/Qdrant"
    
    generate_local_certs
    log_success "Local development certificates ready"
    log_info "Use these certificates in your Rust backend configuration"
}

#############################################
# Container Development Mode  
#############################################

copy_certificates_to_service_dirs() {
    local runtime="$1"
    
    log_info "Creating service-specific certificate directories..."
    mkdir -p "$POSTGRES_CERTS_DIR" "$QDRANT_CERTS_DIR" "$BACKEND_CERTS_DIR"
    
    # Ensure source certificates exist
    if [[ ! -f "$MAIN_CERTS_DIR/cert.pem" ]] || [[ ! -f "$MAIN_CERTS_DIR/key.pem" ]]; then
        log_error "Source certificates not found. Generating them first..."
        generate_local_certs
    fi
    
    # Copy certificates to each service directory
    local cert_files=("cert.pem" "key.pem")
    [[ -f "$MAIN_CERTS_DIR/ca.pem" ]] && cert_files+=("ca.pem")
    
    for file in "${cert_files[@]}"; do
        cp "$MAIN_CERTS_DIR/$file" "$POSTGRES_CERTS_DIR/$file"
        cp "$MAIN_CERTS_DIR/$file" "$QDRANT_CERTS_DIR/$file"
        cp "$MAIN_CERTS_DIR/$file" "$BACKEND_CERTS_DIR/$file"
    done
    
    # Apply service-specific permissions
    apply_service_permissions "$runtime"
}

apply_service_permissions() {
    local runtime="$1"
    
    log_info "Applying service-specific permissions for $runtime runtime..."
    
    # PostgreSQL permissions (UID 999, restrictive)
    log_info "Setting PostgreSQL certificate permissions (UID 999)..."
    if [[ "$runtime" == "podman" ]]; then
        # Use podman unshare for proper UID mapping without sudo
        podman unshare chown -R 999:999 "$POSTGRES_CERTS_DIR"
        podman unshare chmod 644 "$POSTGRES_CERTS_DIR/cert.pem"
        podman unshare chmod 600 "$POSTGRES_CERTS_DIR/key.pem"
        [[ -f "$POSTGRES_CERTS_DIR/ca.pem" ]] && podman unshare chmod 644 "$POSTGRES_CERTS_DIR/ca.pem"
    else
        # Docker mode - let Docker handle internal UID mapping
        log_info "Docker runtime: Relying on container internal UID handling"
        chmod 644 "$POSTGRES_CERTS_DIR/cert.pem"
        chmod 600 "$POSTGRES_CERTS_DIR/key.pem"
        [[ -f "$POSTGRES_CERTS_DIR/ca.pem" ]] && chmod 644 "$POSTGRES_CERTS_DIR/ca.pem"
    fi
    
    # Qdrant permissions (permissive)
    log_info "Setting Qdrant certificate permissions (permissive)..."
    chmod 644 "$QDRANT_CERTS_DIR/cert.pem"
    chmod 644 "$QDRANT_CERTS_DIR/key.pem"
    [[ -f "$QDRANT_CERTS_DIR/ca.pem" ]] && chmod 644 "$QDRANT_CERTS_DIR/ca.pem"
    
    # Backend permissions (user ownership)
    log_info "Setting backend certificate permissions (user ownership)..."
    chmod 644 "$BACKEND_CERTS_DIR/cert.pem"
    chmod 600 "$BACKEND_CERTS_DIR/key.pem"
    [[ -f "$BACKEND_CERTS_DIR/ca.pem" ]] && chmod 644 "$BACKEND_CERTS_DIR/ca.pem"
    
    log_success "Service-specific certificate permissions applied"
    log_info "PostgreSQL certificates: $POSTGRES_CERTS_DIR (UID 999 for Podman, Docker internal for Docker)"
    log_info "Qdrant certificates: $QDRANT_CERTS_DIR (permissive 644)"
    log_info "Backend certificates: $BACKEND_CERTS_DIR (user ownership)"
}

init_container_mode() {
    local runtime=$(detect_runtime)
    
    log_info "Initializing certificates for container development mode..."
    log_info "Mode: Fully containerized backend + services"
    log_info "Runtime: $runtime"
    
    if [[ "$runtime" == "none" ]]; then
        log_error "No container runtime detected. Please install Docker or Podman."
        exit 1
    fi
    
    copy_certificates_to_service_dirs "$runtime"
    
    log_success "Container development certificates ready"
    if [[ -f "$MAIN_CERTS_DIR/ca.pem" ]]; then
        log_success "CA certificate included for container trust"
    else
        log_warning "CA certificate not found - containers may have trust issues"
    fi
}

#############################################
# AWS ECS Mode
#############################################

validate_certificate() {
    local cert_file="$1"
    local key_file="$2"
    
    if ! openssl x509 -in "$cert_file" -text -noout >/dev/null 2>&1; then
        log_error "Invalid certificate format in $cert_file"
        return 1
    fi
    
    if ! openssl rsa -in "$key_file" -check -noout >/dev/null 2>&1; then
        log_error "Invalid private key format in $key_file"
        return 1
    fi
    
    # Check if certificate and key match
    local cert_modulus=$(openssl x509 -noout -modulus -in "$cert_file" 2>/dev/null | openssl md5)
    local key_modulus=$(openssl rsa -noout -modulus -in "$key_file" 2>/dev/null | openssl md5)
    
    if [[ "$cert_modulus" != "$key_modulus" ]]; then
        log_error "Certificate and private key do not match"
        return 1
    fi
    
    log_success "Certificate validation passed"
    return 0
}

show_certificate_info() {
    local cert_file="$1"
    
    log_info "Certificate information:"
    
    local subject=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | sed 's/^subject=//')
    local issuer=$(openssl x509 -noout -issuer -in "$cert_file" 2>/dev/null | sed 's/^issuer=//')
    local start_date=$(openssl x509 -noout -startdate -in "$cert_file" 2>/dev/null | sed 's/^notBefore=//')
    local end_date=$(openssl x509 -noout -enddate -in "$cert_file" 2>/dev/null | sed 's/^notAfter=//')
    
    log_info "  Subject: $subject"
    log_info "  Issuer: $issuer" 
    log_info "  Valid from: $start_date"
    log_info "  Valid until: $end_date"
}

generate_self_signed_cert() {
    local cert_dir="$1"
    local cert_file="$cert_dir/cert.pem"
    local key_file="$cert_dir/key.pem"
    
    log_warning "Generating self-signed certificate for development..."
    
    mkdir -p "$cert_dir"
    openssl req -x509 -newkey rsa:4096 -keyout "$key_file" -out "$cert_file" \
        -days 365 -nodes \
        -subj "/CN=localhost/O=Scribe Development/C=US" \
        -addext "subjectAltName=DNS:localhost,DNS:backend,DNS:qdrant,DNS:postgres,IP:127.0.0.1"
        
    chmod 644 "$cert_file"
    chmod 600 "$key_file"
    
    log_warning "Self-signed certificate generated for development use"
    show_certificate_info "$cert_file"
}

init_aws_mode() {
    local environment="$AWS_ENVIRONMENT"
    log_info "Initializing certificates for AWS ECS deployment..."
    log_info "Environment: $environment"
    
    # Certificate directory for ECS
    local cert_dir="${CERT_DIR:-/shared/certs}"
    local cert_file="$cert_dir/cert.pem"
    local key_file="$cert_dir/key.pem"
    local ca_file="$cert_dir/ca.crt"
    
    # For local testing, use project directories
    if [[ ! -d "/shared" ]]; then
        cert_dir="$PROJECT_ROOT/.certs-aws"
        cert_file="$cert_dir/cert.pem"
        key_file="$cert_dir/key.pem"
        ca_file="$cert_dir/ca.pem"
        log_info "Using local directory for testing: $cert_dir"
    fi
    
    mkdir -p "$cert_dir"
    
    log_info "Checking for TLS certificate environment variables..."
    
    if [[ -n "${TLS_CERT_PEM:-}" ]] && [[ -n "${TLS_KEY_PEM:-}" ]]; then
        log_success "Found TLS certificate environment variables"
        
        # Write certificate to file
        echo "$TLS_CERT_PEM" > "$cert_file"
        log_success "Certificate written to $cert_file"
        
        # Write private key to file
        echo "$TLS_KEY_PEM" > "$key_file"
        log_success "Private key written to $key_file"
        
        # Set proper permissions
        chmod 644 "$cert_file"
        chmod 600 "$key_file"
        log_success "Certificate permissions set (cert: 644, key: 600)"
        
        # Write CA certificate if provided
        if [[ -n "${TLS_CA_PEM:-}" ]]; then
            echo "$TLS_CA_PEM" > "$ca_file"
            chmod 644 "$ca_file"
            log_success "CA certificate written to $ca_file"
        fi
        
        # Validate certificates
        if validate_certificate "$cert_file" "$key_file"; then
            show_certificate_info "$cert_file"
            log_success "AWS certificate initialization completed successfully"
        else
            log_error "Certificate validation failed"
            exit 1
        fi
        
    else
        # Check AWS Secrets Manager for production
        if command -v aws &> /dev/null; then
            local secret_name="${environment}/scribe/app"
            log_info "Checking AWS Secrets Manager: $secret_name"
            
            if aws secretsmanager get-secret-value --secret-id "$secret_name" --query 'SecretString' --output text >/dev/null 2>&1; then
                local cert_exists=$(aws secretsmanager get-secret-value \
                    --secret-id "$secret_name" \
                    --query 'SecretString' \
                    --output text | jq -r '.tls_cert_pem' 2>/dev/null)
                    
                if [[ -n "$cert_exists" ]] && [[ "$cert_exists" != "null" ]]; then
                    log_success "TLS certificates found in AWS Secrets Manager ($secret_name)"
                    return 0
                fi
            fi
        fi
        
        # Fallback for development environment
        if [[ "${ENVIRONMENT:-}" == "development" ]] || [[ "${ENVIRONMENT:-}" == "local" ]] || [[ ! -d "/shared" ]]; then
            generate_self_signed_cert "$cert_dir"
        else
            log_error "Production environment requires proper TLS certificates"
            log_error "Please ensure TLS_CERT_PEM and TLS_KEY_PEM environment variables are set"
            exit 1
        fi
    fi
}

#############################################
# Check and Clean Operations
#############################################

check_local_certs() {
    if [[ -f "$MAIN_CERTS_DIR/cert.pem" ]] && [[ -f "$MAIN_CERTS_DIR/key.pem" ]]; then
        log_success "Local certificates exist"
        log_info "Certificate: $MAIN_CERTS_DIR/cert.pem"
        log_info "Private key: $MAIN_CERTS_DIR/key.pem"
        
        if command -v openssl &> /dev/null; then
            local expiry=$(openssl x509 -in "$MAIN_CERTS_DIR/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
            log_info "Certificate expires: $expiry"
        fi
        
        if [[ -f "$MAIN_CERTS_DIR/ca.pem" ]]; then
            log_success "CA certificate: $MAIN_CERTS_DIR/ca.pem"
        fi
    else
        log_warning "Local certificates not found"
        log_info "Run: $0 local init"
    fi
}

check_container_certs() {
    check_local_certs
    
    local service_dirs=("$POSTGRES_CERTS_DIR" "$QDRANT_CERTS_DIR" "$BACKEND_CERTS_DIR")
    local service_names=("PostgreSQL" "Qdrant" "Backend")
    
    for i in "${!service_dirs[@]}"; do
        local dir="${service_dirs[$i]}"
        local name="${service_names[$i]}"
        
        if [[ -f "$dir/cert.pem" ]] && [[ -f "$dir/key.pem" ]]; then
            log_success "$name certificates exist: $dir"
        else
            log_warning "$name certificates not found: $dir"
        fi
    done
    
    if [[ ! -f "$POSTGRES_CERTS_DIR/cert.pem" ]]; then
        log_info "Run: $0 container init"
    fi
}

check_aws_certs() {
    local environment="$AWS_ENVIRONMENT"
    
    if command -v aws &> /dev/null; then
        local secret_name="${environment}/scribe/app"
        
        if aws secretsmanager get-secret-value --secret-id "$secret_name" --query 'SecretString' --output text >/dev/null 2>&1; then
            log_success "AWS Secrets Manager accessible: $secret_name"
        else
            log_warning "Cannot access AWS Secrets Manager: $secret_name"
        fi
    else
        log_warning "AWS CLI not available for checking"
    fi
    
    # Check local AWS test directory
    local aws_test_dir="$PROJECT_ROOT/.certs-aws"
    if [[ -f "$aws_test_dir/cert.pem" ]] && [[ -f "$aws_test_dir/key.pem" ]]; then
        log_success "Local AWS test certificates exist: $aws_test_dir"
    fi
}

clean_certs() {
    local mode="$1"
    
    case "$mode" in
        local)
            if [[ -d "$MAIN_CERTS_DIR" ]]; then
                log_info "Cleaning local certificates..."
                rm -rf "$MAIN_CERTS_DIR"
                log_success "Local certificates cleaned"
            fi
            ;;
        container)
            local dirs=("$POSTGRES_CERTS_DIR" "$QDRANT_CERTS_DIR" "$BACKEND_CERTS_DIR")
            for dir in "${dirs[@]}"; do
                if [[ -d "$dir" ]]; then
                    log_info "Cleaning $dir..."
                    rm -rf "$dir"
                fi
            done
            log_success "Container certificates cleaned"
            ;;
        aws)
            local aws_test_dir="$PROJECT_ROOT/.certs-aws"
            if [[ -d "$aws_test_dir" ]]; then
                log_info "Cleaning AWS test certificates..."
                rm -rf "$aws_test_dir"
                log_success "AWS test certificates cleaned"
            fi
            log_warning "Production AWS certificates must be managed via Secrets Manager"
            ;;
        all)
            clean_certs local
            clean_certs container
            clean_certs aws
            ;;
    esac
}

#############################################
# Main Function
#############################################

main() {
    # Handle help as first argument
    if [[ "$MODE" == "help" ]] || [[ -z "$MODE" ]]; then
        show_usage
        return 0
    fi
    
    # Auto-detect mode if not specified
    if [[ -z "$MODE" ]]; then
        MODE=$(detect_environment)
        log_info "Auto-detected mode: $MODE"
    fi
    
    case "$ACTION" in
        init)
            case "$MODE" in
                local)
                    init_local_mode
                    ;;
                container)
                    init_container_mode
                    ;;
                aws)
                    init_aws_mode
                    ;;
                *)
                    log_error "Unknown mode: $MODE"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        check)
            case "$MODE" in
                local)
                    check_local_certs
                    ;;
                container)
                    check_container_certs
                    ;;
                aws)
                    check_aws_certs
                    ;;
                all)
                    log_info "=== Checking all certificate configurations ==="
                    log_info "Local certificates:"
                    check_local_certs
                    echo
                    log_info "Container certificates:"
                    check_container_certs
                    echo
                    log_info "AWS certificates:"
                    check_aws_certs
                    ;;
                *)
                    log_error "Unknown mode: $MODE"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        clean)
            clean_certs "$MODE"
            ;;
        *)
            log_error "Unknown action: $ACTION"
            show_usage
            exit 1
            ;;
    esac
}

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi