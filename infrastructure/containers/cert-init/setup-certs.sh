#!/bin/bash
set -euo pipefail

# Certificate Setup Script for AWS ECS
# Converts certificates from environment variables to files with proper permissions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[CERT-INIT]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[CERT-INIT]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[CERT-INIT]${NC} $1"
}

log_error() {
    echo -e "${RED}[CERT-INIT]${NC} $1"
}

# Configuration
CERT_DIR="${CERT_DIR:-/shared/certs}"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
CA_FILE="$CERT_DIR/ca.crt"

# Ensure certificate directory exists
mkdir -p "$CERT_DIR"

log_info "Starting certificate initialization for ECS container"
log_info "Certificate directory: $CERT_DIR"

# Function to validate certificate
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

# Function to show certificate info
show_certificate_info() {
    local cert_file="$1"
    
    log_info "Certificate information:"
    
    # Extract and display certificate details
    local subject=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | sed 's/^subject=//')
    local issuer=$(openssl x509 -noout -issuer -in "$cert_file" 2>/dev/null | sed 's/^issuer=//')
    local start_date=$(openssl x509 -noout -startdate -in "$cert_file" 2>/dev/null | sed 's/^notBefore=//')
    local end_date=$(openssl x509 -noout -enddate -in "$cert_file" 2>/dev/null | sed 's/^notAfter=//')
    local dns_names=$(openssl x509 -noout -text -in "$cert_file" 2>/dev/null | grep -A1 "Subject Alternative Name" | grep -oP 'DNS:\K[^,]*' | tr '\n' ',' | sed 's/,$//')
    
    log_info "  Subject: $subject"
    log_info "  Issuer: $issuer"
    log_info "  Valid from: $start_date"
    log_info "  Valid until: $end_date"
    if [[ -n "$dns_names" ]]; then
        log_info "  DNS names: $dns_names"
    fi
}

# Main certificate setup logic
main() {
    log_info "Checking for TLS certificate environment variables..."
    
    # Check if certificate environment variables are provided
    if [[ -n "${TLS_CERT_PEM:-}" ]] && [[ -n "${TLS_KEY_PEM:-}" ]]; then
        log_success "Found TLS certificate environment variables"
        
        # Write certificate to file
        echo "$TLS_CERT_PEM" > "$CERT_FILE"
        log_success "Certificate written to $CERT_FILE"
        
        # Write private key to file
        echo "$TLS_KEY_PEM" > "$KEY_FILE"
        log_success "Private key written to $KEY_FILE"
        
        # Set proper permissions
        chmod 644 "$CERT_FILE"
        chmod 600 "$KEY_FILE"
        log_success "Certificate permissions set (cert: 644, key: 600)"
        
        # Write CA certificate if provided
        if [[ -n "${TLS_CA_PEM:-}" ]]; then
            echo "$TLS_CA_PEM" > "$CA_FILE"
            chmod 644 "$CA_FILE"
            log_success "CA certificate written to $CA_FILE"
        fi
        
        # Validate certificates
        if validate_certificate "$CERT_FILE" "$KEY_FILE"; then
            show_certificate_info "$CERT_FILE"
            log_success "Certificate initialization completed successfully"
        else
            log_error "Certificate validation failed"
            exit 1
        fi
        
    else
        log_warning "TLS certificate environment variables not found"
        log_info "Expected environment variables:"
        log_info "  - TLS_CERT_PEM: PEM-encoded certificate"
        log_info "  - TLS_KEY_PEM: PEM-encoded private key"  
        log_info "  - TLS_CA_PEM: PEM-encoded CA certificate (optional)"
        
        # Check if this is a development environment where we might generate self-signed certs
        if [[ "${ENVIRONMENT:-}" == "development" || "${ENVIRONMENT:-}" == "local" ]]; then
            log_warning "Development environment detected, generating self-signed certificate..."
            
            # Generate self-signed certificate for development
            openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
                -days 365 -nodes \
                -subj "/CN=localhost/O=Scribe Development/C=US" \
                -addext "subjectAltName=DNS:localhost,DNS:backend,IP:127.0.0.1"
                
            chmod 644 "$CERT_FILE"
            chmod 600 "$KEY_FILE"
            
            log_warning "Self-signed certificate generated for development use"
            show_certificate_info "$CERT_FILE"
        else
            log_error "Production environment requires proper TLS certificates"
            log_error "Please ensure TLS_CERT_PEM and TLS_KEY_PEM environment variables are set"
            exit 1
        fi
    fi
    
    # Final verification that files exist and are readable
    if [[ -f "$CERT_FILE" ]] && [[ -f "$KEY_FILE" ]]; then
        log_success "Certificate files are ready:"
        log_info "  Certificate: $CERT_FILE ($(stat -c%s "$CERT_FILE") bytes)"
        log_info "  Private key: $KEY_FILE ($(stat -c%s "$KEY_FILE") bytes)"
        
        if [[ -f "$CA_FILE" ]]; then
            log_info "  CA certificate: $CA_FILE ($(stat -c%s "$CA_FILE") bytes)"
        fi
        
        log_success "Certificate initialization container completed successfully"
        
        # Keep container running for a moment to ensure certificates are accessible
        log_info "Certificates available for application containers"
        sleep 5
        
    else
        log_error "Certificate files were not created successfully"
        exit 1
    fi
}

# Handle signals gracefully
trap 'log_info "Received signal, shutting down certificate init container"; exit 0' SIGTERM SIGINT

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi