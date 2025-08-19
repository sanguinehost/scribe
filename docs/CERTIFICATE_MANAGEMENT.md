# Certificate Management Architecture

This document outlines the comprehensive certificate management system for Sanguine Scribe across all deployment environments. The system ensures TLS encryption is properly handled while maintaining the security requirements from the [Encryption Architecture](./ENCRYPTION_ARCHITECTURE.md).

## Overview

The certificate management system has been redesigned to properly handle different deployment scenarios while maintaining the encryption requirements for data at rest. The key principle is **environment separation** - each deployment environment has its own certificate management strategy optimized for that context.

## Environment-Specific Architecture

### 1. Local Development Environment (`ENVIRONMENT=local`)

**Use Case**: Running backend with `cargo` locally + containerized PostgreSQL/Qdrant

**Certificate Source**: `mkcert` generated certificates in `.certs/` directory

**Configuration**:
- Environment files: `configs/local/.env`
- Compose file: `podman-compose.local.yml`
- Backend loads from: `.certs/cert.pem`, `.certs/key.pem`
- Qdrant URL: `https://localhost:6334`

**Setup Commands**:
```bash
# Initialize certificates
./scripts/init-certs.sh local init

# Start containers (postgres + qdrant only)
cd infrastructure/containers/compose
podman-compose -f podman-compose.yml -f podman-compose.local.yml up postgres qdrant

# Run backend locally
cargo run --bin scribe-backend
```

**Certificate Flow**:
1. `mkcert` generates CA-signed certificates trusted by local system
2. Certificates placed in `.certs/` with correct local user permissions
3. Backend loads certificates directly from files
4. Containers access host certificates via volume mount

### 2. Container Development Environment (`ENVIRONMENT=container`)

**Use Case**: All services containerized locally for testing full container deployment

**Certificate Source**: Host certificates mounted with container-friendly permissions

**Configuration**:
- Environment files: `configs/container/.env`
- Compose file: `podman-compose.container.yml`
- Backend loads from: `/app/certs/cert.pem`, `/app/certs/key.pem` or `TLS_CERT_PEM`/`TLS_KEY_PEM` env vars
- Qdrant URL: `https://qdrant:6334`

**Setup Commands**:
```bash
# Initialize certificates for containers
./scripts/init-certs.sh container init

# Build backend container
docker build -t scribe-backend:latest backend/

# Start all containers
cd infrastructure/containers/compose  
podman-compose -f podman-compose.yml -f podman-compose.container.yml up
```

**Certificate Flow**:
1. Certificates prepared in `.container-certs/` with container-friendly permissions (644)
2. Certificates mounted into containers via shared volumes
3. Backend container loads certificates from mounted volume
4. Init container pattern available for complex deployments

### 3. AWS Staging Environment (`ENVIRONMENT=staging`)

**Use Case**: AWS ECS Fargate deployment for staging environment

**Certificate Source**: AWS Secrets Manager environment variables

**Configuration**:
- Environment files: `configs/staging/.env.example`
- Terraform: `infrastructure/terraform-examples/ecs-with-cert-init.tf`
- Backend loads from: `TLS_CERT_PEM`/`TLS_KEY_PEM` environment variables
- Qdrant URL: `https://qdrant.staging.local:6334` (ECS Service Discovery)

**Setup Commands**:
```bash
# Check AWS certificates
./scripts/init-certs.sh staging check

# Deploy with Terraform
cd infrastructure/terraform/environments/staging
terraform plan
terraform apply
```

**Certificate Flow**:
1. Certificates stored as strings in AWS Secrets Manager (`staging/scribe/app`)
2. ECS Task Definition loads certificates from Secrets Manager as environment variables
3. Certificate init container converts environment variables to files (optional)
4. Backend loads certificates from environment variables or mounted files

### 4. AWS Production Environment (`ENVIRONMENT=production`)

**Use Case**: AWS ECS Fargate deployment for production environment

**Certificate Source**: AWS Secrets Manager with proper rotation policies

**Configuration**:
- Environment files: `configs/production/.env.example`
- Terraform: Production-specific task definitions
- Backend loads from: `TLS_CERT_PEM`/`TLS_KEY_PEM` environment variables
- Qdrant URL: `https://qdrant.production.local:6334`

**Certificate Requirements**:
- Valid CA-signed certificates (Let's Encrypt, AWS Certificate Manager, etc.)
- Automated rotation via AWS Secrets Manager
- Proper certificate validation and monitoring

## Backend Certificate Loading Logic

The backend automatically detects the environment and loads certificates accordingly:

```rust
match environment {
    "staging" | "production" => {
        // Load from TLS_CERT_PEM/TLS_KEY_PEM environment variables
        load_cloud_certificate().await?
    },
    "container" => {
        // Try environment variables first, then mounted files
        if let (Ok(cert_pem), Ok(key_pem)) = (env::var("TLS_CERT_PEM"), env::var("TLS_KEY_PEM")) {
            RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?
        } else {
            RustlsConfig::from_pem_file("/app/certs/cert.pem", "/app/certs/key.pem").await?
        }
    },
    "local" | _ => {
        // Load from .certs/ directory
        RustlsConfig::from_pem_file(".certs/cert.pem", ".certs/key.pem").await?
    }
}
```

## Certificate Security Features

### Permission Management
- **Local**: User-owned certificates (600 for keys, 644 for certs)
- **Container**: Container-accessible permissions (644/600)
- **AWS**: Environment variables only, no file permissions needed

### Validation
- Certificate format validation (PEM structure)
- Certificate/key pair matching verification
- Expiration date checking
- SAN (Subject Alternative Name) validation

### Secrets Handling
- Environment variables cleared after loading
- No certificate logging in production
- Secure secrets management via AWS Secrets Manager
- Rotation support for production certificates

## Migration Guide

### From Old Single Environment to New Multi-Environment

1. **Update Environment Variables**:
   ```bash
   # Old .env
   DATABASE_URL=postgres://...
   QDRANT_URL=https://localhost:6334
   
   # New configs/local/.env
   ENVIRONMENT=local
   DATABASE_URL=postgresql://...
   QDRANT_URL=https://localhost:6334
   ```

2. **Update Compose Commands**:
   ```bash
   # Old command
   podman-compose -f podman-compose.yml -f podman-compose.dev.yml up
   
   # New commands
   podman-compose -f podman-compose.yml -f podman-compose.local.yml up postgres qdrant  # For local backend
   podman-compose -f podman-compose.yml -f podman-compose.container.yml up              # For containerized
   ```

3. **Certificate Initialization**:
   ```bash
   # Replace manual certificate generation
   ./scripts/dev_certs.sh generate
   
   # With environment-aware initialization
   ./scripts/init-certs.sh local init
   ```

## Troubleshooting

### Permission Errors

**Symptom**: `Permission denied` when loading certificates

**Solutions**:
```bash
# For local development
./scripts/init-certs.sh local clean
./scripts/init-certs.sh local init

# Check certificate ownership
ls -la .certs/
```

**For containers**:
```bash
# Check container certificate permissions
./scripts/init-certs.sh container check

# Regenerate with correct permissions
./scripts/init-certs.sh container init
```

### Certificate Validation Errors

**Symptom**: `Failed to create RustlsConfig` or certificate format errors

**Solutions**:
1. Verify certificate format:
   ```bash
   openssl x509 -in .certs/cert.pem -text -noout
   openssl rsa -in .certs/key.pem -check -noout
   ```

2. Check certificate/key matching:
   ```bash
   openssl x509 -noout -modulus -in .certs/cert.pem | openssl md5
   openssl rsa -noout -modulus -in .certs/key.pem | openssl md5
   ```

3. Regenerate certificates:
   ```bash
   ./scripts/init-certs.sh local clean
   ./scripts/init-certs.sh local init
   ```

### Qdrant Connection Issues

**Symptom**: `Failed to connect to https://localhost:6334`

**Solutions**:
1. Check Qdrant container status:
   ```bash
   podman ps | grep qdrant
   ```

2. Verify TLS is enabled in container:
   ```bash
   podman logs scribe_qdrant | grep -i tls
   ```

3. Test connection:
   ```bash
   curl -k https://localhost:6334/collections
   ```

### Environment Detection Issues

**Symptom**: Wrong certificate loading method used

**Solutions**:
1. Explicitly set environment:
   ```bash
   export ENVIRONMENT=local
   cargo run --bin scribe-backend
   ```

2. Check configuration loading:
   ```bash
   # Add debug logging
   RUST_LOG=debug cargo run --bin scribe-backend 2>&1 | grep -i environment
   ```

## Security Considerations

### Development Environments
- Use `mkcert` for CA-signed local certificates
- Never commit certificates to version control
- Rotate development certificates regularly

### Production Environments  
- Use valid CA-signed certificates only
- Implement automated certificate rotation
- Monitor certificate expiration
- Use AWS Secrets Manager for secure storage
- Enable CloudWatch monitoring for certificate events

### Certificate Storage
- **Local**: File-based with proper permissions
- **Container**: Environment variables preferred, files as fallback
- **AWS**: Secrets Manager only, never in environment files

## Integration with Encryption Architecture

This certificate management system is designed to work seamlessly with the [Encryption Architecture](./ENCRYPTION_ARCHITECTURE.md):

1. **TLS provides encryption in transit** for all API communications
2. **DEK encryption provides encryption at rest** for all stored data
3. **Certificate management ensures TLS is properly configured** across all environments
4. **Separation of concerns**: TLS certificates handle transport security, DEKs handle data security

The combination ensures end-to-end security while maintaining operational flexibility across different deployment scenarios.

## Commands Reference

### Certificate Management
```bash
# Initialize certificates for environment
./scripts/init-certs.sh <environment> init

# Check certificate status  
./scripts/init-certs.sh <environment> check

# Clean certificates
./scripts/init-certs.sh <environment> clean

# Show help
./scripts/init-certs.sh help
```

### Environment-Specific Deployment
```bash
# Local development
podman-compose -f podman-compose.yml -f podman-compose.local.yml up postgres qdrant
cargo run --bin scribe-backend

# Container development
podman-compose -f podman-compose.yml -f podman-compose.container.yml up

# AWS deployment
terraform apply -var-file="staging.tfvars"
```

### Troubleshooting
```bash  
# Check certificate validity
openssl x509 -in .certs/cert.pem -text -noout

# Test Qdrant connection
curl -k https://localhost:6334/collections

# Debug backend startup
RUST_LOG=debug cargo run --bin scribe-backend
```