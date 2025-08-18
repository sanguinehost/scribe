# Infrastructure Scripts

This directory contains scripts for managing the Sanguine Scribe infrastructure with both Podman and Docker support.

## Directory Structure

```
scripts/
├── podman/           # Podman-specific scripts
│   ├── dev_db.sh     # Development database management (Podman/Docker auto-detection)
│   └── build-backend.sh  # Build backend container with Podman
├── deploy/           # Deployment scripts
│   ├── deploy-backend.sh    # Deploy backend to AWS ECS
│   ├── run-migrations.sh    # Run database migrations
│   ├── view-logs.sh         # View application logs
│   ├── update-cookie-domain.sh  # Update cookie domain settings
│   └── nuke-rds.sh          # Dangerous: Delete RDS instance
├── utils/            # Utility scripts
│   ├── dev_db.sh     # Legacy development database script
│   ├── dev_certs.sh  # Generate development certificates
│   ├── generate_internal_cert.sh  # Generate internal certificates
│   └── terraform/    # Terraform utility scripts
└── README.md         # This file
```

## Quick Start

### Development (Podman/Docker)

```bash
# Start development databases with auto-detection
./infrastructure/scripts/podman/dev_db.sh up

# Build backend container
./infrastructure/scripts/podman/build-backend.sh --local-only

# Stop development databases
./infrastructure/scripts/podman/dev_db.sh down
```

### Deployment

```bash
# Deploy backend to AWS ECS
./infrastructure/scripts/deploy/deploy-backend.sh

# Run database migrations
./infrastructure/scripts/deploy/run-migrations.sh

# View application logs
./infrastructure/scripts/deploy/view-logs.sh
```

## Environment Variables

### Container Runtime Detection

The scripts automatically detect available container runtimes:

1. **Podman** (preferred if available)
2. **Docker** (fallback)

Override with: `CONTAINER_RUNTIME=docker ./script.sh`

### Common Variables

- `CONTAINER_RUNTIME`: Force runtime (podman|docker)
- `COMPOSE_FILE`: Override compose file path
- `CONTAINER_REGISTRY`: Registry for container images (default: quay.io)
- `CONTAINER_NAMESPACE`: Registry namespace (default: sanguine-scribe)

## Migration Notes

### From Docker to Podman

All scripts have been updated to support both Docker and Podman:

- Automatic runtime detection
- SELinux context handling (`:Z` volume mounts)
- Rootless container support
- Docker compatibility maintained

### Legacy Scripts

The `utils/` directory contains the original scripts for reference. Use the new `podman/` scripts for development.

## Security Notes

- Podman runs rootless by default (more secure)
- SELinux contexts are properly handled
- Container security options are configured
- Scripts validate runtime availability before execution