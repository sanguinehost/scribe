# Certificate Initialization Container

This container handles TLS certificate setup for containerized deployments of the Scribe backend.

## Purpose

The certificate init container solves the common problem of providing TLS certificates to containers in different deployment scenarios:

- **AWS ECS**: Converts certificates from AWS Secrets Manager environment variables to files
- **Local Development**: Can generate self-signed certificates for development use
- **Container Orchestration**: Provides certificates to other containers via shared volumes

## How It Works

1. **Environment Variable Detection**: Checks for `TLS_CERT_PEM` and `TLS_KEY_PEM` environment variables
2. **Certificate Writing**: Converts PEM-encoded certificates to files with proper permissions
3. **Validation**: Verifies certificate format and that cert/key pair match
4. **Shared Volume**: Places certificates in `/shared/certs/` for other containers to access

## Usage

### In Docker Compose / Podman Compose

```yaml
services:
  cert-init:
    build: ./infrastructure/containers/cert-init/
    environment:
      - TLS_CERT_PEM=${TLS_CERT_PEM}
      - TLS_KEY_PEM=${TLS_KEY_PEM}
      - TLS_CA_PEM=${TLS_CA_PEM}  # Optional
    volumes:
      - certificates:/shared/certs
    restart: "no"  # Run once only
    
  backend:
    image: scribe-backend:latest
    depends_on:
      - cert-init
    volumes:
      - certificates:/app/certs:ro
    environment:
      - ENVIRONMENT=container

volumes:
  certificates:
```

### In AWS ECS Task Definition

```json
{
  "containerDefinitions": [
    {
      "name": "cert-init",
      "image": "your-ecr-repo/scribe-cert-init:latest",
      "essential": false,
      "secrets": [
        {
          "name": "TLS_CERT_PEM",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:env/scribe/app:tls_cert_pem::"
        },
        {
          "name": "TLS_KEY_PEM", 
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:env/scribe/app:tls_key_pem::"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "certificates",
          "containerPath": "/shared/certs"
        }
      ]
    },
    {
      "name": "backend",
      "image": "your-ecr-repo/scribe-backend:latest",
      "essential": true,
      "dependsOn": [
        {
          "containerName": "cert-init",
          "condition": "SUCCESS"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "certificates",
          "containerPath": "/app/certs",
          "readOnly": true
        }
      ]
    }
  ],
  "volumes": [
    {
      "name": "certificates"
    }
  ]
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TLS_CERT_PEM` | Yes* | PEM-encoded TLS certificate |
| `TLS_KEY_PEM` | Yes* | PEM-encoded private key |
| `TLS_CA_PEM` | No | PEM-encoded CA certificate |
| `ENVIRONMENT` | No | Environment type (development/production) |
| `CERT_DIR` | No | Certificate output directory (default: `/shared/certs`) |

*Required for production environments. Development environments can use self-signed certificates.

## File Output

The container creates the following files in the shared volume:

- `/shared/certs/cert.pem` - TLS certificate (permissions: 644)
- `/shared/certs/key.pem` - Private key (permissions: 600)
- `/shared/certs/ca.crt` - CA certificate if provided (permissions: 644)

## Security Features

- **Non-root execution**: Runs as `certuser` for security
- **Proper permissions**: Sets restrictive permissions on private key
- **Certificate validation**: Verifies certificate format and matching
- **Secure secrets handling**: Processes environment variables securely

## Building the Image

```bash
cd infrastructure/containers/cert-init/
docker build -t scribe-cert-init:latest .

# For multi-arch builds
docker buildx build --platform linux/amd64,linux/arm64 -t scribe-cert-init:latest .
```

## Troubleshooting

### Certificate Validation Errors
- Ensure PEM format is correct (includes BEGIN/END markers)
- Verify certificate and key match
- Check for extra whitespace or encoding issues

### Permission Errors
- Container runs as non-root user `certuser`
- Shared volumes must allow write access
- Target directories must be writable by UID 1000

### Development Use
- Set `ENVIRONMENT=development` to enable self-signed certificate generation
- Self-signed certs include `localhost` and `backend` in SAN

## Integration with Scribe Backend

The Scribe backend automatically detects certificates in the following order:

1. **Environment variables**: `TLS_CERT_PEM`, `TLS_KEY_PEM` (preferred for containers)
2. **Mounted files**: `/app/certs/cert.pem`, `/app/certs/key.pem`
3. **Local files**: `.certs/cert.pem`, `.certs/key.pem` (local development only)

This init container provides option #2, making certificates available as mounted files for the backend to consume.