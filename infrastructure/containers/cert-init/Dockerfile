# Certificate Initialization Container
# This container handles TLS certificate setup for AWS ECS deployments
# It converts certificates from AWS Secrets Manager environment variables to files

FROM alpine:3.20

# Install required tools
RUN apk add --no-cache \
    openssl \
    curl \
    jq \
    bash \
    && rm -rf /var/cache/apk/*

# Create certificate directory
RUN mkdir -p /shared/certs

# Copy certificate setup script
COPY setup-certs.sh /usr/local/bin/setup-certs.sh
RUN chmod +x /usr/local/bin/setup-certs.sh

# Create non-root user for security
RUN adduser -D -s /bin/bash certuser && \
    chown -R certuser:certuser /shared

# Switch to non-root user
USER certuser

# Set working directory
WORKDIR /shared

# Set environment variables
ENV CERT_DIR=/shared/certs

# Health check to verify certificates are created
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD test -f /shared/certs/cert.pem && test -f /shared/certs/key.pem || exit 1

# Run the certificate setup script
CMD ["/usr/local/bin/setup-certs.sh"]