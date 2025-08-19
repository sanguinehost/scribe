# Build stage
FROM rust:1.87-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    cmake \
    g++ \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Copy diesel migrations
COPY migrations ./migrations

# Copy diesel.toml
COPY diesel.toml ./

# Copy tokenizer resources
COPY resources ./resources

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 app

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/scribe-backend /app/backend

# Copy migrations (needed for runtime migration checks)
COPY --from=builder /app/migrations /app/migrations

# Copy resources (tokenizers)
COPY --from=builder /app/resources /app/resources

# Create certificate directory with proper permissions
RUN mkdir -p /app/certs && \
    chown -R app:app /app

# Switch to app user
USER app

# Expose port
EXPOSE 8080

# Set environment variables for container deployment
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV ENVIRONMENT=container

# TLS certificates can be provided via:
# 1. Environment variables: TLS_CERT_PEM and TLS_KEY_PEM (preferred)
# 2. Mounted files: /app/certs/cert.pem and /app/certs/key.pem

# Health check (use HTTP for internal health, HTTPS will be available on port 8080)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f -k https://localhost:8080/health || curl -f http://localhost:8080/health || exit 1

# Run the binary
CMD ["./backend"]