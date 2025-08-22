#!/bin/bash

# Generate TLS certificates for local backend development
# These certificates are owned by your user (not containers)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DEV_DIR="$PROJECT_ROOT/.certs-dev"

echo "🔐 Generating TLS certificates for local backend development..."

# Create .certs-dev directory
mkdir -p "$CERTS_DEV_DIR"

# Check if mkcert is available
if ! command -v mkcert &>/dev/null; then
    echo "❌ Error: mkcert not found"
    echo "Please install mkcert:"
    echo "  • Arch Linux: sudo pacman -S mkcert"
    echo "  • Ubuntu/Debian: sudo apt install mkcert"
    echo "  • macOS: brew install mkcert"
    echo "  • Or download from: https://github.com/FiloSottile/mkcert"
    exit 1
fi

# Generate certificates
echo "📜 Generating certificates for localhost development..."
cd "$PROJECT_ROOT"

mkcert -cert-file "$CERTS_DEV_DIR/cert.pem" \
       -key-file "$CERTS_DEV_DIR/key.pem" \
       localhost 127.0.0.1 ::1

# Verify ownership
echo "✅ Verifying certificate ownership..."
ls -la "$CERTS_DEV_DIR/"

echo ""
echo "🎉 Developer certificates generated successfully!"
echo "📁 Location: $CERTS_DEV_DIR/"
echo "🔑 Owned by: $(whoami)"
echo ""
echo "These certificates are for local backend development only."
echo "Containers continue to use certificates in .certs/ directory."
echo ""
echo "Next steps:"
echo "  1. Your .env file should already point to these certificates"
echo "  2. Run 'cargo run' from the backend directory"
echo "  3. Your backend will use these developer-owned certificates"