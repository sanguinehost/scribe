#!/bin/bash

# Utility script for managing local development TLS certificates using mkcert

COMMAND=$1
PROJECT_ROOT="$(dirname "$0")/.."
CERT_DIR="$PROJECT_ROOT/.certs"
KEY_FILE="$CERT_DIR/key.pem"
CERT_FILE="$CERT_DIR/cert.pem"

# Function to print usage
usage() {
  echo "Usage: $0 {generate|check|clean}"
  echo "  generate: Ensure local CA is installed and generate cert/key for localhost."
  echo "            (Requires mkcert: https://github.com/FiloSottile/mkcert)"
  echo "  check   : Show certificate file locations and mkcert CA path."
  echo "  clean   : Remove the generated certificate files and directory."
  exit 1
}

# --- Check for mkcert ---
if ! command -v mkcert &> /dev/null; then
  echo "Error: 'mkcert' command not found." >&2
  echo "Please install mkcert first. See: https://github.com/FiloSottile/mkcert#installation" >&2
  exit 1
fi

# --- Change to project root ----
cd "$PROJECT_ROOT" || exit

# --- Handle Commands ---
case "$COMMAND" in
  generate)
    echo "Ensuring local CA is installed (may require password)..."
    # Attempt to install the local CA. This is idempotent.
    # May prompt for sudo password on first run or if CA needs updates.
    if ! mkcert -install; then
        echo "Error: Failed to install mkcert local CA." >&2
        exit 1
    fi

    echo "Generating certificate and key files in $CERT_DIR..."
    mkdir -p "$CERT_DIR"
    if ! mkcert -key-file "$KEY_FILE" -cert-file "$CERT_FILE" localhost 127.0.0.1 ::1; then
        echo "Error: Failed to generate certificates with mkcert." >&2
        # Clean up potentially partially created files
        rm -f "$KEY_FILE" "$CERT_FILE"
        exit 1
    fi

    echo "Successfully generated certificate files:"
    echo "  Key file : $KEY_FILE"
    echo "  Cert file: $CERT_FILE"
    echo ""
    echo "Configure your servers (Vite, Axum) to use these files for HTTPS."
    ;;

  check)
    echo "Checking certificate status..."
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo "Certificate files found:"
        echo "  Key file : $KEY_FILE"
        echo "  Cert file: $CERT_FILE"
        # Optionally add openssl check if available
        if command -v openssl &> /dev/null; then
            echo "  Subject   : $(openssl x509 -in "$CERT_FILE" -noout -subject -nameopt RFC2253 | sed 's/subject=//')"
            echo "  Expires   : $(openssl x509 -in "$CERT_FILE" -noout -enddate | sed 's/notAfter=//')"
        fi
    else
        echo "Certificate files not found in $CERT_DIR." >&2
        echo "Run '$0 generate' to create them." >&2
    fi
    echo ""
    echo "mkcert Local CA Root: $(mkcert -CAROOT)"
    ;;

  clean)
    echo "Removing certificate directory: $CERT_DIR..."
    if [ -d "$CERT_DIR" ]; then
        rm -rf "$CERT_DIR"
        echo "Removed."
    else
        echo "Directory not found, nothing to remove."
    fi
    ;;

  *)
    usage
    ;;
esac

echo "Done."
exit 0 