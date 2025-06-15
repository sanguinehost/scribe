#!/bin/bash
set -euo pipefail

# Generate internal certificate for backend service
# This creates a proper certificate (not self-signed) for internal communication

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../.internal-certs"

echo "Creating internal certificates directory..."
mkdir -p "$CERT_DIR"

# Generate private key
echo "Generating private key..."
openssl genrsa -out "$CERT_DIR/internal-key.pem" 2048

# Create certificate signing request configuration
cat > "$CERT_DIR/csr.conf" << EOF
[req]
default_bits = 2048
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=Cloud
L=Internal
O=Scribe
OU=Backend
CN=backend.staging.local

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = backend.staging.local
DNS.2 = staging-scribe-backend
DNS.3 = localhost
DNS.4 = backend.staging.scribe.sanguinehost.com
IP.1 = 127.0.0.1
EOF

# Generate certificate signing request
echo "Generating certificate signing request..."
openssl req -new -key "$CERT_DIR/internal-key.pem" -out "$CERT_DIR/internal.csr" -config "$CERT_DIR/csr.conf"

# Create a proper certificate (signed by a CA we create)
echo "Creating internal CA..."
openssl genrsa -out "$CERT_DIR/ca-key.pem" 2048

cat > "$CERT_DIR/ca.conf" << EOF
[req]
default_bits = 2048
prompt = no
distinguished_name = dn

[dn]
C=US
ST=Cloud
L=Internal
O=Scribe Internal CA
OU=Certificate Authority
CN=Scribe Internal CA
EOF

openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca-cert.pem" -days 365 -config "$CERT_DIR/ca.conf"

# Sign the certificate with our CA
echo "Signing certificate with internal CA..."
openssl x509 -req -in "$CERT_DIR/internal.csr" -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial -out "$CERT_DIR/internal-cert.pem" -days 365 -extensions v3_req -extfile "$CERT_DIR/csr.conf"

echo "Internal certificates generated successfully!"
echo "Certificate: $CERT_DIR/internal-cert.pem"
echo "Private key: $CERT_DIR/internal-key.pem"
echo "CA certificate: $CERT_DIR/ca-cert.pem"

# Show certificate details
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_DIR/internal-cert.pem" -text -noout | grep -A 1 "Subject:"
openssl x509 -in "$CERT_DIR/internal-cert.pem" -text -noout | grep -A 10 "Subject Alternative Name"