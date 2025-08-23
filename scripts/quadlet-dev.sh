#!/bin/bash

# Podman Quadlet management script for systemd integration
# Manages PostgreSQL and Qdrant as systemd services

set -euo pipefail

COMMAND="${1:-help}"

# Function to print usage
usage() {
    echo "Podman Quadlet Development Environment Manager"
    echo "Usage: $0 {start|stop|restart|status|enable|disable|logs|install|help}"
    echo ""
    echo "Commands:"
    echo "  start    : Start PostgreSQL and Qdrant services"
    echo "  stop     : Stop services"
    echo "  restart  : Restart services"
    echo "  status   : Show service status"
    echo "  enable   : Enable services to start on boot"
    echo "  disable  : Disable services from starting on boot"
    echo "  logs     : Show service logs"
    echo "  install  : Install Quadlet files (run once)"
    echo "  help     : Show this help message"
    echo ""
    echo "Services are managed by systemd as user services."
    echo "Containers run rootless with TLS encryption enabled."
    exit 1
}

# Check if quadlet files exist
check_quadlets() {
    QUADLET_DIR="$HOME/.config/containers/systemd"
    if [[ ! -f "$QUADLET_DIR/postgres.container" || ! -f "$QUADLET_DIR/qdrant.container" ]]; then
        echo "Error: Quadlet files not found in $QUADLET_DIR"
        echo "Run '$0 install' to install them."
        exit 1
    fi
}

# Install quadlet files
install_quadlets() {
    PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    QUADLET_DIR="$HOME/.config/containers/systemd"
    
    echo "Installing Quadlet definitions..."
    mkdir -p "$QUADLET_DIR"
    
    # Copy quadlet files from the script location to the proper systemd location
    if [[ -f "$QUADLET_DIR/postgres.container" ]]; then
        echo "✅ postgres.container already exists"
    else
        echo "❌ postgres.container not found - please ensure Quadlet files are properly created"
        exit 1
    fi
    
    if [[ -f "$QUADLET_DIR/qdrant.container" ]]; then
        echo "✅ qdrant.container already exists"
    else
        echo "❌ qdrant.container not found - please ensure Quadlet files are properly created"
        exit 1
    fi
    
    # Reload systemd to pick up new quadlet files
    echo "Reloading systemd daemon..."
    systemctl --user daemon-reload
    
    echo ""
    echo "✅ Quadlet installation complete!"
    echo "Services available:"
    echo "  • postgres.service"
    echo "  • qdrant.service"
    echo ""
    echo "Next steps:"
    echo "  $0 start    # Start services"
    echo "  $0 enable   # Enable auto-start on boot"
}

# Generate and check certificates
ensure_certs() {
    PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    CERTS_DIR="$PROJECT_ROOT/.certs"
    
    if [[ ! -f "$CERTS_DIR/cert.pem" || ! -f "$CERTS_DIR/key.pem" ]]; then
        echo "Generating TLS certificates..."
        "$PROJECT_ROOT/scripts/certs/manage.sh" local init
    fi
}

case "$COMMAND" in
    start)
        check_quadlets
        ensure_certs
        echo "Starting Quadlet services..."
        systemctl --user start postgres.service qdrant.service
        echo "✅ Services started"
        ;;
        
    stop)
        echo "Stopping Quadlet services..."
        systemctl --user stop postgres.service qdrant.service
        echo "✅ Services stopped"
        ;;
        
    restart)
        check_quadlets
        echo "Restarting Quadlet services..."
        systemctl --user restart postgres.service qdrant.service
        echo "✅ Services restarted"
        ;;
        
    status)
        echo "=== Service Status ==="
        systemctl --user status postgres.service qdrant.service --no-pager -l
        echo ""
        echo "=== Container Status ==="
        podman ps --filter name=scribe_postgres_quadlet --filter name=scribe_qdrant_quadlet
        ;;
        
    enable)
        check_quadlets
        echo "Enabling Quadlet services for auto-start..."
        systemctl --user enable postgres.service qdrant.service
        echo "✅ Services enabled - will start automatically on login"
        ;;
        
    disable)
        echo "Disabling Quadlet services..."
        systemctl --user disable postgres.service qdrant.service
        echo "✅ Services disabled"
        ;;
        
    logs)
        echo "=== PostgreSQL Logs ==="
        systemctl --user --no-pager -l logs postgres.service
        echo ""
        echo "=== Qdrant Logs ==="
        systemctl --user --no-pager -l logs qdrant.service
        ;;
        
    install)
        install_quadlets
        ;;
        
    help|--help|-h)
        usage
        ;;
        
    *)
        echo "Error: Unknown command '$COMMAND'"
        echo ""
        usage
        ;;
esac