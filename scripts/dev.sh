#!/bin/bash

# Unified Sanguine Scribe Development Environment Manager
# Modern container orchestration with Podman-first approach (2025)
#
# Three deployment strategies:
#   1. Compose: Quick development workflows (up/down cycles)
#   2. Quadlet: Persistent systemd-managed services  
#   3. Legacy: Docker compatibility fallback

set -euo pipefail

STRATEGY="${1:-help}"
COMMAND="${2:-help}"

# Project paths
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Function to print usage
usage() {
    cat << 'EOF'
🚀 Sanguine Scribe Development Environment Manager

Usage: ./scripts/dev.sh {compose|quadlet|legacy} [command]

DEPLOYMENT STRATEGIES:

📦 compose [up|down|logs|ps]
    Modern Podman with docker-compose backend
    • Rootless containers with TLS encryption
    • Quick up/down for development cycles
    • Uses: podman compose (not deprecated podman-compose)

⚙️  quadlet [start|stop|status|enable|logs]
    Systemd-managed containers via Podman Quadlets
    • Persistent services that survive reboots
    • Better integration with system services
    • Ideal for long-running development infrastructure

🐋 legacy [up|down|logs|ps]  
    Docker Compose compatibility fallback
    • For systems without Podman
    • Maintains existing docker-compose.yml workflows
    • Less secure (requires root or docker group)

EXAMPLES:
  ./scripts/dev.sh compose up     # Start with modern Podman
  ./scripts/dev.sh quadlet start  # Start as systemd services
  ./scripts/dev.sh legacy up      # Use Docker as fallback

QUICK COMMANDS:
  ./scripts/dev.sh certs          # Generate TLS certificates
  ./scripts/dev.sh status         # Show all container status
  ./scripts/dev.sh help           # Show this help

INDIVIDUAL TOOLS (also available):
  ./scripts/podman-dev.sh         # Modern Podman workflow
  ./scripts/quadlet-dev.sh        # Systemd Quadlet management
  ./scripts/dev_db.sh             # Legacy script (updated for Podman)

🛡️  All approaches use TLS encryption by default for security.
EOF
    exit 1
}

# Detect available container runtimes
detect_runtime() {
    if command -v podman &>/dev/null; then
        echo "podman"
    elif command -v docker &>/dev/null; then
        echo "docker" 
    else
        echo "none"
    fi
}

# Status check for all approaches
show_status() {
    echo -e "${BLUE}=== Container Runtime Status ===${NC}"
    RUNTIME=$(detect_runtime)
    case "$RUNTIME" in
        podman)
            echo -e "✅ ${GREEN}Podman available${NC} (recommended)"
            if command -v docker-compose &>/dev/null; then
                echo -e "✅ ${GREEN}docker-compose available${NC} (for podman compose)"
            elif command -v podman-compose &>/dev/null; then
                echo -e "⚠️  ${YELLOW}podman-compose available${NC} (deprecated)"
            fi
            ;;
        docker)
            echo -e "⚠️  ${YELLOW}Docker available${NC} (fallback mode)"
            ;;
        none)
            echo -e "❌ ${RED}No container runtime found${NC}"
            echo "Install: podman (recommended) or docker"
            return 1
            ;;
    esac
    
    echo ""
    echo -e "${BLUE}=== Running Containers ===${NC}"
    
    # Check for running containers with various approaches
    if command -v podman &>/dev/null; then
        echo "Podman containers:"
        podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "No podman containers running"
    fi
    
    if command -v docker &>/dev/null; then
        echo "Docker containers:"  
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "No docker containers running"
    fi
    
    echo ""
    echo -e "${BLUE}=== Systemd Services (Quadlets) ===${NC}"
    if systemctl --user is-active postgres.service &>/dev/null; then
        echo -e "PostgreSQL: ${GREEN}active${NC}"
    else
        echo -e "PostgreSQL: ${RED}inactive${NC}"
    fi
    
    if systemctl --user is-active qdrant.service &>/dev/null; then
        echo -e "Qdrant: ${GREEN}active${NC}"
    else
        echo -e "Qdrant: ${RED}inactive${NC}"
    fi
}

# Generate certificates
generate_certs() {
    echo -e "${BLUE}=== Generating TLS Certificates ===${NC}"
    "$PROJECT_ROOT/scripts/dev_certs.sh" generate
}

# Main command routing
case "$STRATEGY" in
    compose)
        echo -e "${GREEN}🐧 Using Modern Podman Compose Strategy${NC}"
        "$PROJECT_ROOT/scripts/podman-dev.sh" "${COMMAND:-up}"
        ;;
        
    quadlet)
        echo -e "${GREEN}⚙️ Using Systemd Quadlet Strategy${NC}"
        "$PROJECT_ROOT/scripts/quadlet-dev.sh" "${COMMAND:-start}"
        ;;
        
    legacy) 
        echo -e "${YELLOW}🐋 Using Legacy Docker Strategy${NC}"
        echo "Note: Consider migrating to 'compose' strategy for better security"
        "$PROJECT_ROOT/scripts/dev_db.sh" "${COMMAND:-up}"
        ;;
        
    certs)
        generate_certs
        ;;
        
    status)
        show_status
        ;;
        
    help|--help|-h)
        usage
        ;;
        
    *)
        if [[ -n "${STRATEGY:-}" ]]; then
            echo -e "${RED}Error: Unknown strategy '$STRATEGY'${NC}"
            echo ""
        fi
        usage
        ;;
esac