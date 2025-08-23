#!/bin/bash

# Log Viewing Utility
# Views logs from different deployment scenarios

set -euo pipefail

COMMAND="${1:-containers}"
SERVICE="${2:-all}"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE_DIR="$PROJECT_ROOT/infrastructure/containers/compose"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo "Log Viewing Utility"
    echo "Usage: $0 {containers|quadlet|aws} [service]"
    echo ""
    echo "Commands:"
    echo "  containers       - View container logs (podman compose)"
    echo "  quadlet         - View systemd quadlet service logs"
    echo "  aws             - View AWS ECS service logs"
    echo ""
    echo "Services (for containers/quadlet):"
    echo "  all             - All services (default)"
    echo "  postgres        - PostgreSQL logs only"
    echo "  qdrant          - Qdrant logs only"
    echo "  backend         - Backend logs only"
    exit 1
}

setup_podman_env() {
    if ! command -v podman &>/dev/null; then
        echo "Error: podman not found." >&2
        exit 1
    fi

    systemctl --user start podman.socket
    export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
    
    if command -v docker-compose &>/dev/null; then
        export PODMAN_COMPOSE_PROVIDER="docker-compose"
    elif command -v podman-compose &>/dev/null; then
        export PODMAN_COMPOSE_PROVIDER="podman-compose"
    else
        echo "Error: No compose provider found." >&2
        exit 1
    fi
}

case "$COMMAND" in
    containers)
        echo -e "${GREEN}📋 Viewing container logs${NC}"
        setup_podman_env
        
        if [[ "$SERVICE" == "all" ]]; then
            echo -e "${BLUE}Following all container logs...${NC}"
            podman compose \
                -f "$COMPOSE_DIR/podman-compose.yml" \
                -f "$COMPOSE_DIR/podman-compose.local.yml" \
                logs -f
        else
            echo -e "${BLUE}Following logs for: $SERVICE${NC}"
            podman compose \
                -f "$COMPOSE_DIR/podman-compose.yml" \
                -f "$COMPOSE_DIR/podman-compose.local.yml" \
                logs -f "$SERVICE"
        fi
        ;;
        
    quadlet)
        echo -e "${GREEN}📋 Viewing systemd quadlet logs${NC}"
        
        case "$SERVICE" in
            all)
                echo -e "${BLUE}PostgreSQL logs:${NC}"
                journalctl --user -u postgres.service -f --no-pager &
                PG_PID=$!
                
                echo -e "${BLUE}Qdrant logs:${NC}"
                journalctl --user -u qdrant.service -f --no-pager &
                QD_PID=$!
                
                # Wait for interrupt
                trap "kill $PG_PID $QD_PID 2>/dev/null" EXIT
                wait
                ;;
            postgres)
                echo -e "${BLUE}Following PostgreSQL logs...${NC}"
                journalctl --user -u postgres.service -f --no-pager
                ;;
            qdrant)
                echo -e "${BLUE}Following Qdrant logs...${NC}"
                journalctl --user -u qdrant.service -f --no-pager
                ;;
            *)
                echo "Error: Unknown service '$SERVICE' for quadlet logs"
                echo "Available services: all, postgres, qdrant"
                exit 1
                ;;
        esac
        ;;
        
    aws)
        echo -e "${GREEN}📋 Viewing AWS ECS logs${NC}"
        
        if [[ -f "$PROJECT_ROOT/scripts/view-logs.sh" ]]; then
            exec "$PROJECT_ROOT/scripts/view-logs.sh"
        elif [[ -f "$PROJECT_ROOT/infrastructure/scripts/deploy/view-logs.sh" ]]; then
            exec "$PROJECT_ROOT/infrastructure/scripts/deploy/view-logs.sh"
        else
            echo -e "${BLUE}Using AWS CLI to view logs...${NC}"
            
            if ! command -v aws &>/dev/null; then
                echo "Error: AWS CLI not found" >&2
                exit 1
            fi
            
            # Get recent log events
            aws logs describe-log-groups --query 'logGroups[?starts_with(logGroupName, `/ecs/staging-scribe`)].logGroupName' --output text | \
            while read -r log_group; do
                if [[ -n "$log_group" ]]; then
                    echo -e "${BLUE}Logs from $log_group:${NC}"
                    aws logs tail "$log_group" --follow
                fi
            done
        fi
        ;;
        
    help|--help|-h)
        usage
        ;;
        
    *)
        echo "Error: Unknown command '$COMMAND'"
        usage
        ;;
esac