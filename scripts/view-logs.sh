#!/bin/bash
set -euo pipefail

# View CloudWatch logs for Scribe ECS services
# This script provides an easy way to tail logs from the staging environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION=${AWS_REGION:-us-east-1}
ENVIRONMENT=${ENVIRONMENT:-staging}
LOG_GROUP_BACKEND="/ecs/${ENVIRONMENT}-scribe-backend"
LOG_GROUP_QDRANT="/ecs/${ENVIRONMENT}-scribe-qdrant"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Please run 'aws configure' or set environment variables."
        exit 1
    fi
}

# List available log streams
list_log_streams() {
    local log_group=$1
    local service_name=$2
    
    log_info "Available log streams for $service_name:"
    aws logs describe-log-streams \
        --log-group-name "$log_group" \
        --order-by LastEventTime \
        --descending \
        --limit 5 \
        --query 'logStreams[*].[logStreamName,lastEventTime]' \
        --output table \
        --region "$AWS_REGION" 2>/dev/null || {
            log_error "Failed to list log streams. The log group may not exist yet."
            return 1
        }
}

# Tail logs from a specific service
tail_logs() {
    local log_group=$1
    local service_name=$2
    local follow=${3:-true}
    
    log_info "Tailing logs for $service_name..."
    log_info "Log group: $log_group"
    log_info "Press Ctrl+C to stop"
    echo ""
    
    if [ "$follow" = "true" ]; then
        # Follow logs in real-time
        aws logs tail "$log_group" \
            --follow \
            --region "$AWS_REGION" \
            --format short
    else
        # Show recent logs without following
        aws logs tail "$log_group" \
            --region "$AWS_REGION" \
            --format short \
            --since 10m
    fi
}

# Get logs for a specific time range
get_logs_range() {
    local log_group=$1
    local service_name=$2
    local start_time=$3
    local end_time=${4:-$(date +%s)000}
    
    log_info "Getting logs for $service_name from $(date -d @$((start_time/1000))) to $(date -d @$((end_time/1000)))"
    
    aws logs filter-log-events \
        --log-group-name "$log_group" \
        --start-time "$start_time" \
        --end-time "$end_time" \
        --region "$AWS_REGION" \
        --query 'events[*].[timestamp,message]' \
        --output text | while IFS=$'\t' read -r timestamp message; do
            echo "[$(date -d @$((timestamp/1000)) '+%Y-%m-%d %H:%M:%S')] $message"
        done
}

# Search logs for specific pattern
search_logs() {
    local log_group=$1
    local service_name=$2
    local pattern=$3
    local hours_back=${4:-1}
    
    local start_time=$(($(date +%s) - hours_back * 3600))000
    
    log_info "Searching $service_name logs for pattern: '$pattern' (last $hours_back hours)"
    
    aws logs filter-log-events \
        --log-group-name "$log_group" \
        --start-time "$start_time" \
        --filter-pattern "$pattern" \
        --region "$AWS_REGION" \
        --query 'events[*].[timestamp,message]' \
        --output text | while IFS=$'\t' read -r timestamp message; do
            echo "[$(date -d @$((timestamp/1000)) '+%Y-%m-%d %H:%M:%S')] $message"
        done
}

# Show usage
usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  tail <service>       - Tail logs in real-time (service: backend, qdrant, all)"
    echo "  recent <service>     - Show recent logs without following"
    echo "  list <service>       - List available log streams"
    echo "  search <service> <pattern> [hours] - Search logs for pattern (default: last 1 hour)"
    echo "  help                 - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 tail backend      - Tail backend logs"
    echo "  $0 tail all          - Tail all service logs"
    echo "  $0 recent backend    - Show recent backend logs"
    echo "  $0 search backend ERROR 24  - Search for ERROR in last 24 hours"
    echo "  $0 list backend      - List backend log streams"
    echo ""
    echo "Environment variables:"
    echo "  AWS_REGION          - AWS region (default: us-east-1)"
    echo "  ENVIRONMENT         - Environment name (default: staging)"
}

# Main execution
main() {
    check_prerequisites
    
    case "${1:-help}" in
        "tail")
            case "${2:-all}" in
                "backend")
                    tail_logs "$LOG_GROUP_BACKEND" "Backend"
                    ;;
                "qdrant")
                    tail_logs "$LOG_GROUP_QDRANT" "Qdrant"
                    ;;
                "all")
                    # Tail both services (requires multiplexing)
                    log_info "Tailing all services..."
                    log_warning "Note: For better experience, run separate terminals for each service"
                    echo ""
                    # Use AWS CLI's multi-log-group tailing
                    aws logs tail "$LOG_GROUP_BACKEND" "$LOG_GROUP_QDRANT" \
                        --follow \
                        --region "$AWS_REGION" \
                        --format short
                    ;;
                *)
                    log_error "Unknown service: ${2}. Use: backend, qdrant, or all"
                    exit 1
                    ;;
            esac
            ;;
        "recent")
            case "${2:-all}" in
                "backend")
                    tail_logs "$LOG_GROUP_BACKEND" "Backend" false
                    ;;
                "qdrant")
                    tail_logs "$LOG_GROUP_QDRANT" "Qdrant" false
                    ;;
                "all")
                    log_info "Recent logs from all services:"
                    echo "=== BACKEND ==="
                    tail_logs "$LOG_GROUP_BACKEND" "Backend" false
                    echo ""
                    echo "=== QDRANT ==="
                    tail_logs "$LOG_GROUP_QDRANT" "Qdrant" false
                    ;;
                *)
                    log_error "Unknown service: ${2}. Use: backend, qdrant, or all"
                    exit 1
                    ;;
            esac
            ;;
        "list")
            case "${2:-all}" in
                "backend")
                    list_log_streams "$LOG_GROUP_BACKEND" "Backend"
                    ;;
                "qdrant")
                    list_log_streams "$LOG_GROUP_QDRANT" "Qdrant"
                    ;;
                "all")
                    list_log_streams "$LOG_GROUP_BACKEND" "Backend"
                    echo ""
                    list_log_streams "$LOG_GROUP_QDRANT" "Qdrant"
                    ;;
                *)
                    log_error "Unknown service: ${2}. Use: backend, qdrant, or all"
                    exit 1
                    ;;
            esac
            ;;
        "search")
            if [ $# -lt 3 ]; then
                log_error "Search requires service and pattern arguments"
                echo "Usage: $0 search <service> <pattern> [hours]"
                exit 1
            fi
            
            local hours=${4:-1}
            case "${2}" in
                "backend")
                    search_logs "$LOG_GROUP_BACKEND" "Backend" "$3" "$hours"
                    ;;
                "qdrant")
                    search_logs "$LOG_GROUP_QDRANT" "Qdrant" "$3" "$hours"
                    ;;
                "all")
                    log_info "Searching all services:"
                    echo "=== BACKEND ==="
                    search_logs "$LOG_GROUP_BACKEND" "Backend" "$3" "$hours"
                    echo ""
                    echo "=== QDRANT ==="
                    search_logs "$LOG_GROUP_QDRANT" "Qdrant" "$3" "$hours"
                    ;;
                *)
                    log_error "Unknown service: ${2}. Use: backend, qdrant, or all"
                    exit 1
                    ;;
            esac
            ;;
        "help"|*)
            usage
            ;;
    esac
}

# Run main with all arguments
main "$@"