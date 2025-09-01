#!/bin/bash
# backend/scripts/test-llm-security.sh
# Test script for LLM security tests with automatic llama-server management

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"

# Default values (can be overridden by environment)
LLAMA_SERVER_PATH="${LLAMA_SERVER_PATH:-/home/socol/Workspace/llama.cpp/build/bin/llama-server}"
MODEL_PATH="${LLAMACPP_MODEL_PATH:-/home/socol/Workspace/sanguine-scribe/models/gpt-oss-20b-Q4_K_M.gguf}"
SERVER_HOST="${LLAMACPP_SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${LLAMACPP_SERVER_PORT:-11435}"
CONTEXT_SIZE="${LLAMACPP_CONTEXT_SIZE:-131072}"
GPU_LAYERS="${LLAMACPP_GPU_LAYERS:-999}"
THREADS="${LLAMACPP_THREADS:-8}"

# Test configuration
MAX_WAIT_TIME=60
HEALTH_CHECK_INTERVAL=2

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    if [[ -n "${LLAMA_PID:-}" ]] && kill -0 "$LLAMA_PID" 2>/dev/null; then
        log_info "Stopping llama-server (PID: $LLAMA_PID)..."
        kill "$LLAMA_PID" 2>/dev/null || true
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$LLAMA_PID" 2>/dev/null && [[ $count -lt 10 ]]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$LLAMA_PID" 2>/dev/null; then
            log_warning "Force killing llama-server..."
            kill -9 "$LLAMA_PID" 2>/dev/null || true
        fi
        
        log_success "llama-server stopped"
    fi
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    # Check if llama-server exists
    if [[ ! -f "$LLAMA_SERVER_PATH" ]]; then
        log_error "llama-server not found at: $LLAMA_SERVER_PATH"
        log_error "Please build llama.cpp first or set LLAMA_SERVER_PATH environment variable"
        exit 1
    fi
    
    # Check if model file exists
    if [[ ! -f "$MODEL_PATH" ]]; then
        log_error "Model file not found at: $MODEL_PATH"
        log_error "Please download a GGUF model or set LLAMACPP_MODEL_PATH environment variable"
        exit 1
    fi
    
    # Check if port is available
    if lsof -Pi ":$SERVER_PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_error "Port $SERVER_PORT is already in use"
        log_error "Please stop the service using this port or change LLAMACPP_SERVER_PORT"
        exit 1
    fi
    
    # Check if cargo is available
    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Please install Rust"
        exit 1
    fi
    
    log_success "All prerequisites validated"
}

# Start llama-server
start_llama_server() {
    log_info "Starting llama-server..."
    log_info "Model: $MODEL_PATH"
    log_info "Host: $SERVER_HOST:$SERVER_PORT"
    log_info "Context: $CONTEXT_SIZE, GPU Layers: $GPU_LAYERS, Threads: $THREADS"
    
    # Build command
    local cmd=(
        "$LLAMA_SERVER_PATH"
        "--model" "$MODEL_PATH"
        "--host" "$SERVER_HOST"
        "--port" "$SERVER_PORT"
        "--ctx-size" "$CONTEXT_SIZE"
        "--n-gpu-layers" "$GPU_LAYERS"
        "--threads" "$THREADS"
        "--parallel" "2"
        "--cont-batching"
        "--metrics"
        "--verbose"
    )
    
    log_info "Command: ${cmd[*]}"
    
    # Start server in background
    "${cmd[@]}" > /tmp/llama-server.log 2>&1 &
    LLAMA_PID=$!
    
    log_info "llama-server started with PID: $LLAMA_PID"
    log_info "Log file: /tmp/llama-server.log"
    
    # Wait for server to be ready
    wait_for_server_ready
}

# Wait for server to be ready
wait_for_server_ready() {
    log_info "Waiting for llama-server to be ready..."
    
    local count=0
    local max_count=$((MAX_WAIT_TIME / HEALTH_CHECK_INTERVAL))
    
    while [[ $count -lt $max_count ]]; do
        if check_server_health; then
            log_success "llama-server is ready!"
            return 0
        fi
        
        # Check if process is still running
        if ! kill -0 "$LLAMA_PID" 2>/dev/null; then
            log_error "llama-server process died. Check logs at /tmp/llama-server.log"
            tail -20 /tmp/llama-server.log
            exit 1
        fi
        
        echo -n "."
        sleep $HEALTH_CHECK_INTERVAL
        ((count++))
    done
    
    echo ""
    log_error "Timeout waiting for llama-server to be ready"
    log_error "Check logs at /tmp/llama-server.log"
    tail -20 /tmp/llama-server.log
    exit 1
}

# Check server health
check_server_health() {
    curl -s "http://$SERVER_HOST:$SERVER_PORT/health" >/dev/null 2>&1
}

# Run security tests
run_security_tests() {
    log_info "Running LLM security tests..."
    
    cd "$BACKEND_DIR"
    
    # Build with local-llm feature first
    log_info "Building backend with local-llm feature..."
    if ! cargo build --features local-llm --release; then
        log_error "Failed to build backend with local-llm feature"
        exit 1
    fi
    
    log_success "Build completed"
    
    # Run the specific security tests
    log_info "Running security tests..."
    
    # Set environment variables for tests
    export LLAMACPP_SERVER_HOST="$SERVER_HOST"
    export LLAMACPP_SERVER_PORT="$SERVER_PORT"
    export RUN_LLM_TESTS=true
    
    # Run tests with local-llm feature
    if cargo test --features local-llm --test llm_security_tests -- --nocapture; then
        log_success "All security tests passed!"
        return 0
    else
        log_error "Some security tests failed"
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting LLM Security Test Pipeline"
    log_info "=================================="
    
    # Load environment from .env file if it exists
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        log_info "Loading environment from .env file..."
        set -a
        source "$PROJECT_ROOT/.env"
        set +a
    fi
    
    validate_prerequisites
    start_llama_server
    
    # Run tests
    if run_security_tests; then
        log_success "LLM Security Test Pipeline completed successfully!"
        exit 0
    else
        log_error "LLM Security Test Pipeline failed!"
        exit 1
    fi
}

# Show usage
show_usage() {
    cat << EOF
LLM Security Test Script

Usage: $0 [OPTIONS]

This script automatically manages llama-server lifecycle and runs LLM security tests.

Environment Variables:
    LLAMA_SERVER_PATH      Path to llama-server binary (default: /home/socol/Workspace/llama.cpp/build/bin/llama-server)
    LLAMACPP_MODEL_PATH    Path to GGUF model file (default: /home/socol/Workspace/sanguine-scribe/models/gpt-oss-20b-Q4_K_M.gguf)
    LLAMACPP_SERVER_HOST   Server host (default: 127.0.0.1)
    LLAMACPP_SERVER_PORT   Server port (default: 11435)
    LLAMACPP_CONTEXT_SIZE  Context size (default: 131072)
    LLAMACPP_GPU_LAYERS    GPU layers (default: 999)
    LLAMACPP_THREADS       Number of threads (default: 8)

Examples:
    # Run with defaults
    $0
    
    # Run with different model
    LLAMACPP_MODEL_PATH=/path/to/model.gguf $0
    
    # Run with different port
    LLAMACPP_SERVER_PORT=8080 $0

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Run main function
main "$@"