#!/usr/bin/env bash
#
# Scribe Desktop - Development Build Script
#
# This script orchestrates the complete desktop build pipeline:
# 1. Clean stale build artifacts (frontend/backend/binaries)
# 2. Frontend build (SvelteKit static adapter with desktop config)
# 3. Backend binary (Rust with desktop features: SQLite + LanceDB)
# 4. Binary placement for Tauri sidecar
# 5. Validation and Tauri dev server startup (optional)
#
# Usage: ./scripts/build-desktop-dev.sh [--clean] [--skip-backend] [--no-rebuild] [--run|--open] [--check]
#
# Options:
#   --clean         Full clean rebuild (removes all Cargo cache - slow but thorough)
#                   Use when switching features or if cargo gets confused
#   --skip-backend  Skip backend compilation (only rebuild frontend)
#   --no-rebuild    Skip both frontend and backend compilation (just run existing binaries)
#   --run/--open    Start the Tauri dev server after building
#   --check         Run cargo check instead of cargo build (fast verification)
#
# Default: Incremental rebuild (fast, only recompiles changed files)
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}==> $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

# Disable aws-lc-sys assembly optimizations to avoid assembler compatibility issues
export AWS_LC_SYS_NO_ASM=1

# Use stable protoc if systems one is broken
if [ -z "${PROTOC:-}" ] && [ -f "/tmp/protoc_stable/bin/protoc" ]; then
    export PROTOC="/tmp/protoc_stable/bin/protoc"
    log_info "Using local stable protoc: $PROTOC"
fi

# Parse command line flags
CLEAN_BUILD=false
SKIP_BACKEND=false
SKIP_FRONTEND=false
RUN_APP=false
CHECK_ONLY=false
LOG_LEVEL="info"
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --skip-backend)
            SKIP_BACKEND=true
            shift
            ;;
        --no-rebuild)
            SKIP_BACKEND=true
            SKIP_FRONTEND=true
            shift
            ;;
        --log-level=*)
            LOG_LEVEL="${arg#*=}"
            shift
            ;;
        --run|--open)
            RUN_APP=true
            shift
            ;;
        --skip-frontend)
            SKIP_FRONTEND=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--clean] [--skip-backend] [--run|--open] [--check]"
            exit 1
            ;;
    esac
done

# Colors for output


# Determine project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ "$SKIP_FRONTEND" = true ] && [ "$SKIP_BACKEND" = true ]; then
    log_info "Running Scribe Desktop (Development Mode - NO REBUILD)"
elif [ "$SKIP_BACKEND" = true ]; then
    log_info "Building Scribe Desktop (Development Mode - FRONTEND ONLY)"
elif [ "$CLEAN_BUILD" = true ]; then
    log_info "Building Scribe Desktop (Development Mode - FULL CLEAN REBUILD)"
else
    log_info "Building Scribe Desktop (Development Mode - INCREMENTAL REBUILD)"
fi
echo "Project root: $PROJECT_ROOT"
echo ""

# Step 1: Validate prerequisites
log_info "Step 1/6: Validating prerequisites..."

command -v pnpm >/dev/null 2>&1 || {
    log_error "pnpm not found. Install with: npm install -g pnpm"
    exit 1
}
log_success "pnpm: $(pnpm --version)"

command -v cargo >/dev/null 2>&1 || {
    log_error "cargo not found. Install Rust from: https://rustup.rs"
    exit 1
}
log_success "cargo: $(cargo --version | cut -d' ' -f2)"

command -v rustc >/dev/null 2>&1 || {
    log_error "rustc not found. Install Rust from: https://rustup.rs"
    exit 1
}
log_success "rustc: $(rustc --version | cut -d' ' -f2)"

# Detect platform
RUST_TARGET=$(rustc -vV | grep host | cut -f2 -d' ')
log_success "Platform detected: $RUST_TARGET"

echo ""

# Step 2: Clean stale build artifacts
log_info "Step 2/7: Cleaning stale build artifacts..."

# Clean frontend build artifacts only if we are building frontend
if [ "$SKIP_FRONTEND" = false ]; then
    if [ -d "$PROJECT_ROOT/frontend/build" ]; then
        log_info "Removing frontend build directory..."
        rm -rf "$PROJECT_ROOT/frontend/build"
        log_success "Cleaned: frontend/build/"
    fi

    if [ -d "$PROJECT_ROOT/frontend/.svelte-kit" ]; then
        log_info "Removing frontend .svelte-kit directory..."
        rm -rf "$PROJECT_ROOT/frontend/.svelte-kit"
        log_success "Cleaned: frontend/.svelte-kit/"
    fi
else
    log_info "Skipping frontend clean (--no-rebuild flag set)"
fi

# Clean backend artifacts based on flags
if [ "$SKIP_BACKEND" = false ]; then
    if [ "$CLEAN_BUILD" = true ]; then
        # Full clean: Remove entire Cargo target directory
        if [ -d "$PROJECT_ROOT/target" ]; then
            log_info "FULL CLEAN: Removing entire Cargo target directory..."
            BEFORE_SIZE=$(du -sh "$PROJECT_ROOT/target" 2>/dev/null | cut -f1 || echo "unknown")
            rm -rf "$PROJECT_ROOT/target"
            log_success "Cleaned: target/ (was $BEFORE_SIZE)"
        fi
    else
        # Incremental: Just clean the desktop binary to force Tauri to pick up new one
        if [ -f "$PROJECT_ROOT/target/debug/scribe-backend" ]; then
            log_info "Removing backend binary for clean placement..."
            rm -f "$PROJECT_ROOT/target/debug/scribe-backend"
            log_success "Cleaned: target/debug/scribe-backend"
        fi
    fi

    # Always clean desktop binaries directory when building backend
    if [ -d "$PROJECT_ROOT/desktop/binaries" ]; then
        log_info "Removing desktop binaries directory..."
        rm -rf "$PROJECT_ROOT/desktop/binaries"
        log_success "Cleaned: desktop/binaries/"
    fi
else
    log_info "Skipping backend clean (--skip-backend flag set)"
fi

log_success "All stale artifacts cleaned successfully"
echo ""

# Step 3: Build frontend for desktop
log_info "Step 3/7: Building frontend with desktop configuration..."

if [ "$SKIP_FRONTEND" = false ]; then
    cd "$PROJECT_ROOT/frontend"

    if [ ! -f "package.json" ]; then
        log_error "frontend/package.json not found"
        exit 1
    fi

    # Run the desktop build script
    if [ ! -f "build-desktop.sh" ]; then
        log_error "frontend/build-desktop.sh not found"
        exit 1
    fi

    log_info "Running pnpm run build:desktop..."
    pnpm run build:desktop

    # Verify frontend build output
    if [ ! -f "$PROJECT_ROOT/frontend/build/index.html" ]; then
        log_error "Frontend build failed - index.html not found at frontend/build/index.html"
        exit 1
    fi

    log_success "Frontend build successful → frontend/build/"
else
    log_info "Skipping frontend build (--no-rebuild flag set)"
fi
echo ""

# Step 4: Build backend binary with desktop features (or skip if requested)
if [ "$SKIP_BACKEND" = false ]; then
    log_info "Step 4/7: Building backend binary with desktop features (SQLite + LanceDB)..."

    cd "$PROJECT_ROOT"

    if [ "$CHECK_ONLY" = true ]; then
        log_info "Running: cargo check -p scribe-backend --no-default-features --features desktop"
        cargo check -p scribe-backend \
            --no-default-features \
            --features desktop \
            --message-format=short
        log_success "Backend check successful"
        exit 0
    fi

    log_info "Running: cargo build -p scribe-backend --no-default-features --features desktop --bin scribe-backend"
    cargo build -p scribe-backend \
        --no-default-features \
        --features desktop \
        --bin scribe-backend \
        --message-format=short

    # Verify backend binary exists
    if [ ! -f "$PROJECT_ROOT/target/debug/scribe-backend" ]; then
        log_error "Backend build failed - binary not found at target/debug/scribe-backend"
        exit 1
    fi

    BINARY_SIZE=$(du -h "$PROJECT_ROOT/target/debug/scribe-backend" | cut -f1)
    log_success "Backend build successful → target/debug/scribe-backend ($BINARY_SIZE)"
    echo ""

    # Step 5: Copy backend binary to Tauri binaries directory
    log_info "Step 5/7: Copying backend binary to Tauri binaries directory..."

    mkdir -p "$PROJECT_ROOT/desktop/binaries"

    # Copy with platform-specific name
    PLATFORM_BINARY="$PROJECT_ROOT/desktop/binaries/scribe-backend-${RUST_TARGET}"
    cp "$PROJECT_ROOT/target/debug/scribe-backend" "$PLATFORM_BINARY"
    log_success "Binary copied to: desktop/binaries/scribe-backend-${RUST_TARGET}"

    # Create symlink for backwards compatibility (in case tauri.conf.json uses generic name)
    GENERIC_BINARY="$PROJECT_ROOT/desktop/binaries/scribe-backend"
    ln -sf "scribe-backend-${RUST_TARGET}" "$GENERIC_BINARY"
    log_success "Symlink created: desktop/binaries/scribe-backend → scribe-backend-${RUST_TARGET}"
    echo ""
else
    log_info "Step 4/7: Skipping backend build (--skip-backend flag set)"
    log_info "Step 5/7: Skipping backend binary copy (--skip-backend flag set)"
    echo ""

    # Set PLATFORM_BINARY for later verification
    PLATFORM_BINARY="$PROJECT_ROOT/desktop/binaries/scribe-backend-${RUST_TARGET}"
fi

# Step 6: Verify all prerequisites
log_info "Step 6/7: Verifying build artifacts..."

# Check frontend build
if [ ! -d "$PROJECT_ROOT/frontend/build" ]; then
    log_error "Frontend build directory missing: frontend/build/"
    exit 1
fi
log_success "Frontend build directory exists"

# Check backend binary (platform-specific)
if [ ! -f "$PLATFORM_BINARY" ]; then
    log_error "Backend binary missing: desktop/binaries/scribe-backend-${RUST_TARGET}"
    exit 1
fi
log_success "Backend binary exists (platform-specific)"

# Verify backend was built with correct features (should link to libsqlite3)
if ldd "$PLATFORM_BINARY" 2>/dev/null | grep -q "libsqlite3"; then
    log_success "Backend correctly linked to SQLite"
elif command -v otool >/dev/null 2>&1; then
    # macOS
    if otool -L "$PLATFORM_BINARY" 2>/dev/null | grep -q "libsqlite3"; then
        log_success "Backend correctly linked to SQLite (macOS)"
    else
        log_warn "Cannot verify SQLite linkage (macOS otool check inconclusive)"
    fi
else
    log_warn "Cannot verify SQLite linkage (ldd/otool not available)"
fi

echo ""

# Step 7: Start Tauri dev server (optional)
if [ "$RUN_APP" = true ]; then
    log_info "Step 7/7: Starting Tauri desktop app..."

    cd "$PROJECT_ROOT/desktop"

    # Set required environment variables
    export WEBKIT_DISABLE_DMABUF_RENDERER=1  # Required for Linux WebKitGTK

    # Load GEMINI_API_KEY from .env file if it exists and not already set
    if [ -z "${GEMINI_API_KEY:-}" ] && [ -f "$PROJECT_ROOT/.env" ]; then
        # Extract GEMINI_API_KEY from .env file
        GEMINI_API_KEY=$(grep '^GEMINI_API_KEY=' "$PROJECT_ROOT/.env" | cut -d '=' -f2-)
        if [ -n "$GEMINI_API_KEY" ]; then
            export GEMINI_API_KEY
            log_success "Loaded GEMINI_API_KEY from .env file"
        fi
    fi

    # Pass GEMINI_API_KEY if set in environment
    if [ -z "${GEMINI_API_KEY:-}" ]; then
        log_warn "GEMINI_API_KEY not set - AI features will not work"
        log_warn "Set it with: export GEMINI_API_KEY=\"your-key-here\" or add to .env file"
    fi

    log_info "Starting cargo tauri dev..."
    log_info "Note: First build may take several minutes..."
    echo ""

    export RUST_LOG="$LOG_LEVEL"
    log_info "Setting RUST_LOG=$RUST_LOG"

    TAURI_ARGS=""
    if [ "$SKIP_BACKEND" = true ] && [ "$SKIP_FRONTEND" = true ]; then
        TAURI_ARGS="--no-watch"
        log_info "Running with --no-watch (no-rebuild mode)"
    fi

    cargo tauri dev $TAURI_ARGS

    log_success "Build complete!"
else
    log_success "Build complete!"
    log_info "To run the app, use: ./scripts/build-desktop-dev.sh --run"
    log_info "Or manually: cd desktop && cargo tauri dev"
fi
