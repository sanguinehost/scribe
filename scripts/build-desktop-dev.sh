#!/usr/bin/env bash
#
# Scribe Desktop - Development Build Script
#
# This script orchestrates the complete desktop build pipeline:
# 1. Clean stale build artifacts (frontend/backend/binaries)
# 2. Frontend build (SvelteKit static adapter with desktop config)
# 3. Backend binary (Rust with desktop features: SQLite + LanceDB)
# 4. Binary placement for Tauri sidecar
# 5. Validation and Tauri dev server startup
#
# Usage: ./scripts/build-desktop-dev.sh [--clean]
#
# Options:
#   --clean    Perform a full clean rebuild (removes all Cargo build cache)
#

set -euo pipefail

# Parse command line flags
CLEAN_BUILD=false
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--clean]"
            exit 1
            ;;
    esac
done

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

# Determine project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ "$CLEAN_BUILD" = true ]; then
    log_info "Building Scribe Desktop (Development Mode - FULL CLEAN REBUILD)"
else
    log_info "Building Scribe Desktop (Development Mode)"
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

# Clean frontend build artifacts
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

# Clean backend build artifacts
if [ "$CLEAN_BUILD" = true ]; then
    # Full clean: Remove entire Cargo target directory for complete rebuild
    if [ -d "$PROJECT_ROOT/target" ]; then
        log_info "FULL CLEAN: Removing entire Cargo target directory..."
        BEFORE_SIZE=$(du -sh "$PROJECT_ROOT/target" 2>/dev/null | cut -f1 || echo "unknown")
        rm -rf "$PROJECT_ROOT/target"
        log_success "Cleaned: target/ (was $BEFORE_SIZE)"
    fi

    # Also clean frontend node_modules for thoroughness
    if [ -d "$PROJECT_ROOT/frontend/node_modules" ]; then
        log_info "FULL CLEAN: Removing frontend node_modules..."
        BEFORE_SIZE=$(du -sh "$PROJECT_ROOT/frontend/node_modules" 2>/dev/null | cut -f1 || echo "unknown")
        rm -rf "$PROJECT_ROOT/frontend/node_modules"
        log_success "Cleaned: frontend/node_modules/ (was $BEFORE_SIZE)"
        log_warn "Will run 'pnpm install' to restore dependencies..."
    fi
else
    # Normal clean: Just remove the scribe-backend binary
    if [ -f "$PROJECT_ROOT/target/debug/scribe-backend" ]; then
        log_info "Removing backend binary..."
        rm -f "$PROJECT_ROOT/target/debug/scribe-backend"
        log_success "Cleaned: target/debug/scribe-backend"
    fi

    # Also remove the scribe-backend fingerprint to force rebuild
    if [ -d "$PROJECT_ROOT/target/debug/.fingerprint/scribe-backend-"* ]; then
        log_info "Removing backend build fingerprints..."
        rm -rf "$PROJECT_ROOT/target/debug/.fingerprint/scribe-backend-"*
        log_success "Cleaned: scribe-backend fingerprints"
    fi
fi

# Clean desktop binaries directory
if [ -d "$PROJECT_ROOT/desktop/binaries" ]; then
    log_info "Removing desktop binaries directory..."
    rm -rf "$PROJECT_ROOT/desktop/binaries"
    log_success "Cleaned: desktop/binaries/"
fi

log_success "All stale artifacts cleaned successfully"
echo ""

# Step 2.5: Restore frontend dependencies if cleaned
if [ "$CLEAN_BUILD" = true ] && [ ! -d "$PROJECT_ROOT/frontend/node_modules" ]; then
    log_info "Step 2.5/7: Restoring frontend dependencies..."
    cd "$PROJECT_ROOT/frontend"
    log_info "Running: pnpm install"
    pnpm install
    log_success "Frontend dependencies restored"
    echo ""
fi

# Step 3: Build frontend for desktop
log_info "Step 3/7: Building frontend with desktop configuration..."

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
echo ""

# Step 4: Build backend binary with desktop features
log_info "Step 4/7: Building backend binary with desktop features (SQLite + LanceDB)..."

cd "$PROJECT_ROOT"

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

# Step 7: Start Tauri dev server
log_info "Step 7/7: Starting Tauri desktop app..."

cd "$PROJECT_ROOT/desktop"

# Set required environment variables
export WEBKIT_DISABLE_DMABUF_RENDERER=1  # Required for Linux WebKitGTK

# Pass GEMINI_API_KEY if set in environment
if [ -z "${GEMINI_API_KEY:-}" ]; then
    log_warn "GEMINI_API_KEY not set - AI features will not work"
    log_warn "Set it with: export GEMINI_API_KEY=\"your-key-here\""
fi

log_info "Starting cargo tauri dev..."
log_info "Note: First build may take several minutes..."
echo ""

cargo tauri dev

log_success "Build complete!"
