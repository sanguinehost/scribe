#!/usr/bin/env bash
#
# Scribe Desktop - Development Build Script
#
# This script orchestrates the complete desktop build pipeline:
# 1. Frontend build (SvelteKit static adapter with desktop config)
# 2. Backend binary (Rust with desktop features: SQLite + LanceDB)
# 3. Binary placement for Tauri sidecar
# 4. Validation and Tauri dev server startup
#
# Usage: ./scripts/build-desktop-dev.sh
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

# Determine project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

log_info "Building Scribe Desktop (Development Mode)"
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

# Step 2: Build frontend for desktop
log_info "Step 2/6: Building frontend with desktop configuration..."

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

# Step 3: Build backend binary with desktop features
log_info "Step 3/6: Building backend binary with desktop features (SQLite + LanceDB)..."

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

# Step 4: Copy backend binary to Tauri binaries directory
log_info "Step 4/6: Copying backend binary to Tauri binaries directory..."

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

# Step 5: Verify all prerequisites
log_info "Step 5/6: Verifying build artifacts..."

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

# Step 6: Start Tauri dev server
log_info "Step 6/6: Starting Tauri desktop app..."

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
