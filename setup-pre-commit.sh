#!/bin/bash
set -euo pipefail

# Sanguine Scribe Pre-commit Setup Script
# This script installs and configures pre-commit hooks for professional code quality

echo "🚀 Setting up professional pre-commit hooks for Sanguine Scribe..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f ".pre-commit-config.yaml" ]]; then
    print_error "This script must be run from the project root (where .pre-commit-config.yaml exists)"
    exit 1
fi

# Check and install pre-commit
print_status "Checking pre-commit installation..."

if ! command -v pre-commit &> /dev/null; then
    print_status "Installing pre-commit..."

    # Try different installation methods based on what's available
    if command -v pipx &> /dev/null; then
        print_status "Installing pre-commit via pipx (recommended)..."
        pipx install pre-commit
    elif command -v pip &> /dev/null; then
        print_status "Installing pre-commit via pip..."
        pip install --user pre-commit
    elif command -v pip3 &> /dev/null; then
        print_status "Installing pre-commit via pip3..."
        pip3 install --user pre-commit
    else
        print_error "No Python package installer found (pip/pipx). Please install pre-commit manually:"
        print_error "  pipx install pre-commit"
        print_error "  OR pip install --user pre-commit"
        exit 1
    fi
else
    print_success "pre-commit is already installed"
fi

# Ensure pre-commit is in PATH
if ! command -v pre-commit &> /dev/null; then
    print_warning "pre-commit not found in PATH. Adding ~/.local/bin to PATH for this session..."
    export PATH="$HOME/.local/bin:$PATH"

    if ! command -v pre-commit &> /dev/null; then
        print_error "Still can't find pre-commit. Please ensure it's installed and in your PATH."
        print_error "Try: export PATH=\"\$HOME/.local/bin:\$PATH\" or restart your terminal."
        exit 1
    fi
fi

# Check and install Gitleaks if needed
print_status "Checking Gitleaks installation..."

if ! command -v gitleaks &> /dev/null; then
    print_status "Installing Gitleaks for security scanning..."

    # Try to install via package manager based on OS
    if command -v pacman &> /dev/null; then
        print_status "Installing via pacman (Arch Linux)..."
        sudo pacman -S gitleaks --noconfirm || print_warning "Failed to install gitleaks via pacman"
    elif command -v brew &> /dev/null; then
        print_status "Installing via Homebrew..."
        brew install gitleaks
    elif command -v apt &> /dev/null; then
        print_status "Installing via apt (Ubuntu/Debian)..."
        sudo apt update && sudo apt install -y gitleaks
    else
        print_warning "Could not install gitleaks automatically. Please install manually:"
        print_warning "  Arch: pacman -S gitleaks"
        print_warning "  macOS: brew install gitleaks"
        print_warning "  Ubuntu/Debian: apt install gitleaks"
        print_warning "  Or download from: https://github.com/gitleaks/gitleaks/releases"
    fi
else
    print_success "Gitleaks is already installed"
fi

# Install pre-commit hooks
print_status "Installing pre-commit hooks..."
pre-commit install

# Install commit message hook for conventional commits
print_status "Installing commit message validation hook..."
pre-commit install --hook-type commit-msg

# Append Scribe auto-formatter wrapper to the pre-commit hook
print_status "Configuring auto-formatter bypass in pre-commit hook..."
HOOK_FILE=".git/hooks/pre-commit"
if [ -f "$HOOK_FILE" ]; then
    AUTO_FORMAT_BLOCK='
# --- SCRIBE AUTO-FORMATTER WRAPPER ---
# Format modified backend Rust files
if git diff --cached --name-only | grep -q "^backend/.*\.rs$"; then
    echo "🦀 Auto-formatting backend Rust code..."
    cargo fmt -p scribe-backend
    git add $(git diff --cached --name-only)
fi

# Format modified frontend files
if git diff --cached --name-only | grep -E -q "^frontend/.*\.(js|ts|tsx|svelte|json|css|md)$"; then
    echo "⚡ Auto-formatting frontend code..."
    (cd frontend && pnpm format > /dev/null 2>&1)
    git add $(git diff --cached --name-only)
fi
# --- END SCRIBE AUTO-FORMATTER WRAPPER ---
'
    if ! grep -q "SCRIBE AUTO-FORMATTER WRAPPER" "$HOOK_FILE"; then
        awk -v block="$AUTO_FORMAT_BLOCK" "NR==1{print; print block; next} 1" "$HOOK_FILE" > "$HOOK_FILE.tmp"
        mv "$HOOK_FILE.tmp" "$HOOK_FILE"
        chmod +x "$HOOK_FILE"
        print_success "Auto-formatter wrapper installed successfully"
    else
        print_status "Auto-formatter wrapper already installed"
    fi
fi


# Verify Rust tools are available
print_status "Verifying Rust tools (cargo, rustfmt, clippy)..."

if ! command -v cargo &> /dev/null; then
    print_error "Cargo not found. Please install Rust toolchain: https://rustup.rs/"
    exit 1
fi

if ! command -v rustfmt &> /dev/null; then
    print_status "Installing rustfmt..."
    rustup component add rustfmt
fi

if ! command -v cargo-clippy &> /dev/null; then
    print_status "Installing clippy..."
    rustup component add clippy
fi

print_success "Rust tools verified"

# Verify Node.js/pnpm for frontend
print_status "Verifying frontend tools (pnpm)..."

if [[ ! -d "frontend" ]]; then
    print_warning "Frontend directory not found, skipping frontend tool verification"
else
    if ! command -v pnpm &> /dev/null; then
        print_error "pnpm not found. Please install pnpm: https://pnpm.io/installation"
        exit 1
    fi

    print_status "Installing frontend dependencies..."
    cd frontend
    pnpm install --frozen-lockfile
    cd ..

    print_success "Frontend tools verified"
fi

# Test the installation with a dry run
print_status "Testing pre-commit hooks (dry run)..."

if pre-commit run --all-files --dry-run; then
    print_success "All pre-commit hooks are configured correctly!"
else
    print_warning "Some hooks may need attention. This is normal for first-time setup."
    print_status "Run 'pre-commit run --all-files' to see detailed output and fix any issues."
fi

# Display helpful information
echo ""
print_success "🎉 Pre-commit setup complete!"
echo ""
print_status "What happens now:"
echo "  • Code formatting and linting will run automatically on every commit"
echo "  • Conventional commit messages will be enforced"
echo "  • Security scans will prevent accidental credential commits"
echo "  • All team members will maintain consistent code quality"
echo ""
print_status "Useful commands:"
echo "  • Run hooks manually: ${BLUE}pre-commit run --all-files${NC}"
echo "  • Skip hooks (emergency): ${YELLOW}git commit --no-verify${NC}"
echo "  • Update hook versions: ${BLUE}pre-commit autoupdate${NC}"
echo "  • Uninstall hooks: ${RED}pre-commit uninstall${NC}"
echo ""
print_status "Commit message format (enforced):"
echo "  • ${GREEN}feat: add new feature${NC}"
echo "  • ${GREEN}fix: resolve bug issue${NC}"
echo "  • ${GREEN}docs: update documentation${NC}"
echo "  • ${GREEN}style: format code${NC}"
echo "  • ${GREEN}refactor: improve code structure${NC}"
echo "  • ${GREEN}test: add or update tests${NC}"
echo "  • ${GREEN}chore: maintenance tasks${NC}"
echo ""
print_success "Your code is now professionally protected! 🛡️"
