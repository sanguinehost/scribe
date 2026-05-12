# Agentic Reference: Development Commands & Workflows

## Quick Start
```bash
# One-command development setup
./start.sh

# Start backend (in another terminal)
cargo run --bin scribe-backend

# Start frontend (optional)
./start.sh --frontend

# Start desktop app (primary way to run desktop)
./scripts/build-desktop-dev.sh --run
```

## Backend Development

> [!IMPORTANT]
> **Command Output Handling**
>
> When running long-running commands like `cargo test`, `cargo check`, or `cargo build`, **always pipe output to a file in `/tmp/`** instead of using `tail` or `head`. This ensures the full output is available for review.
>
> ```bash
> # Good - full output preserved
> cargo test 2>&1 | tee /tmp/test-output.log
> cargo check 2>&1 | tee /tmp/check-output.log
>
> # Bad - loses important output
> cargo test 2>&1 | tail -n 50
> ```

```bash
# Build and run backend
cargo run --bin scribe-backend

# Run tests
cargo test

# Run specific test
cargo test test_name

# Format code
cargo fmt

# Lint code (cloud backend with PostgreSQL)
cargo clippy -p scribe-backend --no-default-features --features cloud,payment -- -D clippy::correctness -D clippy::suspicious -D clippy::complexity -W clippy::all -A unused-imports

# Lint code (desktop backend with SQLite)
cargo clippy -p scribe-backend --no-default-features --features desktop -- -D clippy::correctness -D clippy::suspicious -D clippy::complexity -W clippy::all -A unused-imports

# Check compilation (cloud features)
cargo check -p scribe-backend --no-default-features --features cloud,payment

# Check compilation (desktop features) - USE BUILD SCRIPT INSTEAD
./scripts/build-desktop-dev.sh --check
```

## Frontend Development
```bash
cd frontend

# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build

# Type checking
pnpm check

# Format code
pnpm format

# Lint code
pnpm lint

# Run tests
pnpm test

# Test with UI
pnpm test:ui

# Build for desktop (static adapter with desktop config)
pnpm run build:desktop
```

## Desktop Development
```bash
# Build and run desktop app (primary development method)
./scripts/build-desktop-dev.sh --run

# Build desktop app without running
./scripts/build-desktop-dev.sh

# Full clean rebuild (removes all Cargo cache - use when switching features)
./scripts/build-desktop-dev.sh --clean --run

# Skip backend compilation (only rebuild frontend)
./scripts/build-desktop-dev.sh --skip-backend --run

# Check build
./scripts/build-desktop-dev.sh --check

# Manual desktop development
cd desktop && cargo tauri dev

# Set required environment variables for desktop
export WEBKIT_DISABLE_DMABUF_RENDERER=1  # Required for Linux WebKitGTK
export GEMINI_API_KEY="your-key-here"    # Required for AI features
```

## Database Operations
```bash
# Run migrations
diesel migration run

# Generate new migration
diesel migration generate migration_name

# Redo last migration
diesel migration redo

# Print schema
diesel print-schema
```

## Pre-commit Hooks
```bash
# Install pre-commit hooks (one-time setup)
./setup-pre-commit.sh

# Run all hooks manually
pre-commit run --all-files

# Skip hooks (emergency only)
git commit --no-verify
```
