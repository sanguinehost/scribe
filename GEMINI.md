# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Quick Start
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

### Backend Development
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

# Check compilation (desktop features)
cargo check -p scribe-backend --no-default-features --features desktop
```

### Frontend Development
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

### Desktop Development
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

### Database Operations
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

### Pre-commit Hooks
```bash
# Install pre-commit hooks (one-time setup)
./setup-pre-commit.sh

# Run all hooks manually
pre-commit run --all-files

# Skip hooks (emergency only)
git commit --no-verify
```

## Architecture Overview

### CRITICAL: Backend Feature Isolation
> [!IMPORTANT]
> **NEVER** run `cargo check`, `cargo clippy`, or `cargo build` for both `cloud` and `desktop` features simultaneously or in the same command.
> The project uses mutually exclusive backend implementations (PostgreSQL vs SQLite). Running both at once will cause conflicting trait implementations and build failures.
>
> **Always use `--no-default-features`** when targeting a specific backend:
> - **Cloud**: `cargo check -p scribe-backend --no-default-features --features cloud,payment`
> - **Desktop**: `cargo check -p scribe-backend --no-default-features --features desktop`

### Multi-Component Architecture
Sanguine Scribe is a privacy-first AI roleplaying platform with multiple deployment modes:

**Backend (Rust + Axum)**: Core API server with dual support for:
- Cloud mode: PostgreSQL + Qdrant (vector database) for production
- Desktop mode: SQLite + LanceDB for self-hosted desktop applications

**Frontend (SvelteKit + TypeScript)**: Reactive web interface with character management, chat functionality, and real-time updates.

**Desktop (Tauri)**: Native desktop application wrapper using the backend compiled for desktop mode. The desktop build process orchestrates building frontend (SvelteKit static adapter with desktop config), backend binary (Rust with desktop features: SQLite + LanceDB), and places the binary in the Tauri binaries directory for sidecar deployment.

**CLI**: Command-line interface for administrative tasks and system management.

### Key Architectural Patterns

**Feature Flags**: Backend uses Cargo features to support different backends:
- `cloud`: PostgreSQL + Qdrant for production hosting
- `desktop`: SQLite + LanceDB for local applications
- `payment`: Stripe integration for cloud features
- `local-llm`: Support for running local models (experimental)

**Security-First Design**:
- Client-side encryption for all character data and chat history
- Password-derived keys for server-side encryption
- OWASP Top 10 security testing requirements for all new features

**Context Management**:
- Chronicle system automatically tracks narrative history and character interactions
- Context enrichment agent provides smart retrieval of relevant character history
- Hybrid search combining keyword and semantic search via Qdrant/LanceDB

**Database Architecture**:
- PostgreSQL/SQLite for structured data (users, characters, messages, chronicles)
- Vector database (Qdrant/LanceDB) for semantic search and context retrieval
- Diesel ORM for database operations with careful feature separation

### Development Mode Considerations

When developing, always be aware of which backend mode you're targeting:
- Pre-commit hooks test both cloud and desktop configurations
- Database migrations differ between PostgreSQL and SQLite modes
- Some features are payment-gated in cloud mode but available in desktop mode
- Test suites include security tests covering OWASP Top 10 requirements

### Testing Requirements

All code changes must include comprehensive testing:
- Backend: Unit tests (`#[cfg(test)]`) and integration tests (`tests/` directory)
- Security tests mandatory for OWASP Top 10 coverage
- Frontend: Component tests with @testing-library/svelte
- Use `test_helpers` module for common backend test setup

### Important Conventions

**Commit Messages**: Follow conventional commits format (feat:, fix:, docs:, etc.)

**Branch Strategy**: Use descriptive names like `feat/add-voice-chat`, `fix/login-error`

**Code Organization**:
- Routes → Handlers → Services → Models pattern in backend
- Reusable components with Svelte 5 runes in frontend
- Strong typing throughout (no `any` in TypeScript)

**Security**: Never commit secrets, use environment variables, and ensure all user data is properly encrypted at rest.
## Context Management & Limits

Sanguine Scribe uses a sophisticated context management system to maximize the usage of available tokens while respecting user settings and model capabilities.

### Token Budgeting Strategy

The system employs a "Waterfall Budgeting" strategy for RAG (Retrieval-Augmented Generation) content to ensure that the context window is fully utilized:

1.  **Total Limit**: Determined by user settings (e.g., 128k) or subscription tier (Cloud). Desktop builds bypass subscription limits.
2.  **Recent History**: Allocated a portion of the budget (e.g., 30%) to ensure immediate conversation continuity.
3.  **RAG Waterfall**: The remaining budget is available for RAG, processed in a specific order with "soft caps":
    *   **Lorebooks**: Capped at 40% of total RAG budget. Unused tokens flow to the next category.
    *   **Chronicles**: Capped at 40% of total RAG budget. Unused tokens flow to the next category.
    *   **Older Chat History**: Receives *all* remaining budget. This ensures that if Lorebooks or Chronicles are sparse, the system fills the remaining space with older chat history, maximizing context usage.

### Key Files
- `backend/src/services/chat/generation.rs`: Implements the waterfall selection logic.
- `backend/src/services/rag_budget_manager.rs`: Handles budget planning and dynamic selection.
- `backend/src/prompt_builder.rs`: Assembles the final prompt and enforces hard limits.
