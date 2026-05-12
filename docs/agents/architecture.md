# Agentic Reference: Architecture Overview

## CRITICAL: Backend Feature Isolation
> [!IMPORTANT]
> **NEVER** run `cargo check`, `cargo clippy`, or `cargo build` for both `cloud` and `desktop` features simultaneously or in the same command.
> The project uses mutually exclusive backend implementations (PostgreSQL vs SQLite). Running both at once will cause conflicting trait implementations and build failures.
>
> **Always use `--no-default-features`** when targeting a specific backend:
> - **Cloud**: `cargo check -p scribe-backend --no-default-features --features cloud,payment`
> - **Desktop**: `cargo check -p scribe-backend --no-default-features --features desktop`

## Multi-Component Architecture
Sanguine Scribe is a privacy-first AI roleplaying platform with multiple deployment modes:

**Backend (Rust + Axum)**: Core API server with dual support for:
- Cloud mode: PostgreSQL + Qdrant (vector database) for production
- Desktop mode: SQLite + LanceDB for self-hosted desktop applications

**Frontend (SvelteKit + TypeScript)**: Reactive web interface with character management, chat functionality, and real-time updates.

**Desktop (Tauri)**: Native desktop application wrapper using the backend compiled for desktop mode. The desktop build process orchestrates building frontend (SvelteKit static adapter with desktop config), backend binary (Rust with desktop features: SQLite + LanceDB), and places the binary in the Tauri binaries directory for sidecar deployment.

**CLI**: Command-line interface for administrative tasks and system management.

## Key Architectural Patterns

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

## Development Mode Considerations

When developing, always be aware of which backend mode you're targeting:
- Pre-commit hooks test both cloud and desktop configurations
- Database migrations differ between PostgreSQL and SQLite modes
- Some features are payment-gated in cloud mode but available in desktop mode
- Test suites include security tests covering OWASP Top 10 requirements

## Testing Requirements

All code changes must include comprehensive testing:
- Backend: Unit tests (`#[cfg(test)]`) and integration tests (`tests/` directory)
- Security tests mandatory for OWASP Top 10 coverage
- Frontend: Component tests with @testing-library/svelte
- Use `test_helpers` module for common backend test setup

## Important Conventions

**Commit Messages**: Follow conventional commits format (feat:, fix:, docs:, etc.)

**Branch Strategy**: Use descriptive names like `feat/add-voice-chat`, `fix/login-error`

**Code Organization**:
- Routes → Handlers → Services → Models pattern in backend
- Reusable components with Svelte 5 runes in frontend
- Strong typing throughout (no `any` in TypeScript)

**Privacy-Safe Logging**: See [docs/PRIVACY_SAFE_LOGGING.md](../PRIVACY_SAFE_LOGGING.md). Key rules:
- **Always use `capture_user_id_middleware`** - This automatically populates the obfuscated `loggable_user_id()` as `user_id` on the OTLP `tracing::Span`. Extract headers into native `tracing::info!` macros. Never log raw email addresses, plaintext IDs, or User PII to strings natively.
- **Never log raw user IDs** - use `loggable_user_id(user.id)` for obfuscated format `u8a3f2xx`
- **Never log usernames/emails** - use `sanitize_personal_info(email)` for partial redaction
- **Never log user content** (messages, prompts, AI responses, reasoning) - log only lengths/metadata
- **For payment/sensitive flows** - use `sanitize_json_value()` for deep PII redaction

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
