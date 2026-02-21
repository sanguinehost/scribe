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

**Privacy-Safe Logging**: See [docs/PRIVACY_SAFE_LOGGING.md](docs/PRIVACY_SAFE_LOGGING.md). Key rules:
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

## Engineering Methodology

The methodology employed transitions a task from a simple **request-response** pattern into a formal **Engineering Lifecycle**. By rejecting "low-effort" immediate fixes, the process enforces a rigorous standard of proof and verification that mirrors a high-level software development lifecycle (SDLC).

### 1. The Strategy: From Fixer to Architect

Depending on whether a task involves addressing a regression (Fixing) or building a new capability (Engineering), the focus shifts between **Reproduction of Failure** and **Verification of Invariants**.

| Phase | Security/Fixing Focus | New Feature Focus |
| --- | --- | --- |
| **Step 1** | Blast Radius (Who can be pwned?) | Domain Modeling (What are the types?) |
| **Step 2** | Failure PoC (Proof of Exploit) | MVC Spike (Proof of Concept) |
| **Step 3** | Hardening (Removing the bug) | Implementation (Building the engine) |
| **Step 4** | Regression (Is the hole closed?) | Invariant Verification (Does it always work?) |
| **Step 5** | Security Polish (Logs/Alerts) | Architectural Polish (Telemetry/UX) |

---

### Phase-Specific Breakdown: New Feature Engineering

To build entirely new features (like the Embedded Durable Machine), the methodology focuses on proving that logic is mathematically sound and architecturally compatible before it touches the main branch.

#### 1. Domain Modeling and Constraint Mapping
Perform an architectural impact analysis of the new capability.
* **Type-Driven Design:** Define Algebraic Data Types (ADTs) and Trait bounds first. In Rust, encode business logic into the type system to ensure "illegal states are unrepresentable."
* **Dependency Surface Area:** Map interactions with persistence layers (Diesel) and the async runtime (Tokio).
* **Performance Budgeting:** Establish expected asymptotic complexity and memory footprint. Define state transition functions for stateful systems.

#### 2. The Minimum Viable Capability (MVC) Spike
Prove the core logic can execute in a vacuum (the "Functional PoC").
* **Logic Isolation:** Create a standalone test binary/module to exercise the core algorithm without database or frontend overhead.
* **Happy Path Verification:** Prove viability under current constraints.
* **Stubbed Environment:** Use mock traits to simulate I/O or latency.

#### 3. Core Engine Implementation (Idiomatic Rust)
Flesh out the implementation focusing on zero-cost abstractions and memory safety.
* **Memory Layout:** Address alignment and padding in structs (especially for JSONB serialization).
* **Error Propagation:** Use context-aware, zero-allocation Enums. Ensure "panic-proof" operations with the `?` operator.
* **Static Dispatch:** Prefer Generics and Traits over `Box<dyn Trait>` for inlining and performance.

#### 4. Invariant and Property-Based Testing
Replace simple regression testing with invariant verification.
* **Property-Based Testing:** Use tools like `proptest` to verify the state machine against thousands of random inputs.
* **Integration Spikes:** Integrate with the Diesel schema and verify ACID transaction atomicity.
* **State Sync Check:** Verify database state matches in-memory representation after "yield" points.

#### 5. Architectural Alignment and Polishing
Ensure the feature feels like a native part of the Scribe platform.
* **CLI and Telemetry:** Add OTel tracing to visualize flows.
* **Style and Linting:** Strict adherence to `clippy::pedantic` and `clippy::nursery`.
* **PR Narrative:** Explain "First Principles" reasoning for implementation choices (e.g., "Why EDM over Temporal").

---

### Phase-Specific Breakdown: Security & Regression Fixing

For addressing vulnerabilities or bugs, the focus is on empirical proof of failure.

#### 1. Contextual Impact Analysis (The "Blast Radius" Check)
* **Dependency Mapping:** Identifying every consumer of the component.
* **Tenet Alignment:** Alignment with performance-first and zero-cost abstraction tenets.
* **Failure Reachability:** Determining how the bug is reached through the call chain.

#### 2. Isolated Proof of Concept (The "Empirical" Phase)
* **Failure Reproduction:** Create a standalone environment/script that proves the current state is broken.
* **Sandbox Testing:** Validate logic in isolation without environment constraints.

#### 3. Idiomatic Implementation (The "Senior Engineer" Phase)
* **Precision Fix:** Implement with focus on precision and language idioms.
* **Observability:** Custom exception types to distinguish failure modes.

#### 4. Post-Implementation Verification (The "Regression" Phase)
* **Negative Testing:** Verify rejection of malformed/malicious inputs.
* **Regression Suite:** Ensure legacy functionality remains intact.

#### 5. Aesthetic and PR Polish
* **Compliance:** Ruff/Clippy/Rustfmt standards.
* **Documentation:** Google-style docstrings and clear PR descriptions.

## Operational Runbook

### Secure Production Access
Direct access to production/staging databases (RDS) is restricted. Access is granted via SSM Port Forwarding through a Bastion host or Tailscale router.

#### 1. Database Access (Read/Write)
**Prerequisites**: AWS CLI configured with appropriate permissions.

```bash
# 1. Retrieve Database Password
aws secretsmanager get-secret-value \
    --secret-id arn:aws:secretsmanager:ap-southeast-4:058264339990:secret:staging/scribe/database-tXXaO7 \
    --region ap-southeast-4 \
    --query SecretString --output text | jq -r .password

# 2. Start SSM Tunnel (Port Forwarding)
# Find the Tailscale router or Bastion instance ID
INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=staging-scribe-tailscale-router" \
    --query "Reservations[0].Instances[0].InstanceId" --output text --region ap-southeast-4)

aws ssm start-session \
    --target $INSTANCE_ID \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters '{"host":["staging-scribe-postgres.c9oy0o248kqw.ap-southeast-4.rds.amazonaws.com"],"portNumber":["5432"], "localPortNumber":["54320"]}' \
    --region ap-southeast-4

# 3. Connect via Localhost
# Note: sslmode=require is mandatory
PGPASSWORD='<RETRIEVED_PASSWORD>' psql "postgresql://scribe_admin@localhost:54320/scribe?sslmode=require"
```

#### 2. ECS Exec (Shell Access)
For debugging running containers (e.g., checking env vars, network connectivity).

```bash
# 1. List Tasks
aws ecs list-tasks --cluster staging-scribe-cluster --service-name staging-scribe-backend --region ap-southeast-4

# 2. Start Interactive Shell
aws ecs execute-command \
    --cluster staging-scribe-cluster \
    --task <TASK_ARN> \
    --container backend \
    --command "/bin/sh" \
    --interactive \
    --region ap-southeast-4
```

### OpenObserve (OBS) Operations
Common tasks for monitoring, querying, and managing alerts in OpenObserve.

#### 1. Connecting and API Calls
OpenObserve provides a REST API. You need your organization name, stream name, and basic auth credentials token.

```bash
# Set your OpenObserve URL and credentials
export OBS_URL="https://api.openobserve.ai"
export OBS_ORG="default"
export OBS_STREAM="scribe_logs"
export OBS_TOKEN="Basic <base64_encoded_email:password>"

# Test Connection / Get Streams
curl -X GET "${OBS_URL}/api/${OBS_ORG}/streams" \
  -H "Authorization: ${OBS_TOKEN}" \
  -H "Accept: application/json"

# Search Logs using SQL via API
curl -X POST "${OBS_URL}/api/${OBS_ORG}/_search" \
  -H "Authorization: ${OBS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "sql": "SELECT * FROM scribe_logs WHERE level = '\''ERROR'\'' LIMIT 10",
      "start_time": <START_TIMESTAMP_MICROSECONDS>,
      "end_time": <END_TIMESTAMP_MICROSECONDS>
    }
  }'
```

#### 2. Configuring Alerts
Alerts in OpenObserve monitor streams using SQL queries and trigger destinations (e.g., webhooks, Slack) when conditions are met. Alert configurations are stored as JSON files in `infrastructure/monitoring/alerts/`.

```bash
# Example: Create or Update an Alert via API
curl -X POST "${OBS_URL}/api/${OBS_ORG}/alerts/scribe_external_dependency" \
  -H "Authorization: ${OBS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/alerts/external_dependency_failure.json
```

**Key Alerting Principles:**
- Store all alert configurations in version control (`infrastructure/monitoring/alerts`).
- Use structured JSON logging to extract the right metrics (e.g., `event_type = 'payment_failed'`).
- Ensure every alert has a clear destination (e.g., Discord webhook) and action plan.

### Manual User Management
Common tasks for support or debugging.

#### Reset User for Signup
If a user needs to re-signup (e.g., email verification failed), delete them from the DB.

```sql
-- Connect via SSM Tunnel (see above)
DELETE FROM users WHERE email = 'target@email.com';
```

### Deployment Process

#### 1. Backend Deployment
The backend is deployed via the `scripts/deploy/aws.sh` script, which handles building the Docker image, pushing to ECR, and updating the ECS service.

```bash
# Deploy backend to Staging
./scripts/deploy/aws.sh backend
```

**Key Steps Performed:**
1.  Builds `scribe-backend` Docker image.
2.  Pushes image to ECR (`058264339990.dkr.ecr.ap-southeast-4.amazonaws.com/staging-scribe-backend`).
3.  Forces a new deployment in ECS, pulling the latest image.

#### 2. Frontend Deployment (ECS)
Frontend is deployed to AWS ECS alongside the backend using the consolidated deployment script.

```bash
# Deploy frontend to Staging
./scripts/deploy/aws.sh frontend
```

This script will:
- Build the Docker image for the frontend
- Push to ECR
- Update the ECS service

See `docs/frontend/FRONTEND_DEPLOYMENT.md` for detailed instructions.

#### 3. Infrastructure Updates (Terraform/Terragrunt)
Infrastructure changes (e.g., env vars, IAM roles) are managed via Terragrunt.

```bash
cd infrastructure/terragrunt/aws/staging/<module>
terragrunt apply
```

**Workflow:**
1.  **Plan**: `terragrunt plan` to preview changes.
2.  **Apply**: `terragrunt apply` to execute.
3.  **Verify**: Check AWS console or verification scripts.
