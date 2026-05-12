# AGENTS.md: Sanguine Scribe — Architectural Blueprint & Operations Manual

This document is the definitive AI-native architectural blueprint for **Sanguine Scribe**, a privacy-first AI roleplaying platform with multiple deployment modes (Cloud and Desktop).

The Scribe backend is a robust Rust/Axum API server interacting with SvelteKit on the frontend and Tauri on the desktop. It enforces strong type-safety, privacy-safe logging, and a tiered storage architecture for context management and agentic intelligence.

**This document follows the rigor standard established across SanguineHost platforms (e.g., Lyrium Engine).**

---

## 0. The Prime Directive: Verify & Compose

Sanguine Scribe relies on composable, Linux-ethos style CLI tools and rigorous isolation between features (Cloud vs. Desktop). **Do not invent new patterns or bypass the established CLI toolchain.** Audit the existing integrations (e.g., Qdrant, LanceDB, Stripe, LLM interfaces) and rely on the internal toolchain for validation.

**Key Architectural Difference from Monolithic APIs:**
- **Mutually Exclusive Features:** The backend heavily relies on Cargo feature flags (`cloud`, `desktop`, `payment`). Compiling multiple feature sets simultaneously will break trait implementations. You must always use `--no-default-features` when targeting a specific backend.
- **Privacy-First Data Flow:** Never log raw user IDs, emails, or content directly. Always route through `capture_user_id_middleware` and use `loggable_user_id()`, `sanitize_personal_info()`, or `sanitize_json_value()`.

---

## 1. The Ground Truth: Core CLI Workflows

Scribe is built to be manipulated via sharp, focused command-line actions. Rely on these over manual IDE tweaking where possible.

- **Cloud Dev:** `cargo check -p scribe-backend --no-default-features --features cloud,payment`
- **Desktop Dev:** `./scripts/build-desktop-dev.sh --check`
- **Frontend Dev:** `pnpm dev` (in `/frontend`)
- **DB Migrations:** `diesel migration run`

---

## 2. Blueprint Modules & The Swarm Mandate

> [!IMPORTANT]
> **MANDATORY READING:** AI agents are FORBIDDEN from making assumptions about the platform's internal logic. You MUST read the relevant modular documentation in `docs/agents/` before proposing code changes or running diagnostic tools. Failure to do so is a violation of the Prime Directive.

- [**Development Commands**](docs/agents/development.md) — The specific CLI invocations for backend, frontend, and desktop builds, plus database and pre-commit hook operations.
- [**Architecture Overview**](docs/agents/architecture.md) — Backend feature isolation, Context Management constraints (RAG Waterfall), and Privacy-Safe logging rules.
- [**Engineering Methodology**](docs/agents/engineering.md) — The strategy from Fixer to Architect, defining the Engineering Lifecycle (Blast Radius → PoC → Hardening → Regression).
- [**Operational Runbook**](docs/agents/operations.md) — Secure production access via AWS SSM, OpenObserve telemetry rules, and the deployment pipelines.

> [!CAUTION]
> **Toolchain Mandate:** If you run `cargo check` or `cargo clippy` without targeting the correct feature flags (`cloud` vs `desktop`), you will break the build due to conflicting SQLite/PostgreSQL traits. Always verify your target environment first.

---

## 3. The Swarm Methodology (Epics, Waves, and Agents)

Scribe leverages structured parallelism and the Agentic Chain to maintain high stability across its complex feature matrix:

- **Epics & Sprints:** Large architectural features (e.g., Tiered Storage MMO Integration) are defined as **Epics**, broken down into multi-day **Sprints**.
- **Tasks & Subtasks:** Within a sprint, work is atomized into specific Tasks and executable Subtasks.
- **The Wave-Based Approach:** Agents are deployed in distinct, sequential Waves to prevent merge conflicts.
- **Mathematical Debugging over Heuristics:** Replace simple regression testing with invariant verification and property-based testing (e.g., `proptest`).

*For detailed state machine invariants and security hardening steps, see the [Engineering Methodology](docs/agents/engineering.md).*
