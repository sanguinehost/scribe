# Epic: Multi-Cloud OTLP Observability & Infrastructure Abstraction

**Goal:** Transition Scribe from an AWS-locked observability and infrastructure model to a resilient, privacy-centric, and provider-agnostic global architecture. This involves standardizing on OpenTelemetry (OTLP), implementing an **Embedded Durable Machine** for orchestration (replacing the sidecar-heavy Temporal model), and abstracting the infrastructure layer through Terragrunt and platform-agnostic ingress (Traefik/Caddy).

## Core Architectural Principles

1.  **OTLP-Direct Telemetry:** The backend shall emit logs, metrics, and traces directly via OpenTelemetry. We bypass legacy provider-specific ingestion (CloudWatch/Kinesis) to ensure portability across AWS, GCP, Azure, or on-prem.
2.  **Privacy-at-the-Edge:** All PII and sensitive AI prompts/completions are masked or redacted at the SDK level (client-side) *before* they exit the application process memory.
3.  **Embedded Durable Machine (EDM):** Instead of an external workflow engine (Temporal), Scribe will utilize a **Diesel-backed Task Queue**. This ensures logical parity between Cloud (Postgres) and Desktop (SQLite) within a single binary, providing "deterministic-like" durability without the overhead of a sidecar.
4.  **Global Resiliency & Sovereignty:** Infrastructure is managed via Terragrunt to facilitate multi-region/multi-cloud "active-active" deployments, respecting regional data residency and minimizing cross-region egress costs.
5.  **Desktop (Tauri) Safety:** High-overhead cloud services (OTLP, metrics) are guarded by feature flags (`otel`) to maintain the lean footprint and local-only nature of the Desktop application.

---

## 1. Engineering Methodology Alignment

This project adheres to the Scribe **Engineering Lifecycle** (as defined in `GEMINI.md`):

1.  **Contextual Impact Analysis (The "Blast Radius" Check):** Before any code is modified, we interrogate the system to understand the breadth of the change.
2.  **Isolated Proof of Concept (The "Empirical" Phase):** We requires evidence before implementation. Prototyping logic in isolation ensures the core system remains stable.
3.  **Idiomatic Implementation (The "Senior Engineer" Phase):** Focus on precision, leveraging Rust idiomatic patterns and zero-cost abstractions for observability and orchestration.
4.  **Post-Implementation Verification (The "Regression" Phase):** Exhaustive validation including negative testing and regression suites.
5.  **Aesthetic and PR Polish (The "Definition of Done"):** Adherence to formatting, documentation, and impact summaries.

---

## 2. Security Review & OWASP Alignment

### 2.1 OWASP Top 10 (2021)
- **A02: Cryptographic Failures**: Use TLS 1.3 for OTLP exports; integrate with `rustls`.
- **A09: Redefining Logging**: Moving to OTLP-first observability to improve visibility and forensics.
- **A10: SSRF**: Strictly validate telemetry sinks and avoid dynamic user-provided URLs.

### 2.2 OWASP LLM Top 10 (2025)
- **LLM01: Prompt Injection**: Observability to track unusual behavioral patterns.
- **LLM02: Sensitive Information Disclosure**: SDK-level masking for prompts and completions.
- **LLM10: Unbounded Consumption**: Monitor token usage per user/session to detect DoS/DoW.

---

### Phase 1: Backend Telemetry & Privacy-First Ingestion
**Lifecycle Focus:** Security/Fixing (PII Protection) & Feature Engineering (OTLP Sink).

#### 1. Contextual Impact Analysis (Blast Radius)
- [ ] **Subtask:** Update `backend/Cargo.toml` with OTLP and Orchestration crates.
    - Add `opentelemetry = "0.31"`, `opentelemetry-otlp`, `tracing-opentelemetry`, `opentelemetry_langfuse`.
- [ ] **Subtask:** Audit `backend/src/logging/tracing.rs` for existing layer interactions.

#### 2. Isolated Proof of Concept (Empirical Phase)
- [ ] **Subtask:** Implement standalone `mask` function PoC.
    - Verify redaction of PII in mock chat payloads before integration.
- [ ] **Subtask:** Validate OTel Span Processor stubs for "Fail-Closed" logic.
    - **Constraint:** Ensure spanning drops if masking fails. Use `Cow<'static, str>` for replacement markers to minimize allocations.

#### 3. Core Engine Implementation (Idiomatic Rust)
- [ ] **Subtask:** Refactor `init_subscriber` with OTLP metrics/logs/trace layers.
- [ ] **Subtask:** Implement `PrivacyMaskProcessor` (implementing `opentelemetry::sdk::trace::SpanProcessor`).

#### 4. Post-Implementation Verification (Regression)
- [ ] **Subtask:** Negative testing: Verify raw PII rejection in local OTLP collector logs.
- [ ] **Subtask:** `cargo test --features cloud,otel` vs `cargo test --features desktop`.

---

### Phase 2: Embedded Durable Machine (Orchestration)
**Lifecycle Focus:** New Feature Engineering (Stateful Orchestration).

#### 1. Domain Modeling & Constraint Mapping
- [ ] **Subtask:** Define `NarrativeTask` ADTs and state transition enums.
- [ ] **Subtask:** Diesel migration for `narrative_tasks` table (UUID, state JSONB, status, scheduled_at).

#### 2. Minimum Viable Capability (MVC) Spike
- [ ] **Subtask:** Create standalone test runner for the state machine logic.
- [ ] **Subtask:** Prove "Happy Path" state transitions in a stubbed SQLite environment.

#### 3. Core Engine Implementation (Idiomatic Rust)
- [ ] **Subtask:** Implement the poll-and-execute loop in a dedicated `tokio` task.
    - **Memory Ordering:** Use `Ordering::Acquire` for status checks and `Ordering::Release` for heartbeat/state updates.
    - **Transaction Isolation:** Use `SERIALIZABLE` isolation for task pickup to prevent phantoms.
- [ ] **Subtask:** Refactor `agent_runner.rs` to "Yield" by updating database state.

#### 4. Invariant and Property-Based Testing
- [ ] **Subtask:** Use `proptest` to verify state machine robustness.
- [ ] **Subtask:** Atomic transaction verification: ensure state + memory updates are committed together.

---

## Phase 3: Global Infrastructure & Ingress Abstraction

### Task 3.1: Terragrunt Migration & Module Abstraction
- [ ] **Subtask:** Create `infrastructure/terragrunt/` directory structure.
    - Organize by `provider/region/account/environment`.
    - Implement DRY `terragrunt.hcl` for global constants.
- [ ] **Subtask:** Provide Agnostic Ingress Module.
    - Replace `aws_alb` with a **Traefik** or **Caddy** module.
    - Implement **Keepalived** for control plane High Availability in hybrid/non-AWS environments.

### Task 3.2: Networking & GSLB
- [ ] **Subtask:** Implement Global Server Load Balancing (GSLB).
    - Use Cloudflare or Route53 GSLB to route users to the nearest regional cluster (AWS Primary vs GCP Failover).
    - **State Continuity:** Prioritize application-level state transfer via EDM JSONB state to handle cross-cloud session migration.
- [ ] **Subtask:** Provider-Agnostic VPC/Subnet abstractions.

---

## Phase 4: Observability Infrastructure (Self-Hosted)

### Task 4.1: Aggregator Stack
- [ ] **Subtask:** Provision **ClickHouse** Cluster.
    - High-performance storage for the OTLP telemetry sink.
- [ ] **Subtask:** Deploy **OpenObserve** (or SigNoz).
    - Native OTLP ingestion replacing CloudWatch and Kinesis Firehose.
- [ ] **Subtask:** Deploy Regional OTLP Collectors.
    - Batch, compress, and redact telemetry locally within each AZ to minimize egress costs.

### Task 4.2: AI Evaluation & Tracking
- [ ] **Subtask:** Self-host **Langfuse**.
    - Connect to the OTel layer with localized data residency.
    - Verify client-side masking is effective across all agents.

---

## Phase 5: AIOps, Alerting & Monitoring

### Task 5.1: Centralized Alerting
- [ ] **Subtask:** Integrate **Keep**.
    - Centralize alerts from OpenObserve, Sentry, and the EDM Task Queue.
- [ ] **Subtask:** Error Tracking.
    - Self-hosted **Sentry** for cluster-wide exception monitoring.

---

## Operational & Global Strategy

### Multi-Region Failover
- **Active-Active:** Deployments in `us-east-1` (AWS) and `europe-west-1` (GCP).
- **State Sync:** Background db replication vs application-level state transfer.
- **Failover Verification:** Terminate a region's ingress; verify GSLB flips traffic within <30s.

### Data Sovereignty & Privacy Audit
- **Man-in-the-Middle Audit:** Intercept traffic between Backend and regional collector; verify zero raw PII is visible.
- **Redaction Logs:** Ensure the masking function logs redaction events for audit trails.

---

## Verification Plan

### Automated Tests
- `cargo test --features cloud,otel` - Verify OTLP layer initialization and EDM task transitions.
- `cargo test --features desktop` - Ensure zero OTLP leakage in the Tauri binary.
- `cargo test test_durable_orchestrator` - Verify task recovery after simulated crash.

### Manual Verification
1. **AI Tracing:** Trigger chat in staging, verify traces in Langfuse (masked).
2. **Log Aggregation:** Verify Rust logs appear in OpenObserve via OTLP.
3. **Ingress:** Verify Traefik routing works across non-AWS nodes.
