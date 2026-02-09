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

### Phase 1: Backend Telemetry & Privacy-First Ingestion [COMPLETED]
**Lifecycle Focus:** Security/Fixing (PII Protection) & Feature Engineering (OTLP Sink).

#### 1. Contextual Impact Analysis (Blast Radius)
- [x] **Subtask:** Update `backend/Cargo.toml` with OTLP crates.
- [x] **Subtask:** Audit `backend/src/logging/tracing.rs` for existing layer interactions.

#### 2. Isolated Proof of Concept (Empirical Phase)
- [x] **Subtask:** Implement standalone `mask` function PoC and `PrivacyMaskExporter`.
- [x] **Subtask:** Validate OTel Span Processor redaction in `otel_verification.rs`.

#### 3. Core Engine Implementation (Idiomatic Rust)
- [x] **Subtask:** Refactor `init_subscriber` with OTLP layer.
- [x] **Subtask:** Implement OTLP pipeline with privacy-safe redaction logic.

#### 4. Post-Implementation Verification (Regression)
- [x] **Subtask:** Negative testing: Verify raw PII rejection in local OTLP collector logs.
- [x] **Subtask:** Verified `otel` feature isolation for Cloud vs Desktop.

---

### Phase 2: Lorebook & RAG Instrumentation [IN PROGRESS]
**Lifecycle Focus:** Domain Modeling & Performance Observability.

#### 1. Service Instrumentation
- [x] Instrument `LorebookService::create_lorebook_entry` with metadata (title, content length).
- [x] Instrument `LorebookService::list_lorebook_entries` (CRUD level).
- [x] Added `decrypt_entries` surgical span to track decryption overhead.

#### 2. RAG Engine Observability
- [x] Instrument `DynamicRagSelector::select_rag_content` with token utilization fields.
- [x] Record events for budget-driven context truncation.
- [x] Instrument `NarrativeIntelligenceService` main chat processing loop with `narrative_workflow_execution` span.

#### 3. Verification
- [x] Fix `Send` trait violations in async `instrument` spans.
- [x] Verify new spans appear correctly in Jaeger UI with expected attributes.

---

### Phase 3: Embedded Durable Machine (Orchestration) [COMPLETED]
**Lifecycle Focus:** New Feature Engineering (Stateful Orchestration).

#### 1. Domain Modeling & Constraint Mapping
- [x] **Subtask:** Audit Temporal SDK and Effectum for durable patterns.
- [x] **Subtask:** Define `DurableWorkflow` trait (step, snapshot, restore).
- [x] **Subtask:** Diesel migration for `narrative_tasks` table:
    - Fields: `id`, `workflow_type`, `current_state` (encrypted blob), `status`, `expires_at` (heartbeat), `last_step_at`.

#### 2. Minimum Viable Capability (MVC) Spike
- [x] **Subtask:** Implement "Checkpoint & Heartbeat" PoC in a standalone SQLite environment.
- [x] **Subtask:** Prove state recovery after a simulated process crash (Panic/SIGKILL).

#### 3. Core Engine Implementation (Idiomatic Rust)
- [x] **Subtask:** Implement the poll-and-execute loop with OTel instrumentation.
    - **Heartbeats:** Update `expires_at` during long-running LLM calls to prevent task double-pickup.
    - **Checkpoints:** Serialize `DurableWorkflow` state to `current_state` blob after every successful transition.
- [x] **Subtask:** Refactor `NarrativeIntelligenceService` to use `DurableWorkflow` for multi-stage generations (Triage -> Plan -> Execute).

#### 4. Invariant and Property-Based Testing
- [x] **Subtask:** Verify "Exactly-Once" (effectively) execution via idempotent task pickup.
- [x] **Subtask:** Verify PII-safe state storage (Encryption at rest for all task states).

---

### Phase 4: Global Infrastructure & Ingress Abstraction

#### Task 4.1: Terragrunt Migration & Module Abstraction
- [ ] **Subtask:** Create `infrastructure/terragrunt/` directory structure.
- [ ] **Subtask:** Provide Agnostic Ingress Module (Traefik/Caddy).

#### Task 4.2: Networking & GSLB
- [ ] **Subtask:** Implement Global Server Load Balancing (GSLB) via Cloudflare/Route53.

---

### Phase 5: Observability Infrastructure (Self-Hosted)

#### Task 5.1: Aggregator Stack
- [ ] **Subtask:** Provision **ClickHouse** Cluster.
- [ ] **Subtask:** Deploy **OpenObserve** (or SigNoz) for OTLP ingestion.
- [ ] **Subtask:** Deploy Regional OTLP Collectors for data residency.

#### Task 5.2: AI Evaluation & Tracking
- [ ] **Subtask:** Self-host **Langfuse** and connect to OTel layer.

---

### Phase 6: AIOps, Alerting & Monitoring

#### Task 6.1: Centralized Alerting
- [ ] **Subtask:** Integrate **Keep** for unified alerting.
- [ ] **Subtask:** Self-host **Sentry** for cluster-wide exception monitoring.

---

## Operational & Global Strategy

### Multi-Region Failover
- **Active-Active:** Deployments in `us-east-1` (AWS) and `europe-west-1` (GCP).
- **Failover Verification:** Terminate a region's ingress; verify GSLB flips traffic within <30s.

### Data Sovereignty & Privacy Audit
- **Man-in-the-Middle Audit:** Intercept traffic between Backend and regional collector; verify zero raw PII is visible.
- **Redaction Logs:** Ensure the masking function logs redaction events for audit trails.

#### Task 6.2: Error Budget Tracking
- [ ] Define SLOs for core narrative loops.
- [ ] Implement Error Budget alerts.

---

### Phase 7: Metrics-Driven Autoscaling & Concurrency
**Lifecycle Focus:** Architectural Polish (Telemetry/UX) & Performance Budgeting.

#### 1. EDM Queue Monitoring
- [ ] **Subtask:** Implement `EDMMetrics` using the `prometheus` crate.
    - Fields: `edm_queue_depth` (Gauge), `edm_processing_latency` (Histogram).
- [ ] **Subtask:** Instrument `NarrativeWorker` to report depth/latency on every poll/completion.

#### 2. Scaling Infrastructure
- [ ] **Subtask:** Expose `/metrics` endpoint in `health.rs` (protected by internal subnet check or authentication).
- [ ] **Subtask:** Define Kubernetes HPA (Horizontal Pod Autoscaler) or cloud-native scaling rules targeting `edm_queue_depth > 10`.

#### 3. Verification
- [ ] **Subtask:** Load test: Simulate 500 concurrent chat requests and verify worker auto-scaling.
- [ ] **Subtask:** Verify "Near-Instant" UX metrics: Confirm p99 latency for initial request acceptance remains < 100ms.

---

## Verification Plan [UPDATED]

### Automated Tests
- `cargo test --features cloud,otel` - Verify OTLP layer initialization and spans.
- `cargo test --features desktop` - Ensure zero OTLP leakage in the Tauri binary.
- `cargo test test_otel_redaction_flow` - Verify PII redaction pipeline.

### Manual Verification
1. **AI Tracing:** Trigger chat in staging, verify traces in Jaeger (masked).
2. **Context Budgets:** Verify "discarded" warnings in logs when tokens exceed budget.
3. **Redaction:** Verify `user_id` and `user_email` are redacted in exported span attributes.
