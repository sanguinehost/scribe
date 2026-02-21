# Scribe Observability & Durability Architecture

**Status:** Draft / Principal Review
**Version:** 1.0.0
**Owner:** Engineering Leadership

## Executive Summary

Scribe utilizes a unified telemetry and orchestration architecture designed for **Privacy-at-the-Edge**, **Global Resiliency**, and **Platform Parity**. By standardizing on OpenTelemetry (OTLP) and an Embedded Durable Machine (EDM), we ensure that observability and reliability are intrinsic properties of the system rather than bolt-on infrastructure.

---

## 1. Telemetry Philosophy: OTLP-First

We reject vendor-specific agents (CloudWatch, DataDog, New Relic) in favor of the **OpenTelemetry Protocol (OTLP)**.

### 1.1 SDK-Level Redaction (Privacy-at-the-Edge)
To comply with strict privacy requirements, all telemetry data is intercepted at the application memory boundary.
- **Pattern:** Custom `PrivacyRedactionProcessor` within the OTel pipeline.
- **Constraint:** Raw PII (Emails, User IDs, Prompts) must *never* reach the network buffer in unredacted form.
- **Implementation:** Attributes like `user_id` are hashed or obfuscated (e.g., `u8a3f2xx`), and `content` fields are strictly size-logged without contents.

### 1.2 Instrumentation Standards
- **Spans:** Represent units of work with high-cardinality metadata (e.g., `lorebook_id`, `token_count`).
- **Events:** Represent point-in-time occurrences within a span (e.g., "Context Truncated", "Decryption Start").
- **Attributes:** Key-value pairs following the [OTel Semantic Conventions](https://opentelemetry.io/docs/specs/otel/common/semantic-conventions/).

---

## 2. Orchestration: Embedded Durable Machine (EDM)

Replacing heavy sidecar-based workflow engines (Temporal) with a library-based, database-backed durable machine.

### 2.1 The "Checkpoint & Heartbeat" Model
Inspired by Temporal's state machines and Effectum's SQLite persistence:
- **Persistence:** Uses Diesel for dual-backend support (SQLite for Desktop, Postgres for Cloud).
- **Task Acquisition:** Mediated by a `TaskStore` trait.
    - **Postgres:** Uses `FOR UPDATE SKIP LOCKED` for horizontal scalability.
    - **SQLite:** Uses an atomic `UPDATE ... RETURNING` pattern for local concurrency.
- **Checkpoints:** After every state transition, the `DurableWorkflow` state is serialized, encrypted with `SessionDEK`, and persisted to `narrative_tasks.current_state`.
- **Heartbeats:** Background tasks update an `expires_at` timestamp.

### 2.2 Trace Context Propagation
To maintain causal links across background boundaries, the system implements **Durable Context Propagation**:
- When a task is enqueued, the current **W3C Trace Context** is serialized into the `trace_context` column.
- When a worker claims a task, it restores the `parent_context` from the DB, ensuring the background spans are correctly nested under the originating HTTP request.

---

## 3. Security & Compliance Alignment

### 3.1 OWASP LLM Top 10 Redlines
- **LLM02: Sensitive Information Disclosure:** Prevented via SDK Redaction.
- **LLM10: Unbounded Consumption:** Mitigated via unified `token_usage` spans exported to **OpenObserve** for real-time alerting.

### 3.2 Data Sovereignty
- **Regional Collectors:** Telemetry is exported to regional OTLP collectors to minimize cross-border data transfer of even redacted metadata.

---

## 4. Aggregator Stack: OpenObserve (S3-Native)

To scale with Scribe's high-throughput narrative engine without the operational complexity of ClickHouse or ELK, we utilize **OpenObserve**.

### 4.1 Scaling & Efficiency
- **Architecture:** Stateless compute nodes querying Apache Parquet files on S3/MinIO.
- **Throughput:** Capable of handling hundreds of thousands of events/sec per node (5-10x faster than Elasticsearch).
- **Cost:** Significant storage reduction via zero-indexing; only metadata and Parquet columnar headers are indexed.
- **Parity:** Built in Rust, allowing for potential integration of shared crates between the aggregator and the Scribe backend.

---

## 4. Platform Parity (Cloud vs Desktop)

| Feature | Cloud (Postgres) | Desktop (SQLite) |
| :--- | :--- | :--- |
| **Telemetry** | Enabled (OTLP Sink) | Disabled (Local Logs Only) |
| **Persistence** | Distributed Postgres | Local SQLite File |
| **Encryption** | KMS-backed DEKs | User-derived Keys |
| **Durability** | Multi-worker Failover | Process Restart Recovery |

---

## 5. Implementation Methodology

All observability and durability features follow the **High-Level SDLC**:
1. **Domain Modeling:** Define types and trait bounds first.
2. **MVC Spike:** Prove logic in a mock DB environment.
3. **Hardening:** Implementation with OTel instrumentation.
4. **Invariant Verification:** Property-based testing for state transitions.
