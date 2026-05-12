# Agentic Reference: Engineering Methodology

The methodology employed transitions a task from a simple **request-response** pattern into a formal **Engineering Lifecycle**. By rejecting "low-effort" immediate fixes, the process enforces a rigorous standard of proof and verification that mirrors a high-level software development lifecycle (SDLC).

## 1. The Strategy: From Fixer to Architect

Depending on whether a task involves addressing a regression (Fixing) or building a new capability (Engineering), the focus shifts between **Reproduction of Failure** and **Verification of Invariants**.

| Phase | Security/Fixing Focus | New Feature Focus |
| --- | --- | --- |
| **Step 1** | Blast Radius (Who can be pwned?) | Domain Modeling (What are the types?) |
| **Step 2** | Failure PoC (Proof of Exploit) | MVC Spike (Proof of Concept) |
| **Step 3** | Hardening (Removing the bug) | Implementation (Building the engine) |
| **Step 4** | Regression (Is the hole closed?) | Invariant Verification (Does it always work?) |
| **Step 5** | Security Polish (Logs/Alerts) | Architectural Polish (Telemetry/UX) |

---

## Phase-Specific Breakdown: New Feature Engineering

To build entirely new features (like the Embedded Durable Machine), the methodology focuses on proving that logic is mathematically sound and architecturally compatible before it touches the main branch.

### 1. Domain Modeling and Constraint Mapping
Perform an architectural impact analysis of the new capability.
* **Type-Driven Design:** Define Algebraic Data Types (ADTs) and Trait bounds first. In Rust, encode business logic into the type system to ensure "illegal states are unrepresentable."
* **Dependency Surface Area:** Map interactions with persistence layers (Diesel) and the async runtime (Tokio).
* **Performance Budgeting:** Establish expected asymptotic complexity and memory footprint. Define state transition functions for stateful systems.

### 2. The Minimum Viable Capability (MVC) Spike
Prove the core logic can execute in a vacuum (the "Functional PoC").
* **Logic Isolation:** Create a standalone test binary/module to exercise the core algorithm without database or frontend overhead.
* **Happy Path Verification:** Prove viability under current constraints.
* **Stubbed Environment:** Use mock traits to simulate I/O or latency.

### 3. Core Engine Implementation (Idiomatic Rust)
Flesh out the implementation focusing on zero-cost abstractions and memory safety.
* **Memory Layout:** Address alignment and padding in structs (especially for JSONB serialization).
* **Error Propagation:** Use context-aware, zero-allocation Enums. Ensure "panic-proof" operations with the `?` operator.
* **Static Dispatch:** Prefer Generics and Traits over `Box<dyn Trait>` for inlining and performance.

### 4. Invariant and Property-Based Testing
Replace simple regression testing with invariant verification.
* **Property-Based Testing:** Use tools like `proptest` to verify the state machine against thousands of random inputs.
* **Integration Spikes:** Integrate with the Diesel schema and verify ACID transaction atomicity.
* **State Sync Check:** Verify database state matches in-memory representation after "yield" points.

### 5. Architectural Alignment and Polishing
Ensure the feature feels like a native part of the Scribe platform.
* **CLI and Telemetry:** Add OTel tracing to visualize flows.
* **Style and Linting:** Strict adherence to `clippy::pedantic` and `clippy::nursery`.
* **PR Narrative:** Explain "First Principles" reasoning for implementation choices (e.g., "Why EDM over Temporal").

---

## Phase-Specific Breakdown: Security & Regression Fixing

For addressing vulnerabilities or bugs, the focus is on empirical proof of failure.

### 1. Contextual Impact Analysis (The "Blast Radius" Check)
* **Dependency Mapping:** Identifying every consumer of the component.
* **Tenet Alignment:** Alignment with performance-first and zero-cost abstraction tenets.
* **Failure Reachability:** Determining how the bug is reached through the call chain.

### 2. Isolated Proof of Concept (The "Empirical" Phase)
* **Failure Reproduction:** Create a standalone environment/script that proves the current state is broken.
* **Sandbox Testing:** Validate logic in isolation without environment constraints.

### 3. Idiomatic Implementation (The "Senior Engineer" Phase)
* **Precision Fix:** Implement with focus on precision and language idioms.
* **Observability:** Custom exception types to distinguish failure modes.

### 4. Post-Implementation Verification (The "Regression" Phase)
* **Negative Testing:** Verify rejection of malformed/malicious inputs.
* **Regression Suite:** Ensure legacy functionality remains intact.

### 5. Aesthetic and PR Polish
* **Compliance:** Ruff/Clippy/Rustfmt standards.
* **Documentation:** Google-style docstrings and clear PR descriptions.
