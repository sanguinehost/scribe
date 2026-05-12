# Epic: Scribe Networking Trinity — Hardening & Structural Evolution

This document defines the architectural continuation of the **Scribe Networking Trinity** Epic. Having established the foundational P2P bridge, CRDT synchronization, and Stackelberg bandwidth allocation, we now move to the hardening and optimization phases. 

In accordance with the **Prime Directive**, this plan enforces strict invariant testing over simple heuristics and relies on the Wave-based Agentic Chain to prevent integration conflicts.

---

## 1. Context & Architectural Mandate

Recent adversarial testing and ArXiv-backed structural analysis (e.g., *TreeP Hierarchies*, *FoolsGold Sybil Mitigation*) revealed that while the `scribe-networking` baseline is functional, it requires rigorous cryptographic bounds and a shift toward a **Hierarchical Sharded Topology** to survive in an adversarial, high-throughput environment.

> [!IMPORTANT]
> **Security Mandate:** AI agents executing these waves MUST assume a zero-trust network. Every payload must be treated as potentially malicious, requiring explicit validation of time (TTL), origin (ACL), and uniqueness (Nonces).

---

## 2. Wave 4: The Fortress (Security Hardening)

This wave focuses on mitigating deterministic vectors: Replay Attacks, Clock-Drift Poisoning, and Unauthorized Sybil Injections.

### Agent 4.1: Invariant State Validation & Replay Mitigation
**Task:** Harden the CRDT and Twin Migration Protocol against temporal manipulation.
*   **Subtask 1 (Clock-Drift):** Implement a `max_future_offset` (e.g., 60 seconds) in `CRDT::merge`. Reject updates exceeding this bounds to prevent Last-Write-Wins poisoning.
*   **Subtask 2 (Replay Protection):** Expand `TwinPayload` to include `nonce` (UUID v4) and `expires_at` (TTL). Update `TwinMigrationProtocol::verify_payload` to reject expired payloads.
*   **Mathematical Debugging:** Create adversarial `proptest` suites simulating extreme clock drift and duplicate payload injections. Ensure the invariants hold under continuous fuzzing.

### Agent 4.2: The Aegis Access Control List (ACL)
**Task:** Establish the Root of Trust for digital twin migration.
*   **Subtask 1:** Implement an `AccessControlList` module in `src/protocol/acl.rs` that maintains a whitelist of authorized Kademlia `PeerId`s.
*   **Subtask 2:** Integrate the ACL check directly into the P2P event loop (`p2p.rs`). Drop Gossipsub messages originating from unknown or unauthorized peers before they reach the CRDT layer.
*   **Subtask 3:** Write integration tests proving that validly signed payloads are rejected if the signing key is not present in the active ACL.

---

## 3. Wave 5: Hierarchical Scribe Overlay (Structural Optimization)

This wave transitions the network from a flat DHT to a localized, sharded hierarchy to drastically reduce bandwidth consumption and state-sync latency.

### Agent 5.1: Zonal Sharding & Gossip Isolation
**Task:** Implement spatial/affinity partitioning for the P2P overlay.
*   **Subtask 1:** Refactor the `NetworkManager` to subscribe to dynamic Gossipsub topics based on "Metaverse Zones" (e.g., `scribe-zone-<hash>`) rather than a global broadcast channel.
*   **Subtask 2:** Ensure Kademlia is still used for global node discovery, but state-sync traffic is strictly isolated to the node's current zone.
*   **Subtask 3:** Verify zone-transition invariants: when an agent moves zones, they must reliably unsubscribe from the old mesh and resync with the new mesh.

### Agent 5.2: Delta-CRDT Synchronization
**Task:** Eliminate redundant data transmission over the wire.
*   **Subtask 1:** Refactor the `CrdtState` synchronization logic. Instead of broadcasting the entire `HashMap` of registers, implement a diffing engine that yields `CrdtDelta` payloads.
*   **Subtask 2:** Update the Gossipsub publisher to broadcast deltas. Update the receiver to apply deltas to the local LWW-Register map.
*   **Subtask 3:** Implement structural tests ensuring that a sequence of applied deltas results in the exact same deterministic state as a full hashmap merge.

### Agent 5.3: Reputation-Weighted Bandwidth Allocation
**Task:** Prevent Resource Exhaustion griefing in the Stackelberg allocator.
*   **Subtask 1:** Integrate the peer's ACL standing and historical uptime into a `ReputationScore`.
*   **Subtask 2:** Modify `StackelbergAllocator::allocate` to weigh `requested_mbps` against the `ReputationScore`. Nodes that request excessive bandwidth with low reputation must be aggressively throttled.
*   **Subtask 3:** Simulate a Sybil bandwidth attack in `tests/p2p_migration.rs` and verify the allocator successfully defends the legitimate nodes.

---

## 4. Execution Protocol

> [!CAUTION]
> **Worktree Hygiene:** Agents assigned to these tasks MUST execute their work in isolated git worktrees (e.g., `feat/wave4-security`, `feat/wave5-sharding`). Ensure `cargo test -p scribe-networking` executes cleanly, without warnings, prior to concluding the sprint.
