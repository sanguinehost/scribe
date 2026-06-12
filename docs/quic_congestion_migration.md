# Technical Audit: QUIC Transport (BBRv2 & Connection Migration) for SHNA Hardening

## 1. Executive Summary
This document synthesizes architectural paradigms from Google's `quiche` implementation of IETF QUIC to harden the **Scribe Holographic Networking Architecture (SHNA)**. We focus on maximizing throughput over unstable UDP meshes (BBRv2) and maintaining cryptographic state persistence across mobile network transitions (Connection Migration).

---

## 2. BBRv2 Congestion Control: Throughput Maximization over UDP
BBRv2 (Bottleneck Bandwidth and Round-trip propagation time) shifts the congestion control paradigm from loss-based (Cubic) to model-based. This is critical for Scribe's **Fluctuation-Dissipation Sybil Defense** (§2.5 of SHNA RFC), which treats adversarial traffic as thermal noise.

### 2.1. The Network Model (`Bbr2NetworkModel`)
`quiche/quic/core/congestion_control/bbr2_misc.h` defines the `Bbr2NetworkModel`, which continuously tracks:
- **Max Bandwidth**: Filtered over multiple round-trips to find the path capacity.
- **Min RTT**: The lowest observed latency, representing the physical path length without queueing.
- **BDP (Bandwidth-Delay Product)**: Calculated as `MaxBandwidth * MinRtt`. This represents the "optimal" amount of data in flight.

### 2.2. Mode-Based State Machine (`Bbr2Sender`)
BBRv2 operates in four distinct modes to navigate the throughput/delay curve:
1. **STARTUP**: Exponential growth (pacing gain ~2.885x) to quickly discover capacity.
2. **DRAIN**: Reduces pacing to clear queues formed during STARTUP.
3. **PROBE_BW**: The steady state. Cycles through pacing gains (1.25x, 0.9x, 1.0x) to probe for bandwidth changes while maintaining low latency.
4. **PROBE_RTT**: Periodically drops CWND to 4 packets to clear the bottleneck queue and re-measure the "true" Min RTT.

### 2.3. Applicability to SHNA
- **Action Gradient Propagation**: SHNA's $\nabla \phi$ packets should be paced using BBRv2's `pacing_rate_`. This ensures that "Action Waves" do not congest the physical medium.
- **Sybil Dissipation**: BBRv2's `bandwidth_lo` and `inflight_hi` mechanics (triggered by loss > 2%) provide a mathematical basis for the `allocation_gate` in SHNA RFC §3.6. By mapping Sybil noise to BBR's "excessive loss" state, we can forcibly dissipate adversarial gradients.

---

## 3. Connection Migration: P2P Mesh Persistence
QUIC enables "Zero-Latency" migration where a session remains cryptographically unbroken despite IP changes. This is achieved by decoupling the transport session from the network 5-tuple.

### 3.1. Connection ID (CID) Routing
In `quiche/quic/core/quic_connection.h`, the session is identified by a 64-bit to 160-bit `ConnectionID`. 
- **Paradigm**: When a packet arrives from a new `IP:Port` but contains a known `CID`, the connection object is retrieved from the `QuicDispatcher` map.
- **Security**: To prevent spoofing, the server issues multiple "Unused" CIDs to the client. The client switches to a *new* CID when it switches to a *new* network path, preventing linkability (privacy) and ensuring the peer owns the new CID.

### 3.2. Path Validation Protocol
1. **Trigger**: `QuicConnection::ProcessUdpPacket` detects a source address change.
2. **Challenge**: `QuicPathValidator` sends a `PATH_CHALLENGE` frame containing an 8-byte random nonce to the new address.
3. **Response**: The client must respond with a `PATH_RESPONSE` echo.
4. **Migration**: Upon validation, `QuicSentPacketManager::OnConnectionMigration` resets the RTT stats and probes the new path's MTU.

### 3.3. Applicability to SHNA
- **Entanglement Coordinate Persistence**: Mobile Scribe agents transitioning from Wi-Fi to Cellular must maintain their "Entanglement Coordinate" in AdS space.
- **Slotine Bridge Integration**: Connection migration provides the "Event Horizon" detection needed for the Slotine Bridge recovery (§2.4). When a path is lost, the node enters "Orthogonal Superposition" until a new path is validated, at which point it requests the `Conjugate Momentum` ($\lambda$) to perform the $O(1)$ adjoint update.

---

## 4. Implementation Strategy (Rust/Scribe)

### 4.1. Mapping to `quinn` (Rust)
The Scribe networking layer should utilize `quinn`'s `Connection` and `Endpoint` structs:
- **Pacing**: Enable `quinn`'s BBR implementation (via `quinn-proto`).
- **Migration**: Utilize `quinn`'s `Endpoint::accept` and `Connection::remote_address` change events. Ensure `ConnectionId` generation follows the IETF RFC 9000 standard.

### 4.2. Hardening Constraints
- **Zero-Copy Serialization**: Map QUIC's `QuicheBuffer` to Scribe's `ActionGradient` tensor layout to avoid allocation overhead during $O(1)$ updates.
- **Multiplexed Action Streams**: Use QUIC streams to isolate different "Twin Thoughts." If one stream experiences loss, others continue, preventing "Head-of-Line" blocking in the holographic state.

---
**References**:
- Google Quiche: `quiche/quic/core/congestion_control/bbr2_sender.cc` (L300-365)
- Google Quiche: `quiche/quic/core/http/quic_connection_migration_manager.cc` (L365-407)
- SHNA RFC: `~/Workspace/sanguine/docs/src/SHNA_RFC.md`
