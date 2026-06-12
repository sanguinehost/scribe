# QUIC Transport Reconnaissance: Congestion Control & Connection Migration

## 1. Executive Summary
This document synthesizes architectural findings from Google's `quiche` implementation of the IETF QUIC protocol to harden the Scribe SHNA (Holographic Networking Architecture) transport layer. Focus is placed on BBRv2/v3 congestion control and the IETF QUIC connection migration mechanism to ensure unbroken state synchronization for mobile P2P nodes.

## 2. Congestion Control Audit: BBRv2/v3
`quiche` implements BBR (Bottleneck Bandwidth and Round-trip propagation time) as its primary model-based congestion control algorithm.

### 2.1. Model-Based Estimation
Unlike Reno or Cubic, which react to packet loss as a primary signal, BBRv2/v3 builds a mathematical model of the network path:
- **Max Bandwidth**: Tracked via `Bbr2MaxBandwidthFilter` (`bbr2_misc.h:299`) using a windowed max filter over recent delivery rates.
- **Min RTT**: Tracked via `MinRttFilter` (`bbr2_misc.h:280`) during periodic `PROBE_RTT` phases.
- **BDP (Bandwidth Delay Product)**: Computed as `MaxBandwidth * MinRtt`. This represents the "volume" of the physical pipe.

### 2.2. Pacing-First Architecture
BBR uses pacing as the primary mechanism for injection control:
- **Pacing Rate**: `pacing_rate = BandwidthEstimate * PacingGain`.
- **Application to SHNA**: This maps directly to the **Fluidic Viscosity** concept in SHNA. The `pacing_rate` determines the "laminar flow" of Action Gradients ($\nabla\phi$). By adopting a model-based pacing, Scribe nodes can maintain a steady stream of state updates without inducing self-congestion.

### 2.3. Loss and ECN Handling (BBRv2+)
BBRv2 introduced `inflight_hi` and `inflight_lo` bounds (`bbr2_misc.h:627`) to respond to loss and ECN signals.
- **Inflight Hi**: A dynamic upper bound on bytes-in-flight, reduced upon detecting excessive loss or ECN CE marks.
- **Utility**: In Scribe's P2P mesh, where nodes may be subject to adversarial noise (Sybil attacks), these bounds act as the **Fluctuation-Dissipation** gate described in `SHNA_RFC.md §2.5`.

## 3. Connection Migration Architecture
QUIC's ability to survive IP/Port changes without dropping the cryptographic handshake is vital for mobile Scribe agents.

### 3.1. Connection ID Stability
- **Mechanism**: Connections are identified by a 64-bit `Connection ID` (`quic_connection.cc:5338`) rather than the 4-tuple (SrcIP, SrcPort, DstIP, DstPort).
- **Handshake Continuity**: Because the TLS 1.3 state is bound to the Connection ID, a client switching from Wi-Fi to Cellular can continue sending encrypted data immediately.

### 3.2. Path Validation Protocol
To prevent reflection/amplification attacks, `quiche` implements a 3-way path validation:
1. **Detection**: `QuicConnection::StartEffectivePeerMigration` is triggered by a packet from a new address (`quic_connection.cc:5480`).
2. **PATH_CHALLENGE**: The receiver sends a challenge frame containing random bytes (`quic_connection.cc:5349`).
3. **PATH_RESPONSE**: The sender must echo the bytes.
4. **Validation**: Until validated, the path is subject to **Anti-Amplification Limits** (typically 3x the bytes received from the new path).

### 3.3. State Transition Logic
- **RTT Reset**: `RttStats::OnConnectionMigration` (`rtt_stats.cc:99`) resets smoothed RTT and variance to account for different physical path characteristics.
- **CWND Handling**: `sent_packet_manager_.OnConnectionMigration` resets the congestion window to the initial value (typically 10-32 packets) to probe the new path's capacity safely.

## 4. SHNA Integration: Hardening the Scribe Layer

### 4.1. Unbroken Action Propagation
SHNA's **Continuous Action Propagation (CAP)** requires a steady stream of rotors ($GL_2(\mathbb{R})$). Connection migration allows the "Hamiltonian worldline" of a Twin to remain continuous across network transitions.
- **Strategy**: Scribe should implement the QUIC Connection ID mechanism at the SHNA header level (`SHNA_RFC.md §3.2`). The `Twin ID` can serve as the primary Connection ID or be mapped to a session-specific `Path ID`.

### 4.2. Zero-Latency Re-projection
- **Mapping**: The **Entanglement Zone (AdS Coord)** in SHNA can be viewed as a logical path identifier.
- **Optimization**: Instead of triggering a **Slotine Bridge** ($O(1)$ adjoint update) for every network hop, the node should use QUIC-style migration to maintain the current Action Gradient flow. The Slotine Bridge should remain a fallback for *temporal* disconnects where the node is completely offline for $\Delta t > RTT$.

### 4.3. Anti-Amplification as Sybil Defense
The QUIC `PATH_CHALLENGE` mechanism should be integrated into the **Ryu-Takayanagi Entanglement Handshake** (`SHNA_RFC.md §3.3`).
- **Advantage**: It forces peers to prove ownership of their "Entanglement Coordinate" before the Bulk State is projected onto them, mitigating "Gravitational Hijacking" where a Sybil node attempts to sink the network's bandwidth.

## 5. Implementation Roadmap for Scribe Rust
1. **Transport Backend**: Leverage `quinn` (Rust implementation of QUIC) as the baseline for SHNA's UDP overlay.
2. **Path Migration**: Implement a `PathManager` in Scribe that mimics `QuicConnectionMigrationManager` to handle multi-homing and seamless handover.
3. **Pacing Engine**: Implement a BBRv3-inspired pacing loop for `PROPAGATE` calls to ensure "Fluidic Viscosity" compliance.
