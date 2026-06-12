# Scribe Networking Equations & Theoretical Baseline

## FoolsGold (Mitigating Sybils in Federated Learning Poisoning)
The FoolsGold algorithm dynamically adjusts the learning rate (or bandwidth weight) based on the cosine similarity of historical updates.

### Equations:
1. **Historical Gradient Vector:**
   $H_i = \sum_{t=1}^T \nabla_{i,t}$
   The aggregated historical updates for client $i$ up to iteration $T$.

2. **Weighted Cosine Similarity:**
   $cs_{ij} = \text{cosine\_similarity}(H_i, H_j)$
   Evaluated over the set of indicative features $S_t$.

3. **Maximum Similarity Score:**
   $v_i = \max_{j \neq i} (cs_{ij})$

4. **Pardoning Mechanism:**
   If an honest client update happens to be similar to a sybil's update, it is pardoned:
   If $v_j > v_i$, then $cs_{ij} = cs_{ij} \times \frac{v_i}{v_j}$
   Then $v_i$ is re-evaluated.

5. **Client Weight (Learning Rate):**
   $\alpha_i = 1 - \max_j (cs_{ij})$
   Rescaled: $\alpha_i = \frac{\alpha_i}{\max_i(\alpha_i)}$

6. **Logit Transformation:**
   $\alpha_i = \ln\left(\frac{\alpha_i}{1 - \alpha_i}\right) + 0.5$

## Stackelberg Bandwidth Allocation (Theoretical)
A true Stackelberg game consists of a Leader (allocator) and Followers (peers). 
The leader sets a price $p$ to maximize utility $U_L$, knowing the followers will respond with a best-response demand $B_F(p)$.

1. **Follower Utility:**
   $U_F(x) = \text{Value}(x) - p \cdot x$
   Where $x$ is the allocated bandwidth. Follower maximizes this to find $B_F(p)$.

2. **Leader Utility:**
   $U_L(p) = \sum_{i} p \cdot B_{F,i}(p) - C\left(\sum_i B_{F,i}(p)\right)$
   Where $C$ is the cost function (e.g., congestion).

## Implementation Discrepancies (Theoretical Vacuousness)

1. `protocol/bandwidth.rs: StackelbergAllocator` 
   - **Observation 1:** The `StackelbergAllocator` implements an arbitrary heuristic: `let allocation = if score < 0.5 { requested.min(1) } else { requested * score }`.
   - **Observation 2:** This is theoretically vacuous. There is no Leader Utility function, no Follower Best-Response function, and no pricing mechanism to enforce an equilibrium. It is a simple if-else throttle misnamed as a "Stackelberg Allocator".
   - **Observation 3:** Reputation relies on `((uptime + 1.0).ln() / 10.0)`, which has no game-theoretic basis for sybil resistance compared to FoolsGold.

2. `protocol/bandwidth.rs: Global Capacity`
   - **Observation 1:** The allocator lacks a constrained optimization limit (e.g., $\sum x_i \leq C_{max}$). 
   - **Observation 2:** Without this, the system is highly vulnerable to Sybil exhaustion, as the total bandwidth $\sum_i \min(1, \dots)$ is unbounded.

3. `crdt.rs: CrdtDelta`
   - **Observation 1:** Deltas are merged directly without cosine similarity checks or FoolsGold sybil filtering.
   - **Observation 2:** No key-level authorization means $U_{poison}$ is unrestricted for any authorized node.
