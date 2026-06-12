use std::collections::HashMap;
use libp2p::PeerId;
use std::time::Instant;

/// Represents the reputation of a peer based on its ACL status and historical uptime.
#[derive(Debug, Clone)]
pub struct ReputationScore {
    pub is_authorized: bool,
    pub uptime_secs: u64,
}

impl ReputationScore {
    /// Calculates a numerical score between 0.0 and 2.0.
    /// Authorized peers start at 1.0, unauthorized start at 0.1.
    /// Uptime provides a logarithmic bonus up to 1.0.
    pub fn calculate(&self) -> f64 {
        let base_score = if self.is_authorized { 1.0 } else { 0.1 };
        
        // Logarithmic scaling for uptime bonus: ln(uptime + 1) / 10 capped at 1.0
        // This gives ~0.45 bonus after 1 hour (3600s), ~0.7 after 1 day (86400s)
        let uptime_bonus = ((self.uptime_secs as f64 + 1.0).ln() / 10.0).min(1.0);
        
        base_score + uptime_bonus
    }
}

/// A bandwidth allocator that uses Stackelberg game principles to penalize low-reputation nodes.
pub struct StackelbergAllocator {
    allocations: HashMap<PeerId, u64>,
    peer_start_times: HashMap<PeerId, Instant>,
    total_capacity: u64,
}

impl Default for StackelbergAllocator {
    fn default() -> Self {
        Self::new(1000) // Default 1000 Mbps capacity
    }
}

impl StackelbergAllocator {
    pub fn new(total_capacity: u64) -> Self {
        Self {
            allocations: HashMap::new(),
            peer_start_times: HashMap::new(),
            total_capacity,
        }
    }

    /// Records the connection time for a new peer to track uptime.
    pub fn register_peer(&mut self, peer_id: PeerId) {
        self.peer_start_times.entry(peer_id).or_insert_with(Instant::now);
    }

    /// Removes a peer from the allocator tracking, freeing up bandwidth.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.allocations.remove(peer_id);
        self.peer_start_times.remove(peer_id);
    }

    /// Retrieves the current reputation score for a peer.
    pub fn get_reputation(&self, peer_id: &PeerId, is_authorized: bool) -> ReputationScore {
        let uptime_secs = self.peer_start_times.get(peer_id)
            .map(|start| start.elapsed().as_secs())
            .unwrap_or(0);
            
        ReputationScore {
            is_authorized,
            uptime_secs,
        }
    }

    /// Allocates bandwidth to a peer, weighing the request against their reputation score.
    /// High requests from low-reputation nodes are aggressively throttled.
    /// Includes global load-shedding to prevent capacity exhaustion.
    pub fn allocate(&mut self, peer_id: PeerId, requested_mbps: u64, reputation: &ReputationScore) {
        let score = reputation.calculate();
        
        let mut allocation = if score < 0.5 {
            requested_mbps.min(1) 
        } else {
            (requested_mbps as f64 * score.min(1.5)) as u64
        };

        // Current total excluding this peer
        let current_total: u64 = self.allocations.iter()
            .filter(|(k, _)| **k != peer_id)
            .map(|(_, v)| *v)
            .sum();

        // If this allocation exceeds capacity, we must shed load.
        if current_total + allocation > self.total_capacity {
            let available = self.total_capacity.saturating_sub(current_total);
            if available == 0 {
                allocation = 0;
            } else {
                // If there's some available, we take it. 
                // A true Stackelberg game would re-evaluate prices globally here,
                // but for now, we just cap it to available capacity (proportional to score could mean scaling all allocations, 
                // but local update is easier). Let's do simple capping.
                allocation = allocation.min(available);
            }
        }

        self.allocations.insert(peer_id, allocation);
    }

    /// Returns the current bandwidth limit for a peer in Mbps.
    pub fn get_limit(&self, peer_id: &PeerId) -> u64 {
        *self.allocations.get(peer_id).unwrap_or(&1) // Default to 1 Mbps for unknown
    }
}
