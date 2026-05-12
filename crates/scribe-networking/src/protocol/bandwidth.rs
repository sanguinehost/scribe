use std::collections::HashMap;
use libp2p::PeerId;

pub struct BandwidthAllocation {
    allocations: HashMap<PeerId, u64>,
}

impl BandwidthAllocation {
    pub fn new() -> Self {
        Self {
            allocations: HashMap::new(),
        }
    }

    pub fn allocate(&mut self, peer_id: PeerId, limit: u64) {
        self.allocations.insert(peer_id, limit);
    }

    pub fn get_limit(&self, peer_id: &PeerId) -> u64 {
        *self.allocations.get(peer_id).unwrap_or(&1024) // Default limit
    }
}
