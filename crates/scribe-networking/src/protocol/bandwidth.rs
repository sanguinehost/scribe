use serde::{Deserialize, Serialize};
use crate::error::NetworkResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthRequest {
    pub node_id: String,
    pub priority: f64, // 0.0 to 1.0
    pub requested_mbps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthAllocation {
    pub node_id: String,
    pub allocated_mbps: f64,
    pub price_per_mb: f64,
}

pub struct StackelbergAllocator {
    pub total_capacity_mbps: f64,
    pub base_price: f64,
}

impl StackelbergAllocator {
    pub fn new(total_capacity_mbps: f64, base_price: f64) -> Self {
        Self {
            total_capacity_mbps,
            base_price,
        }
    }

    /// Simplified Stackelberg allocation:
    /// 1. Followers submit requests with priority.
    /// 2. Leader calculates price based on total demand.
    /// 3. Leader allocates bandwidth based on priority and demand-to-capacity ratio.
    pub fn allocate(&self, requests: &[BandwidthRequest]) -> Vec<BandwidthAllocation> {
        let total_requested: f64 = requests.iter().map(|r| r.requested_mbps).sum();
        
        // Price increases as demand approaches/exceeds capacity
        let price_multiplier = if total_requested > 0.0 {
            (total_requested / self.total_capacity_mbps).max(1.0)
        } else {
            1.0
        };
        let current_price = self.base_price * price_multiplier;

        let allocation_factor = if total_requested > self.total_capacity_mbps {
            self.total_capacity_mbps / total_requested
        } else {
            1.0
        };

        requests.iter().map(|r| {
            // Priority can also influence allocation in more complex models
            let allocated = r.requested_mbps * allocation_factor * (0.5 + 0.5 * r.priority);
            BandwidthAllocation {
                node_id: r.node_id.clone(),
                allocated_mbps: allocated.min(r.requested_mbps),
                price_per_mb: current_price,
            }
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_allocation() {
        let allocator = StackelbergAllocator::new(100.0, 0.1);
        let requests = vec![
            BandwidthRequest { node_id: "node1".into(), priority: 1.0, requested_mbps: 60.0 },
            BandwidthRequest { node_id: "node2".into(), priority: 0.5, requested_mbps: 60.0 },
        ];

        let allocations = allocator.allocate(&requests);
        assert_eq!(allocations.len(), 2);
        
        let total_allocated: f64 = allocations.iter().map(|a| a.allocated_mbps).sum();
        assert!(total_allocated <= 100.1); // Allowing for floating point precision
    }
}
