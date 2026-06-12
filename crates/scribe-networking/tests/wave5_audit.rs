use scribe_networking::{
    crdt::{CrdtState, CrdtDelta, LwwRegister},
    protocol::bandwidth::{StackelbergAllocator, ReputationScore},
};
use libp2p::PeerId;

#[test]
fn audit_allocator_capacity_exhaustion() {
    let mut allocator = StackelbergAllocator::new(1000);
    
    // Simulate a Sybil attack where 10,000 unauthorized nodes request bandwidth
    let mut total_allocated = 0;
    for _ in 0..10_000 {
        let peer = PeerId::random();
        let rep = ReputationScore { is_authorized: false, uptime_secs: 0 };
        allocator.allocate(peer, 1000, &rep);
        total_allocated += allocator.get_limit(&peer);
    }
    
    // Total allocated is 10,000 Mbps! A single node's bandwidth is easily exhausted.
    // The allocator missing a `total_capacity` check is a critical vulnerability.
    assert!(total_allocated <= 1000, "CRITICAL: Allocator does not enforce global capacity limits. Total allocated: {}", total_allocated);
}

#[test]
fn audit_crdt_delta_size_exhaustion() {
    let mut state = CrdtState::default();
    
    // A malicious authorized node sends a delta with 1 million keys
    let mut malicious_delta = CrdtDelta {
        registers: std::collections::HashMap::new(),
    };
    
    for i in 0..100_000 {
        malicious_delta.registers.insert(
            format!("spam_key_{}", i), 
            LwwRegister::new(serde_json::json!("spam_data_that_takes_up_memory"))
        );
    }
    
    let peer = PeerId::random();
    let mut acl = scribe_networking::protocol::acl::AccessControlList::new(vec![]);
    acl.authorize_prefix(peer, "spam_key".to_string());
    
    // Applying this delta should fail due to OOM/DoS mitigations
    let result = state.apply_delta(malicious_delta, &peer.to_string(), &acl);
    
    assert!(result.is_err(), "CRITICAL: apply_delta should fail on massive payloads");
}
