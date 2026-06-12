use scribe_networking::crdt::{CrdtState, MAX_FUTURE_OFFSET};
use serde_json::json;
use chrono::{Utc, Duration};
use scribe_networking::protocol::acl::AccessControlList;
use libp2p::PeerId;

#[test]
fn test_delta_sync_equivalence() {
    let mut state_a = CrdtState::default();
    let mut state_b = CrdtState::default();

    // 1. Initial updates on A
    state_a.update("key1".into(), json!("value1"));
    state_a.update("key2".into(), json!("value2"));

    // 2. Diff A against B (empty)
    let delta = state_a.diff(&state_b);
    assert_eq!(delta.registers.len(), 2);

    let peer = PeerId::random();
    let mut acl = AccessControlList::new(vec![]);
    acl.authorize(peer);
    
    // 3. Apply delta to B
    state_b.apply_delta(delta, &peer.to_string(), &acl).unwrap();

    // 4. Verify states are identical
    assert_eq!(serde_json::to_value(&state_a).unwrap(), serde_json::to_value(&state_b).unwrap());

    // 5. Update A again
    state_a.update("key1".into(), json!("value1-new"));
    
    // 6. Diff A against updated B
    let delta2 = state_a.diff(&state_b);
    assert_eq!(delta2.registers.len(), 1);
    assert!(delta2.registers.contains_key("key1"));

    // 7. Apply delta2 to B
    state_b.apply_delta(delta2, &peer.to_string(), &acl).unwrap();
    assert_eq!(serde_json::to_value(&state_a).unwrap(), serde_json::to_value(&state_b).unwrap());
}

#[test]
fn test_delta_merge_deterministic_tie_breaking() {
    let mut state_a = CrdtState::default();
    let mut state_b = CrdtState::default();
    
    let now = Utc::now();
    
    // Create two registers with identical timestamps but different values
    // Note: We use manual insertion to bypass the Utc::now() in update()
    state_a.data.insert("key".into(), scribe_networking::crdt::LwwRegister {
        value: json!("aaa"),
        timestamp: now,
    });
    state_b.data.insert("key".into(), scribe_networking::crdt::LwwRegister {
        value: json!("zzz"),
        timestamp: now,
    });
    
    // A.diff(B) should contain nothing if B is "better"
    // B.diff(A) should contain B's value
    
    let delta_b_to_a = state_b.diff(&state_a);
    assert_eq!(delta_b_to_a.registers.get("key").unwrap().value, json!("zzz"));
    
    let peer = PeerId::random();
    let mut acl = AccessControlList::new(vec![]);
    acl.authorize(peer);
    
    state_a.apply_delta(delta_b_to_a, &peer.to_string(), &acl).unwrap();
    assert_eq!(state_a.data.get("key").unwrap().value, json!("zzz"));
}

#[test]
fn test_delta_future_poisoning_protection() {
    let mut state = CrdtState::default();
    let future_time = Utc::now() + MAX_FUTURE_OFFSET + Duration::seconds(10);
    
    let mut delta_registers = std::collections::HashMap::new();
    delta_registers.insert("poison".into(), scribe_networking::crdt::LwwRegister {
        value: json!("evil"),
        timestamp: future_time,
    });
    
    let delta = scribe_networking::crdt::CrdtDelta { registers: delta_registers };
    
    let peer = PeerId::random();
    let mut acl = AccessControlList::new(vec![]);
    acl.authorize(peer);
    
    let _ = state.apply_delta(delta, &peer.to_string(), &acl);
    
    assert!(state.data.get("poison").is_none());
}
