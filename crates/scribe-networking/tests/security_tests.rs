use scribe_networking::{
    crdt::{CrdtState, LwwRegister},
    protocol::{
        twin::TwinMigrationProtocol,
        acl::AccessControlList,
    },
    NetworkError,
};
use libp2p::{identity::Keypair, PeerId};
use chrono::{Utc, Duration};
use serde_json::json;
use proptest::prelude::*;

#[tokio::test]
async fn test_security_future_timestamp_poisoning() {
    let mut state = CrdtState::default();
    
    // Legitimate update
    state.update("position".into(), json!({"x": 10, "y": 20}));
    
    // Adversarial update from the future (e.g., year 2100)
    let future_time = Utc::now() + Duration::days(365 * 75);
    let adversarial_reg = LwwRegister {
        value: json!({"x": 666, "y": 666}),
        timestamp: future_time,
    };
    
    let mut adversarial_state = CrdtState::default();
    adversarial_state.data.insert("position".into(), adversarial_reg);
    
    // Poison the state
    state.merge(&adversarial_state);
    
    // Attempt to update with a current timestamp (should succeed because the future poison was rejected)
    state.update("position".into(), json!({"x": 100, "y": 200}));
    
    let current_val = state.data.get("position").unwrap().value.clone();
    assert_eq!(current_val, json!({"x": 100, "y": 200}), "Legitimate update should succeed; poison was rejected");
}

#[tokio::test]
async fn test_security_replay_attack() {
    let keypair = Keypair::generate_ed25519();
    let mut state = CrdtState::default();
    state.update("mood".into(), json!("calm"));
    
    let signed = TwinMigrationProtocol::sign_payload("agent-X".into(), state.clone(), &keypair).unwrap();
    
    // First verification (legitimate)
    assert!(TwinMigrationProtocol::verify_payload(&signed, None).is_ok());
    
    // Simulate a replay attack (sending the same payload later)
    // Currently, our protocol has TTL (expires_at), but not nonces stored in a DB yet.
    let replayed = signed.clone();
    assert!(TwinMigrationProtocol::verify_payload(&replayed, None).is_ok());
}

#[tokio::test]
async fn test_security_unauthorized_key_injection() {
    // Node A (authorized)
    let kp_a = Keypair::generate_ed25519();
    let peer_a = PeerId::from(kp_a.public());
    let acl = AccessControlList::new(vec![peer_a]);
    
    // Malicious Node B (unauthorized, just generated a key)
    let kp_b = Keypair::generate_ed25519();
    
    let mut mal_state = CrdtState::default();
    mal_state.update("virus".into(), json!("infected"));
    
    let signed_mal = TwinMigrationProtocol::sign_payload("evil-agent".into(), mal_state, &kp_b).unwrap();
    
    // Verification should now FAIL because of the ACL
    let result = TwinMigrationProtocol::verify_payload(&signed_mal, Some(&acl));
    assert!(result.is_err(), "Payload from unauthorized key should be rejected by ACL");
    if let Err(NetworkError::Unauthorized(msg)) = result {
        assert!(msg.contains("not authorized in ACL"), "Error message should mention ACL: {}", msg);
    } else {
        panic!("Expected Unauthorized error, got {:?}", result);
    }
}

// --- Proptest Suites ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_crdt_clock_drift_invariant(
        drift_secs in 61..1000_000i64,
        val in ".*"
    ) {
        let mut state = CrdtState::default();
        let key = "test_key".to_string();
        
        // Initial state
        state.update(key.clone(), json!("initial"));
        
        // Adversarial update from the future
        let future_time = Utc::now() + Duration::seconds(drift_secs);
        let adversarial_reg = LwwRegister {
            value: json!(val),
            timestamp: future_time,
        };
        
        let mut adversarial_state = CrdtState::default();
        adversarial_state.data.insert(key.clone(), adversarial_reg);
        
        // Merge should reject/ignore the future update
        state.merge(&adversarial_state);
        
        let current_val = state.data.get(&key).unwrap().value.clone();
        assert_eq!(current_val, json!("initial"), "CRDT must reject updates beyond MAX_FUTURE_OFFSET");
    }

    #[test]
    fn prop_twin_migration_expiry_invariant(
        ttl_offset_secs in 1..3600i64
    ) {
        let keypair = Keypair::generate_ed25519();
        let state = CrdtState::default();
        
        // Create a payload that will expire in 5 minutes
        let signed = TwinMigrationProtocol::sign_payload("agent".into(), state, &keypair).unwrap();
        
        // Simulate time passing beyond expiry
        let expired_signed = {
            let mut s = signed.clone();
            // Force it to be expired relative to "now"
            s.payload.expires_at = Utc::now() - Duration::seconds(ttl_offset_secs);
            s
        };
        
        let result = TwinMigrationProtocol::verify_payload(&expired_signed, None);
        assert!(result.is_err(), "Expired payload must be rejected");
    }

    #[test]
    fn prop_twin_migration_future_poisoning_invariant(
        drift_secs in 61..1000_000i64
    ) {
        let keypair = Keypair::generate_ed25519();
        let state = CrdtState::default();
        
        let mut signed = TwinMigrationProtocol::sign_payload("agent".into(), state, &keypair).unwrap();
        
        // Inject future timestamp
        signed.payload.timestamp = Utc::now() + Duration::seconds(drift_secs);
        
        // Re-sign because we changed the payload
        let encoded = serde_json::to_vec(&signed.payload).unwrap();
        signed.signature = keypair.sign(&encoded).unwrap();
        
        let result = TwinMigrationProtocol::verify_payload(&signed, None);
        assert!(result.is_err(), "Payload with future timestamp beyond MAX_FUTURE_OFFSET must be rejected");
    }
}
