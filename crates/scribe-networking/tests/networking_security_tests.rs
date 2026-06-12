use scribe_networking::{
    crdt::{CrdtState, LwwRegister},
    protocol::twin::{TwinMigrationProtocol, SignedTwinPayload},
    protocol::acl::AccessControlList,
    NetworkError, NetworkResult,
};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use chrono::{Utc, Duration};
use serde_json::json;

#[tokio::test]
async fn test_security_future_timestamp_poisoning_prevented() {
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
    
    // Poison the state (SHOULD BE REJECTED)
    state.merge(&adversarial_state);
    
    // Legitimate update should still win because poison was ignored
    state.update("position".into(), json!({"x": 100, "y": 200}));
    
    let current_val = state.data.get("position").unwrap().value.clone();
    assert_eq!(current_val, json!({"x": 100, "y": 200}), "Legitimate update should persist, poison rejected");
}

#[tokio::test]
async fn test_security_expiration_enforced() {
    let keypair = Keypair::generate_ed25519();
    let mut state = CrdtState::default();
    state.update("mood".into(), json!("calm"));
    
    let mut signed = TwinMigrationProtocol::sign_payload("agent-X".into(), state.clone(), &keypair).unwrap();
    
    // Force expiration
    signed.payload.expires_at = Utc::now() - Duration::seconds(10);
    
    let result = TwinMigrationProtocol::verify_payload(&signed);
    assert!(result.is_err(), "Expired payload should be rejected");
}

#[tokio::test]
async fn test_security_acl_enforced() {
    let kp_authorized = Keypair::generate_ed25519();
    let peer_authorized = PeerId::from(kp_authorized.public());
    
    let kp_malicious = Keypair::generate_ed25519();
    let peer_malicious = PeerId::from(kp_malicious.public());
    
    let acl = AccessControlList::new(vec![peer_authorized]);
    
    assert!(acl.is_authorized(&peer_authorized));
    assert!(!acl.is_authorized(&peer_malicious));
    
    // Protocol usage would look like:
    let signed_mal = TwinMigrationProtocol::sign_payload("evil-agent".into(), CrdtState::default(), &kp_malicious).unwrap();
    
    // Even if signature is valid, ACL check fails
    let sig_verified = TwinMigrationProtocol::verify_payload(&signed_mal).is_ok();
    let acl_verified = acl.is_authorized(&peer_malicious);
    
    assert!(sig_verified);
    assert!(!acl_verified, "Malicious peer should fail ACL check");
}
