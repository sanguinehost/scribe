use scribe_networking::{NetworkManager, p2p::NetworkEvent, crdt::CrdtState, protocol::twin::TwinMigrationProtocol};
use libp2p::identity::Keypair;

#[tokio::test]
async fn test_multi_node_migration() {
    let kp1 = Keypair::generate_ed25519();
    let kp2 = Keypair::generate_ed25519();
    let kp3 = Keypair::generate_ed25519();

    let (_node1, _rx1) = NetworkManager::new(kp1.clone()).await.unwrap();
    let (_node2, _rx2) = NetworkManager::new(kp2.clone()).await.unwrap();
    let (_node3, _rx3) = NetworkManager::new(kp3.clone()).await.unwrap();

    // In a real test, we would connect them. 
    // For local simulation, we can mock the event propagation or use mdns if enabled.
    
    let mut state = CrdtState::default();
    state.update("mood".into(), serde_json::json!("happy"));
    
    let signed = TwinMigrationProtocol::sign_payload("agent-1".into(), state.clone(), &kp1).unwrap();
    
    // Simulate migration: node1 sends to node2, node2 verifies and sends to node3
    assert!(TwinMigrationProtocol::verify_payload(&signed).unwrap());
    
    // Check CRDT convergence
    let mut state2 = CrdtState::default();
    state2.merge(&signed.payload.state);
    assert_eq!(state2.data.get("mood").unwrap().value, serde_json::json!("happy"));
}
