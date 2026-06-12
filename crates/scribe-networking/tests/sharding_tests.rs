use scribe_networking::{NetworkManager, NetworkCommand, NetworkEvent, crdt::CrdtState};
use libp2p::identity::Keypair;
use std::time::Duration;
use tokio::time::timeout;
use serde_json::json;

#[tokio::test]
async fn test_zonal_sharding_and_isolation() {
    let kp1 = Keypair::generate_ed25519();
    let peer1 = libp2p::PeerId::from(kp1.public());
    let kp2 = Keypair::generate_ed25519();
    let peer2 = libp2p::PeerId::from(kp2.public());

    let (nm1, mut rx1, tx1) = NetworkManager::new(kp1, vec![peer1, peer2]).await.expect("Failed to create nm1");
    let (nm2, mut rx2, tx2) = NetworkManager::new(kp2, vec![peer1, peer2]).await.expect("Failed to create nm2");

    tokio::spawn(async move {
        if let Err(e) = nm1.run().await {
            eprintln!("nm1 run error: {:?}", e);
        }
    });
    tokio::spawn(async move {
        if let Err(e) = nm2.run().await {
            eprintln!("nm2 run error: {:?}", e);
        }
    });

    // Get listen address of nm1
    let mut addr1 = None;
    for _ in 0..10 {
        if let Ok(Some(NetworkEvent::ListeningOn(addr))) = timeout(Duration::from_millis(500), rx1.recv()).await {
            addr1 = Some(addr);
            break;
        }
    }
    let addr1 = addr1.expect("Node 1 failed to provide listen address");

    // Node 2 dials Node 1
    tx2.send(NetworkCommand::Dial(addr1)).unwrap();

    // Step 1: Join different zones and verify isolation
    tx1.send(NetworkCommand::JoinZone("zone-a".into())).unwrap();
    tx2.send(NetworkCommand::JoinZone("zone-b".into())).unwrap();

    // Drain JoinZone events
    let mut zone1_joined = false;
    let mut zone2_joined = false;
    
    for _ in 0..10 {
        if let Ok(Some(event)) = timeout(Duration::from_millis(500), rx1.recv()).await {
            if let NetworkEvent::ZoneJoined(z) = event {
                if z == "zone-a" { zone1_joined = true; break; }
            }
        }
    }
    for _ in 0..10 {
        if let Ok(Some(event)) = timeout(Duration::from_millis(500), rx2.recv()).await {
            if let NetworkEvent::ZoneJoined(z) = event {
                if z == "zone-b" { zone2_joined = true; break; }
            }
        }
    }
    assert!(zone1_joined, "Node 1 failed to join zone-a");
    assert!(zone2_joined, "Node 2 failed to join zone-b");

    // Node 1 broadcasts state
    let mut state = CrdtState::default();
    state.update("pos".into(), json!({"x": 10, "y": 10}));
    tx1.send(NetworkCommand::BroadcastState(state.clone())).unwrap();

    // Node 2 should NOT receive it
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        if let Ok(Some(event)) = timeout(Duration::from_millis(100), rx2.recv()).await {
            if let NetworkEvent::StateUpdate(_) = event {
                panic!("Node 2 received state update from Zone A while in Zone B");
            }
        }
    }

    // Step 2: Node 2 joins Zone A and should now receive updates
    tx2.send(NetworkCommand::JoinZone("zone-a".into())).unwrap();
    
    // Wait for transition
    let mut zone2_moved = false;
    for _ in 0..10 {
        if let Ok(Some(event)) = timeout(Duration::from_millis(500), rx2.recv()).await {
            if let NetworkEvent::ZoneJoined(z) = event {
                if z == "zone-a" { zone2_moved = true; break; }
            }
        }
    }
    assert!(zone2_moved, "Node 2 failed to move to zone-a");

    // Broadcast again multiple times to give Gossipsub time to mesh
    let mut received = false;
    for _ in 0..30 {
        tx1.send(NetworkCommand::BroadcastState(state.clone())).unwrap();
        // Check for updates
        while let Ok(Some(event)) = timeout(Duration::from_millis(100), rx2.recv()).await {
            if let NetworkEvent::StateUpdate(s) = event {
                if s.data.get("pos").is_some() {
                    received = true;
                    break;
                }
            }
        }
        if received { break; }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    assert!(received, "Node 2 failed to receive update after joining Zone A");
}
