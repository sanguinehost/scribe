use libp2p::{
    futures::StreamExt,
    gossipsub, identity, kad, mdns, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, PeerId, Swarm,
};
use std::time::Duration;
use tokio::sync::mpsc;
use crate::error::{NetworkError, NetworkResult};
use crate::crdt::CrdtState;
use serde::{Deserialize, Serialize};

#[derive(NetworkBehaviour)]
pub struct ScribeBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    StateUpdate(CrdtState),
    PeerDiscovered(String), // Use String for PeerId
}

pub struct NetworkManager {
    swarm: Swarm<ScribeBehaviour>,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
}

impl NetworkManager {
    pub async fn new(keypair: identity::Keypair) -> NetworkResult<(Self, mpsc::UnboundedReceiver<NetworkEvent>)> {
        let peer_id = PeerId::from(keypair.public());
        
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            ).map_err(|e| NetworkError::Libp2p(e.to_string()))?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .build()
                    .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                ).map_err(|e| NetworkError::Libp2p(e.to_string()))?;

                let kademlia = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

                Ok(ScribeBehaviour { gossipsub, kademlia, mdns })
            }).map_err(|e| NetworkError::Libp2p(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?)
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

        let (tx, rx) = mpsc::unbounded_channel();

        Ok((Self { swarm, event_sender: tx }, rx))
    }

    pub async fn run(mut self) -> NetworkResult<()> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(ScribeBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, _multiaddr);
                            self.event_sender.send(NetworkEvent::PeerDiscovered(peer_id.to_string())).ok();
                        }
                    }
                    SwarmEvent::Behaviour(ScribeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: _peer_id,
                        message_id: _id,
                        message,
                    })) => {
                        if let Ok(state) = serde_json::from_slice::<CrdtState>(&message.data) {
                            self.event_sender.send(NetworkEvent::StateUpdate(state)).ok();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub fn broadcast_state(&mut self, state: &CrdtState) -> NetworkResult<()> {
        let topic = gossipsub::IdentTopic::new("scribe-state-sync");
        let data = serde_json::to_vec(state)?;
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)
            .map_err(|e| NetworkError::GossipsubPublish(e))?;
        Ok(())
    }
}
