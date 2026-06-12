use libp2p::{
    futures::StreamExt,
    gossipsub, identity, kad, mdns, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, PeerId, Swarm,
};
use std::time::Duration;
use tokio::sync::mpsc;
use crate::error::{NetworkError, NetworkResult};
use crate::crdt::CrdtState;
use crate::protocol::acl::AccessControlList;
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
    PeerDiscovered(String),
    ZoneJoined(String),
    ListeningOn(String),
}

#[derive(Debug)]
pub enum NetworkCommand {
    JoinZone(String),
    BroadcastState(CrdtState),
    Dial(String),
}

pub struct NetworkManager {
    swarm: Swarm<ScribeBehaviour>,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    command_receiver: mpsc::UnboundedReceiver<NetworkCommand>,
    acl: AccessControlList,
    current_zone: Option<String>,
}

impl NetworkManager {
    pub async fn new(
        keypair: identity::Keypair, 
        initial_acl: Vec<PeerId>
    ) -> NetworkResult<(Self, mpsc::UnboundedReceiver<NetworkEvent>, mpsc::UnboundedSender<NetworkCommand>)> {
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

        swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse::<libp2p::Multiaddr>().map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?)
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let acl = AccessControlList::new(initial_acl);

        Ok((Self { 
            swarm, 
            event_sender: event_tx, 
            command_receiver: command_rx,
            acl, 
            current_zone: None 
        }, event_rx, command_tx))
    }

    pub async fn run(mut self) -> NetworkResult<()> {
        loop {
            tokio::select! {
                command = self.command_receiver.recv() => {
                    if let Some(cmd) = command {
                        match cmd {
                            NetworkCommand::JoinZone(zone_id) => {
                                if let Err(e) = self.handle_join_zone(zone_id) {
                                    log::error!("Failed to join zone: {:?}", e);
                                }
                            }
                            NetworkCommand::BroadcastState(state) => {
                                if let Err(e) = self.handle_broadcast_state(&state) {
                                    log::error!("Failed to broadcast state: {:?}", e);
                                }
                            }
                            NetworkCommand::Dial(addr) => {
                                if let Err(e) = self.handle_dial(&addr) {
                                    log::error!("Failed to dial: {:?}", e);
                                }
                            }
                        }
                    }
                }
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("Listening on {:?}", address);
                        self.event_sender.send(NetworkEvent::ListeningOn(address.to_string())).ok();
                    }
                    SwarmEvent::Behaviour(ScribeBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            if self.acl.is_authorized(&peer_id) {
                                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, _multiaddr);
                                self.event_sender.send(NetworkEvent::PeerDiscovered(peer_id.to_string())).ok();
                            }
                        }
                    }
                    SwarmEvent::Behaviour(ScribeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        let is_authorized = if let Some(source) = message.source {
                            self.acl.is_authorized(&source)
                        } else {
                            self.acl.is_authorized(&propagation_source)
                        };

                        if is_authorized {
                            let is_current_zone = if let Some(zone) = &self.current_zone {
                                message.topic == gossipsub::IdentTopic::new(format!("scribe-zone-{}", zone)).hash()
                            } else {
                                false
                            };

                            if is_current_zone {
                                if let Ok(state) = serde_json::from_slice::<CrdtState>(&message.data) {
                                    self.event_sender.send(NetworkEvent::StateUpdate(state)).ok();
                                }
                            }
                        } else {
                            log::warn!("Dropped Gossipsub message from unauthorized peer: {}", propagation_source);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_join_zone(&mut self, zone_id: String) -> NetworkResult<()> {
        if let Some(old_zone) = &self.current_zone {
            if *old_zone == zone_id {
                return Ok(());
            }
            let old_topic = gossipsub::IdentTopic::new(format!("scribe-zone-{}", old_zone));
            self.swarm.behaviour_mut().gossipsub.unsubscribe(&old_topic)
                .map_err(|e| NetworkError::Libp2p(format!("Failed to unsubscribe from old zone: {:?}", e)))?;
        }

        let new_topic = gossipsub::IdentTopic::new(format!("scribe-zone-{}", zone_id));
        self.swarm.behaviour_mut().gossipsub.subscribe(&new_topic)
            .map_err(|e| NetworkError::GossipsubSubscription(e))?;

        self.current_zone = Some(zone_id.clone());
        self.event_sender.send(NetworkEvent::ZoneJoined(zone_id)).ok();
        Ok(())
    }

    fn handle_broadcast_state(&mut self, state: &CrdtState) -> NetworkResult<()> {
        if let Some(zone) = &self.current_zone {
            let topic = gossipsub::IdentTopic::new(format!("scribe-zone-{}", zone));
            let data = serde_json::to_vec(state)?;
            self.swarm.behaviour_mut().gossipsub.publish(topic, data)
                .map_err(|e| NetworkError::GossipsubPublish(e))?;
            Ok(())
        } else {
            Err(NetworkError::Libp2p("Cannot broadcast state without joining a zone".into()))
        }
    }

    fn handle_dial(&mut self, addr: &str) -> NetworkResult<()> {
        let multiaddr = addr.parse::<libp2p::Multiaddr>().map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?;
        self.swarm.dial(multiaddr).map_err(|e| NetworkError::Libp2p(e.to_string()))?;
        Ok(())
    }

    pub fn acl_mut(&mut self) -> &mut AccessControlList {
        &mut self.acl
    }
}


