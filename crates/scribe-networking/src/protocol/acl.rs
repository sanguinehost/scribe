use std::collections::HashSet;
use libp2p::PeerId;
use crate::error::{NetworkError, NetworkResult};

pub struct AccessControlList {
    authorized_peers: HashSet<PeerId>,
}

impl AccessControlList {
    pub fn new(initial_peers: Vec<PeerId>) -> Self {
        Self {
            authorized_peers: initial_peers.into_iter().collect(),
        }
    }

    pub fn is_authorized(&self, peer_id: &PeerId) -> bool {
        self.authorized_peers.contains(peer_id)
    }

    pub fn authorize(&mut self, peer_id: PeerId) {
        self.authorized_peers.insert(peer_id);
    }

    pub fn revoke(&mut self, peer_id: &PeerId) {
        self.authorized_peers.remove(peer_id);
    }

    pub fn check_access(&self, peer_id: &PeerId) -> NetworkResult<()> {
        if self.is_authorized(peer_id) {
            Ok(())
        } else {
            Err(NetworkError::Unauthorized(format!("Peer {} not authorized", peer_id)))
        }
    }
}
