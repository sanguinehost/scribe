use thiserror::Error;
use libp2p::gossipsub;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Libp2p error: {0}")]
    Libp2p(String),

    #[error("Gossipsub subscription error: {0}")]
    GossipsubSubscription(#[from] gossipsub::SubscriptionError),

    #[error("Gossipsub publish error: {0}")]
    GossipsubPublish(#[from] gossipsub::PublishError),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("CRDT error: {0}")]
    Crdt(String),

    #[error("Twin migration error: {0}")]
    TwinMigration(String),

    #[error("Bandwidth allocation error: {0}")]
    Bandwidth(String),

    #[error("Unauthorized peer: {0}")]
    Unauthorized(String),
}

pub type NetworkResult<T> = std::result::Result<T, NetworkError>;
