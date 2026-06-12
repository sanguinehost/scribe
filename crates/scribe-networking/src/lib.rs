pub mod error;
pub mod p2p;
pub mod crdt;
pub mod protocol;

pub use error::NetworkError;
pub use error::NetworkResult;
pub use p2p::{NetworkManager, NetworkEvent, NetworkCommand};
