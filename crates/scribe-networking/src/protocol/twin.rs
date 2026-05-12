use serde::{Deserialize, Serialize};
use crate::crdt::{CrdtState, MAX_FUTURE_OFFSET};
use crate::error::{NetworkError, NetworkResult};
use libp2p::identity::{Keypair, PublicKey};
use libp2p::PeerId;
use chrono::{DateTime, Utc, Duration};
use crate::protocol::acl::AccessControlList;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinPayload {
    pub agent_id: String,
    pub state: CrdtState,
    pub timestamp: DateTime<Utc>,
    pub nonce: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTwinPayload {
    pub payload: TwinPayload,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>, // Protobuf encoded public key
}

pub struct TwinMigrationProtocol;

impl TwinMigrationProtocol {
    pub fn sign_payload(agent_id: String, state: CrdtState, keypair: &Keypair) -> NetworkResult<SignedTwinPayload> {
        let now = Utc::now();
        let payload = TwinPayload {
            agent_id,
            state,
            timestamp: now,
            nonce: Uuid::new_v4(),
            expires_at: now + Duration::minutes(5),
        };
        let encoded = serde_json::to_vec(&payload)?;
        let signature = keypair.sign(&encoded).map_err(|e| NetworkError::Unauthorized(e.to_string()))?;
        let public_key = keypair.public().encode_protobuf();

        Ok(SignedTwinPayload {
            payload,
            signature,
            public_key,
        })
    }

    pub fn verify_payload(signed: &SignedTwinPayload, acl: Option<&AccessControlList>) -> NetworkResult<bool> {
        let now = Utc::now();

        // 1. Check expiration
        if now > signed.payload.expires_at {
            return Err(NetworkError::Unauthorized("Payload expired".into()));
        }

        // 2. Check for future timestamp poisoning (Clock-Drift)
        if signed.payload.timestamp > now + MAX_FUTURE_OFFSET {
            return Err(NetworkError::Unauthorized("Payload timestamp too far in future".into()));
        }

        // 3. Verify signature
        let public_key = PublicKey::try_decode_protobuf(&signed.public_key)
            .map_err(|e| NetworkError::Decoding(e.to_string()))?;
        
        let encoded = serde_json::to_vec(&signed.payload)?;
        
        if !public_key.verify(&encoded, &signed.signature) {
            return Err(NetworkError::Unauthorized("Invalid signature".into()));
        }

        // 4. Check ACL if provided
        if let Some(acl) = acl {
            let peer_id = PeerId::from(public_key);
            if !acl.is_authorized(&peer_id) {
                return Err(NetworkError::Unauthorized(format!("Peer {} not authorized in ACL", peer_id)));
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate_ed25519();
        let mut state = CrdtState::default();
        state.update("memory".into(), serde_json::json!("happy"));
        
        let signed = TwinMigrationProtocol::sign_payload("agent-1".into(), state, &keypair).unwrap();
        let verified = TwinMigrationProtocol::verify_payload(&signed, None).unwrap();
        
        assert!(verified);
        assert_eq!(signed.payload.agent_id, "agent-1");
    }

    #[test]
    fn test_expiration() {
        let keypair = Keypair::generate_ed25519();
        let mut state = CrdtState::default();
        state.update("memory".into(), serde_json::json!("happy"));
        
        let mut signed = TwinMigrationProtocol::sign_payload("agent-1".into(), state, &keypair).unwrap();
        
        // Force expiration
        signed.payload.expires_at = Utc::now() - Duration::seconds(1);
        
        let result = TwinMigrationProtocol::verify_payload(&signed, None);
        assert!(result.is_err());
    }
}
