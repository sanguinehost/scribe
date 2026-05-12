use serde::{Deserialize, Serialize};
use crate::crdt::CrdtState;
use crate::error::{NetworkError, NetworkResult};
use libp2p::identity::{Keypair, PublicKey};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinPayload {
    pub agent_id: String,
    pub state: CrdtState,
    pub timestamp: DateTime<Utc>,
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
        let payload = TwinPayload {
            agent_id,
            state,
            timestamp: Utc::now(),
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

    pub fn verify_payload(signed: &SignedTwinPayload) -> NetworkResult<bool> {
        let public_key = PublicKey::try_decode_protobuf(&signed.public_key)
            .map_err(|e| NetworkError::Decoding(e.to_string()))?;
        
        let encoded = serde_json::to_vec(&signed.payload)?;
        
        if public_key.verify(&encoded, &signed.signature) {
            Ok(true)
        } else {
            Err(NetworkError::Unauthorized("Invalid signature".into()))
        }
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
        let verified = TwinMigrationProtocol::verify_payload(&signed).unwrap();
        
        assert!(verified);
        assert_eq!(signed.payload.agent_id, "agent-1");
    }
}
