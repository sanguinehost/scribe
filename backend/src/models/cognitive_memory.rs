use crate::auth::session_dek::SessionDek;
use crate::crypto::{decrypt_gcm, CryptoError};
use crate::db::{DbId, DbTimestamp};
use crate::schema::{character_opinions, entity_observations};
use diesel::prelude::*;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable, Associations,
)]
#[diesel(table_name = character_opinions)]
#[diesel(belongs_to(crate::models::users::User, foreign_key = user_id))]
#[diesel(belongs_to(crate::models::chronicle::PlayerChronicle, foreign_key = chronicle_id))]
pub struct CharacterOpinion {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub perspective_hash: String,
    pub perspective_encrypted: Vec<u8>,
    pub perspective_nonce: Vec<u8>,
    pub opinion_encrypted: Vec<u8>,
    pub opinion_nonce: Vec<u8>,
    pub confidence: f32,
    pub significance: f32,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

impl CharacterOpinion {
    /// Decrypts the opinion and perspective, returning a formatted string.
    pub fn decrypt(&self, session_dek: &SessionDek) -> Result<String, CryptoError> {
        let perspective_decrypted = decrypt_gcm(
            &self.perspective_encrypted,
            &self.perspective_nonce,
            &session_dek.0,
        )?;
        let perspective =
            String::from_utf8_lossy(perspective_decrypted.expose_secret()).to_string();

        let opinion_decrypted =
            decrypt_gcm(&self.opinion_encrypted, &self.opinion_nonce, &session_dek.0)?;
        let opinion = String::from_utf8_lossy(opinion_decrypted.expose_secret()).to_string();

        Ok(format!("[{}]: {}", perspective, opinion))
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = character_opinions)]
pub struct NewCharacterOpinion {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub perspective_hash: String,
    pub perspective_encrypted: Vec<u8>,
    pub perspective_nonce: Vec<u8>,
    pub opinion_encrypted: Vec<u8>,
    pub opinion_nonce: Vec<u8>,
    pub confidence: f32,
    pub significance: f32,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable, Associations,
)]
#[diesel(table_name = entity_observations)]
#[diesel(belongs_to(crate::models::users::User, foreign_key = user_id))]
#[diesel(belongs_to(crate::models::chronicle::PlayerChronicle, foreign_key = chronicle_id))]
pub struct EntityObservation {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub entity_name_hash: String,
    pub entity_name_encrypted: Vec<u8>,
    pub entity_name_nonce: Vec<u8>,
    pub observation_encrypted: Vec<u8>,
    pub observation_nonce: Vec<u8>,
    pub confidence: f32,
    pub significance: f32,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

impl EntityObservation {
    /// Decrypts the observation and entity name, returning a formatted string.
    pub fn decrypt(&self, session_dek: &SessionDek) -> Result<String, CryptoError> {
        let entity_name_decrypted = decrypt_gcm(
            &self.entity_name_encrypted,
            &self.entity_name_nonce,
            &session_dek.0,
        )?;
        let entity_name =
            String::from_utf8_lossy(entity_name_decrypted.expose_secret()).to_string();

        let observation_decrypted = decrypt_gcm(
            &self.observation_encrypted,
            &self.observation_nonce,
            &session_dek.0,
        )?;
        let observation =
            String::from_utf8_lossy(observation_decrypted.expose_secret()).to_string();

        Ok(format!("[{}]: {}", entity_name, observation))
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = entity_observations)]
pub struct NewEntityObservation {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub entity_name_hash: String,
    pub entity_name_encrypted: Vec<u8>,
    pub entity_name_nonce: Vec<u8>,
    pub observation_encrypted: Vec<u8>,
    pub observation_nonce: Vec<u8>,
    pub confidence: f32,
    pub significance: f32,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitivePayload {
    pub should_create_event: bool,
    pub reasoning: String,
    pub summary: String,
    pub keywords: Vec<String>,
    pub opinions: Vec<OpinionExtraction>,
    pub observations: Vec<ObservationExtraction>,
    pub significance_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpinionExtraction {
    pub perspective: String,
    pub opinion: String,
    pub confidence: f32,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationExtraction {
    pub entity_name: String,
    pub observation: String,
    pub confidence: f32,
}
