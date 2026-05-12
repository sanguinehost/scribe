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
    pub message_variant_id: Option<DbId>,
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
    pub message_variant_id: Option<DbId>,
}

impl Default for NewCharacterOpinion {
    fn default() -> Self {
        Self {
            id: DbId::new(),
            user_id: DbId::nil(),
            chronicle_id: DbId::nil(),
            perspective_hash: String::new(),
            perspective_encrypted: Vec::new(),
            perspective_nonce: Vec::new(),
            opinion_encrypted: Vec::new(),
            opinion_nonce: Vec::new(),
            confidence: 0.0,
            significance: 0.0,
            created_at: DbTimestamp::now(),
            updated_at: DbTimestamp::now(),
            message_variant_id: None,
        }
    }
}

impl NewCharacterOpinion {
    pub fn builder() -> NewCharacterOpinionBuilder {
        NewCharacterOpinionBuilder::default()
    }
}

#[derive(Default)]
pub struct NewCharacterOpinionBuilder {
    inner: NewCharacterOpinion,
}

impl NewCharacterOpinionBuilder {
    pub fn user_id(mut self, id: DbId) -> Self {
        self.inner.user_id = id;
        self
    }
    pub fn chronicle_id(mut self, id: DbId) -> Self {
        self.inner.chronicle_id = id;
        self
    }
    pub fn perspective_hash(mut self, hash: String) -> Self {
        self.inner.perspective_hash = hash;
        self
    }
    pub fn perspective_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.perspective_encrypted = data;
        self
    }
    pub fn perspective_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.perspective_nonce = nonce;
        self
    }
    pub fn opinion_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.opinion_encrypted = data;
        self
    }
    pub fn opinion_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.opinion_nonce = nonce;
        self
    }
    pub fn confidence(mut self, val: f32) -> Self {
        self.inner.confidence = val;
        self
    }
    pub fn significance(mut self, val: f32) -> Self {
        self.inner.significance = val;
        self
    }
    pub fn message_variant_id(mut self, id: Option<DbId>) -> Self {
        self.inner.message_variant_id = id;
        self
    }
    pub fn build(self) -> NewCharacterOpinion {
        self.inner
    }
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
    pub message_variant_id: Option<DbId>,
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
    pub message_variant_id: Option<DbId>,
}

impl Default for NewEntityObservation {
    fn default() -> Self {
        Self {
            id: DbId::new(),
            user_id: DbId::nil(),
            chronicle_id: DbId::nil(),
            entity_name_hash: String::new(),
            entity_name_encrypted: Vec::new(),
            entity_name_nonce: Vec::new(),
            observation_encrypted: Vec::new(),
            observation_nonce: Vec::new(),
            confidence: 0.0,
            significance: 0.0,
            created_at: DbTimestamp::now(),
            updated_at: DbTimestamp::now(),
            message_variant_id: None,
        }
    }
}

impl NewEntityObservation {
    pub fn builder() -> NewEntityObservationBuilder {
        NewEntityObservationBuilder::default()
    }
}

#[derive(Default)]
pub struct NewEntityObservationBuilder {
    inner: NewEntityObservation,
}

impl NewEntityObservationBuilder {
    pub fn user_id(mut self, id: DbId) -> Self {
        self.inner.user_id = id;
        self
    }
    pub fn chronicle_id(mut self, id: DbId) -> Self {
        self.inner.chronicle_id = id;
        self
    }
    pub fn entity_name_hash(mut self, hash: String) -> Self {
        self.inner.entity_name_hash = hash;
        self
    }
    pub fn entity_name_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.entity_name_encrypted = data;
        self
    }
    pub fn entity_name_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.entity_name_nonce = nonce;
        self
    }
    pub fn observation_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.observation_encrypted = data;
        self
    }
    pub fn observation_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.observation_nonce = nonce;
        self
    }
    pub fn confidence(mut self, val: f32) -> Self {
        self.inner.confidence = val;
        self
    }
    pub fn significance(mut self, val: f32) -> Self {
        self.inner.significance = val;
        self
    }
    pub fn message_variant_id(mut self, id: Option<DbId>) -> Self {
        self.inner.message_variant_id = id;
        self
    }
    pub fn build(self) -> NewEntityObservation {
        self.inner
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitivePayload {
    #[serde(default)]
    pub should_create_event: bool,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub reasoning: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub summary: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub facts: Vec<ExtractedFact>,
    #[serde(default)]
    pub surprise_score: f32,
    #[serde(default, deserialize_with = "deserialize_string_or_null")]
    pub core_memory_delta: Option<String>,
    #[serde(default)]
    pub significance_score: f32,
    // Backward compatibility - deprecated but kept for parsing
    #[serde(default)]
    pub opinions: Vec<OpinionExtraction>,
    #[serde(default)]
    pub observations: Vec<ObservationExtraction>,
}

/// Custom deserializer that handles cases where the AI returns null, a string, or omits the field entirely.
/// Also handles cases where AI might return an array instead of a string (treats as None).
fn deserialize_string_or_null<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value: serde_json::Value = serde::Deserialize::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) if s.is_empty() => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s)),
        serde_json::Value::Array(_) => {
            // AI sometimes returns an array when we expect a string - treat as None
            Ok(None)
        }
        other => Err(D::Error::custom(format!(
            "expected string or null for core_memory_delta, got {:?}",
            other
        ))),
    }
}

/// Custom deserializer that handles cases where the AI returns an array of strings (joins them)
/// or other types (converts to string).
fn deserialize_string_flexible<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: serde_json::Value = serde::Deserialize::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(String::new()),
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Array(arr) => {
            // Join array elements with a space
            let strings: Vec<String> = arr
                .iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    _ => v.to_string(),
                })
                .collect();
            Ok(strings.join(" "))
        }
        serde_json::Value::Object(_) => Ok(value.to_string()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFact {
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub who: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub what: String,
    #[serde(
        rename = "where",
        default,
        deserialize_with = "deserialize_string_flexible"
    )]
    pub r#where: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub when: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub why: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub fact_type: String,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub significance: f32,
}

impl std::fmt::Display for ExtractedFact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}: {} (Where: {}, When: {}, Why: {})",
            self.fact_type, self.who, self.what, self.r#where, self.when, self.why
        )
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable, Associations,
)]
#[diesel(table_name = crate::schema::cognitive_facts)]
#[diesel(belongs_to(crate::models::users::User, foreign_key = user_id))]
#[diesel(belongs_to(crate::models::chronicle::PlayerChronicle, foreign_key = chronicle_id))]
pub struct CognitiveFact {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub who_encrypted: Vec<u8>,
    pub who_nonce: Vec<u8>,
    pub what_encrypted: Vec<u8>,
    pub what_nonce: Vec<u8>,
    pub where_encrypted: Vec<u8>,
    pub where_nonce: Vec<u8>,
    pub when_encrypted: Vec<u8>,
    pub when_nonce: Vec<u8>,
    pub why_encrypted: Vec<u8>,
    pub why_nonce: Vec<u8>,
    pub fact_type: String,
    pub confidence: f32,
    pub significance: f32,
    pub created_at: DbTimestamp,
    pub message_variant_id: Option<DbId>,
}

impl CognitiveFact {
    pub fn decrypt(&self, session_dek: &SessionDek) -> Result<ExtractedFact, CryptoError> {
        let who = String::from_utf8_lossy(
            decrypt_gcm(&self.who_encrypted, &self.who_nonce, &session_dek.0)?.expose_secret(),
        )
        .to_string();
        let what = String::from_utf8_lossy(
            decrypt_gcm(&self.what_encrypted, &self.what_nonce, &session_dek.0)?.expose_secret(),
        )
        .to_string();
        let where_ = String::from_utf8_lossy(
            decrypt_gcm(&self.where_encrypted, &self.where_nonce, &session_dek.0)?.expose_secret(),
        )
        .to_string();
        let when = String::from_utf8_lossy(
            decrypt_gcm(&self.when_encrypted, &self.when_nonce, &session_dek.0)?.expose_secret(),
        )
        .to_string();
        let why = String::from_utf8_lossy(
            decrypt_gcm(&self.why_encrypted, &self.why_nonce, &session_dek.0)?.expose_secret(),
        )
        .to_string();

        Ok(ExtractedFact {
            who,
            what,
            r#where: where_,
            when,
            why,
            fact_type: self.fact_type.clone(),
            confidence: self.confidence,
            significance: self.significance,
        })
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::cognitive_facts)]
pub struct NewCognitiveFact {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub who_encrypted: Vec<u8>,
    pub who_nonce: Vec<u8>,
    pub what_encrypted: Vec<u8>,
    pub what_nonce: Vec<u8>,
    pub where_encrypted: Vec<u8>,
    pub where_nonce: Vec<u8>,
    pub when_encrypted: Vec<u8>,
    pub when_nonce: Vec<u8>,
    pub why_encrypted: Vec<u8>,
    pub why_nonce: Vec<u8>,
    pub fact_type: String,
    pub confidence: f32,
    pub significance: f32,
    pub created_at: DbTimestamp,
    pub message_variant_id: Option<DbId>,
}

impl Default for NewCognitiveFact {
    fn default() -> Self {
        Self {
            id: DbId::new(),
            user_id: DbId::nil(),
            chronicle_id: DbId::nil(),
            who_encrypted: Vec::new(),
            who_nonce: Vec::new(),
            what_encrypted: Vec::new(),
            what_nonce: Vec::new(),
            where_encrypted: Vec::new(),
            where_nonce: Vec::new(),
            when_encrypted: Vec::new(),
            when_nonce: Vec::new(),
            why_encrypted: Vec::new(),
            why_nonce: Vec::new(),
            fact_type: String::new(),
            confidence: 0.0,
            significance: 0.0,
            created_at: DbTimestamp::now(),
            message_variant_id: None,
        }
    }
}

impl NewCognitiveFact {
    pub fn builder() -> NewCognitiveFactBuilder {
        NewCognitiveFactBuilder::default()
    }
}

#[derive(Default)]
pub struct NewCognitiveFactBuilder {
    inner: NewCognitiveFact,
}

impl NewCognitiveFactBuilder {
    pub fn user_id(mut self, id: DbId) -> Self {
        self.inner.user_id = id;
        self
    }
    pub fn chronicle_id(mut self, id: DbId) -> Self {
        self.inner.chronicle_id = id;
        self
    }
    pub fn who_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.who_encrypted = data;
        self
    }
    pub fn who_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.who_nonce = nonce;
        self
    }
    pub fn what_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.what_encrypted = data;
        self
    }
    pub fn what_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.what_nonce = nonce;
        self
    }
    pub fn where_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.where_encrypted = data;
        self
    }
    pub fn where_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.where_nonce = nonce;
        self
    }
    pub fn when_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.when_encrypted = data;
        self
    }
    pub fn when_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.when_nonce = nonce;
        self
    }
    pub fn why_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.why_encrypted = data;
        self
    }
    pub fn why_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.why_nonce = nonce;
        self
    }
    pub fn fact_type(mut self, fact_type: String) -> Self {
        self.inner.fact_type = fact_type;
        self
    }
    pub fn confidence(mut self, val: f32) -> Self {
        self.inner.confidence = val;
        self
    }
    pub fn significance(mut self, val: f32) -> Self {
        self.inner.significance = val;
        self
    }
    pub fn message_variant_id(mut self, id: Option<DbId>) -> Self {
        self.inner.message_variant_id = id;
        self
    }
    pub fn build(self) -> NewCognitiveFact {
        self.inner
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable, Associations,
)]
#[diesel(table_name = crate::schema::cognitive_core_memory)]
#[diesel(belongs_to(crate::models::users::User, foreign_key = user_id))]
#[diesel(belongs_to(crate::models::chronicle::PlayerChronicle, foreign_key = chronicle_id))]
pub struct CoreMemory {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub memory_state_encrypted: Vec<u8>,
    pub memory_state_nonce: Vec<u8>,
    pub version: i32,
    pub updated_at: DbTimestamp,
}

impl CoreMemory {
    pub fn decrypt(&self, session_dek: &SessionDek) -> Result<String, CryptoError> {
        let state_decrypted = decrypt_gcm(
            &self.memory_state_encrypted,
            &self.memory_state_nonce,
            &session_dek.0,
        )?;
        Ok(String::from_utf8_lossy(state_decrypted.expose_secret()).to_string())
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::cognitive_core_memory)]
pub struct NewCoreMemory {
    pub id: DbId,
    pub user_id: DbId,
    pub chronicle_id: DbId,
    pub memory_state_encrypted: Vec<u8>,
    pub memory_state_nonce: Vec<u8>,
    pub version: i32,
    pub updated_at: DbTimestamp,
}

impl Default for NewCoreMemory {
    fn default() -> Self {
        Self {
            id: DbId::new(),
            user_id: DbId::nil(),
            chronicle_id: DbId::nil(),
            memory_state_encrypted: Vec::new(),
            memory_state_nonce: Vec::new(),
            version: 1,
            updated_at: DbTimestamp::now(),
        }
    }
}

impl NewCoreMemory {
    pub fn builder() -> NewCoreMemoryBuilder {
        NewCoreMemoryBuilder::default()
    }
}

#[derive(Default)]
pub struct NewCoreMemoryBuilder {
    inner: NewCoreMemory,
}

impl NewCoreMemoryBuilder {
    pub fn user_id(mut self, id: DbId) -> Self {
        self.inner.user_id = id;
        self
    }
    pub fn chronicle_id(mut self, id: DbId) -> Self {
        self.inner.chronicle_id = id;
        self
    }
    pub fn memory_state_encrypted(mut self, data: Vec<u8>) -> Self {
        self.inner.memory_state_encrypted = data;
        self
    }
    pub fn memory_state_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.inner.memory_state_nonce = nonce;
        self
    }
    pub fn version(mut self, version: i32) -> Self {
        self.inner.version = version;
        self
    }
    pub fn build(self) -> NewCoreMemory {
        self.inner
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpinionExtraction {
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub perspective: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub opinion: String,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationExtraction {
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub entity_name: String,
    #[serde(default, deserialize_with = "deserialize_string_flexible")]
    pub observation: String,
    #[serde(default)]
    pub confidence: f32,
}
