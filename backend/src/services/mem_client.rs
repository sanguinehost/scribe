use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::privacy::logging::sanitize_json_value;

// --- Model Types (Re-implemented for standalone client) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    Working,
    Episodic,
    Semantic,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryScope {
    /// Tenant / org id (or a fixed value for single-tenant installs).
    pub tenant: String,
    /// What the scope groups — e.g. "agent:research", "user:u_123".
    pub kind: String,
    /// The specific instance id within kind.
    pub id: String,
}

impl MemoryScope {
    pub fn new(tenant: impl Into<String>, kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            kind: kind.into(),
            id: id.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub scope: MemoryScope,
    /// "user", "assistant", "tool", "system", "event", ...
    pub role: String,
    /// The text of the turn / a rendered event.
    pub content: String,
    /// Arbitrary structured context.
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// When the event happened.
    #[serde(default = "Utc::now")]
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallRequest {
    pub scope: MemoryScope,
    /// The natural-language query to recall against.
    pub query: String,
    /// How many items to return.
    #[serde(default = "default_k")]
    pub k: usize,
    /// Bi-temporal cut — if set, only facts that were true (and known) at this instant are returned.
    #[serde(default)]
    pub as_of: Option<DateTime<Utc>>,
    /// Restrict to facts mentioning at least one of these entity names.
    #[serde(default)]
    pub entities: Vec<String>,
    /// Which tier(s) to draw from.
    #[serde(default = "default_recall_tiers")]
    pub tiers: Vec<MemoryTier>,
}

fn default_k() -> usize { 8 }
fn default_recall_tiers() -> Vec<MemoryTier> { vec![MemoryTier::Semantic] }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryItem {
    pub tier: MemoryTier,
    pub text: String,
    pub source_ref: String,
    pub est_tokens: u32,
    pub score: f32,
    #[serde(default)]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default)]
    pub ref_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResponse {
    pub items: Vec<MemoryItem>,
    pub scope: MemoryScope,
    pub as_of: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub scope: MemoryScope,
    pub episodes: Vec<Episode>,
    #[serde(default)]
    pub skip_extraction: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WriteResponse {
    pub episodes_stored: usize,
    pub facts_extracted: usize,
    pub facts_inserted: usize,
    pub facts_updated: usize,
    pub facts_superseded: usize,
    pub facts_skipped_subsumed: usize,
    pub entities_upserted: usize,
}

// --- Client Implementation ---

#[derive(Debug, thiserror::Error)]
pub enum MemClientError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("API error (status {status}): {message}")]
    Api { status: u16, message: String },
    
    #[error("Invalid configuration: {0}")]
    Config(&'static str),
}

/// Standalone client for the `mem` bi-temporal fact recall service.
pub struct MemServerClient {
    client: reqwest::Client,
    base_url: String,
    token: Option<String>,
}

impl MemServerClient {
    pub fn new(base_url: String, token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        }
    }

    /// Recall relevant memories based on a query.
    pub async fn recall(&self, req: RecallRequest) -> Result<RecallResponse, MemClientError> {
        let url = format!("{}/recall", self.base_url);
        
        // Apply privacy standards before logging
        if let Ok(val) = serde_json::to_value(&req) {
            let sanitized = sanitize_json_value(&val);
            tracing::debug!(target: "scribe_mem_client", payload = %sanitized, "Memory recall request");
        }

        let mut rb = self.client.post(url).json(&req);
        if let Some(ref t) = self.token {
            rb = rb.bearer_auth(t);
        }

        let resp = rb.send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_else(|_| "Unknown error".into());
            return Err(MemClientError::Api { status, message });
        }

        Ok(resp.json().await?)
    }

    /// Write episodes to memory for fact extraction.
    pub async fn write(&self, req: WriteRequest) -> Result<WriteResponse, MemClientError> {
        let url = format!("{}/write", self.base_url);
        
        // Apply privacy standards before logging
        if let Ok(val) = serde_json::to_value(&req) {
            let sanitized = sanitize_json_value(&val);
            tracing::debug!(target: "scribe_mem_client", payload = %sanitized, "Memory write request");
        }

        let mut rb = self.client.post(url).json(&req);
        if let Some(ref t) = self.token {
            rb = rb.bearer_auth(t);
        }

        let resp = rb.send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_else(|_| "Unknown error".into());
            return Err(MemClientError::Api { status, message });
        }

        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_mem_client_extract_and_recall() {
        let mut server = Server::new_async().await;
        let url = server.url();
        let client = MemServerClient::new(url, Some("test-token".into()));

        let scope = MemoryScope::new("default", "user", "u1");

        // 1. Mock the /write endpoint
        let write_mock = server.mock("POST", "/write")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&WriteResponse {
                episodes_stored: 1,
                facts_extracted: 1,
                facts_inserted: 1,
                ..Default::default()
            }).unwrap())
            .create_async().await;

        let episode = Episode {
            id: Uuid::new_v4(),
            scope: scope.clone(),
            role: "user".into(),
            content: "I prefer dark mode".into(),
            metadata: serde_json::Value::Null,
            occurred_at: Utc::now(),
        };

        let write_resp = client.write(WriteRequest {
            scope: scope.clone(),
            episodes: vec![episode],
            skip_extraction: false,
        }).await.expect("Write failed");

        assert_eq!(write_resp.episodes_stored, 1);
        write_mock.assert_async().await;

        // 2. Mock the /recall endpoint
        let recall_mock = server.mock("POST", "/recall")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&RecallResponse {
                items: vec![MemoryItem {
                    tier: MemoryTier::Semantic,
                    text: "User prefers dark mode".into(),
                    source_ref: "mem:fact:123".into(),
                    est_tokens: 5,
                    score: 0.95,
                    as_of: Some(Utc::now()),
                    ref_id: Some(Uuid::new_v4()),
                }],
                scope: scope.clone(),
                as_of: Utc::now(),
            }).unwrap())
            .create_async().await;

        let recall_resp = client.recall(RecallRequest {
            scope: scope.clone(),
            query: "What are the user's preferences?".into(),
            k: 5,
            as_of: None,
            entities: vec![],
            tiers: vec![MemoryTier::Semantic],
        }).await.expect("Recall failed");

        assert_eq!(recall_resp.items.len(), 1);
        assert_eq!(recall_resp.items[0].text, "User prefers dark mode");
        recall_mock.assert_async().await;
    }
}
