use crate::IntelligenceError;
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait VectorService: Send + Sync {
    async fn ensure_collection(&self, name: &str) -> Result<(), IntelligenceError>;
    async fn add_documents(&self, collection: &str, documents: Vec<Value>) -> Result<(), IntelligenceError>;
    async fn search(&self, collection: &str, query: &str, limit: usize) -> Result<Vec<(f32, Value)>, IntelligenceError>;
    async fn health_check(&self) -> Result<(), IntelligenceError>;
}

pub mod qdrant;
pub mod lancedb;
