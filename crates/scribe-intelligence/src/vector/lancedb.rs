use crate::vector::VectorService;
use crate::IntelligenceError;
use async_trait::async_trait;
use serde_json::Value;

pub struct LanceDbVectorService;

#[async_trait]
impl VectorService for LanceDbVectorService {
    async fn ensure_collection(&self, _name: &str) -> Result<(), IntelligenceError> {
        Ok(())
    }
    async fn add_documents(&self, _collection: &str, _documents: Vec<Value>) -> Result<(), IntelligenceError> {
        Ok(())
    }
    async fn search(&self, _collection: &str, _query: &str, _limit: usize) -> Result<Vec<(f32, Value)>, IntelligenceError> {
        Ok(vec![])
    }
    async fn health_check(&self) -> Result<(), IntelligenceError> {
        Ok(())
    }
}
