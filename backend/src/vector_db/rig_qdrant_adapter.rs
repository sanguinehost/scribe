use super::VectorServiceTrait;
use crate::config::Config;
use crate::errors::AppError;
use crate::llm::UnifiedEmbeddingModel;
use ::rig_qdrant::QdrantVectorStore;
use async_trait::async_trait;
use qdrant_client::qdrant::QueryPoints;
use rig::embeddings::EmbeddingModel;
use rig::vector_store::VectorStoreIndex; // Import VectorStoreIndex trait
use std::sync::Arc;

pub struct RigQdrantService {
    client: qdrant_client::Qdrant,
    model: UnifiedEmbeddingModel,
    query_params: QueryPoints,
}

impl RigQdrantService {
    pub async fn new(
        config: Arc<Config>,
        embedding_model: UnifiedEmbeddingModel,
    ) -> Result<Self, AppError> {
        let qdrant_url = config
            .qdrant_url
            .as_ref()
            .ok_or_else(|| AppError::ConfigError("QDRANT_URL is not configured".to_string()))?;

        let client = qdrant_client::Qdrant::from_url(qdrant_url)
            .api_key(config.qdrant_api_key.clone().unwrap_or_default())
            .build()
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to build Qdrant client: {}", e))
            })?;

        let collection_name = config.qdrant_collection_name.clone();

        let query_params = QueryPoints {
            collection_name: collection_name.clone(),
            ..Default::default()
        };

        Ok(Self {
            client,
            model: embedding_model,
            query_params,
        })
    }

    pub fn index(&self) -> Arc<QdrantVectorStore<UnifiedEmbeddingModel>> {
        Arc::new(QdrantVectorStore::new(
            self.client.clone(),
            self.model.clone(),
            self.query_params.clone(),
        ))
    }

    pub async fn add_document<T: rig::Embed + serde::Serialize + Send + Sync>(
        &self,
        document: T,
    ) -> Result<(), AppError> {
        self.add_documents(vec![document]).await
    }

    pub async fn add_documents<T: rig::Embed + serde::Serialize + Send + Sync>(
        &self,
        documents: Vec<T>,
    ) -> Result<(), AppError> {
        for doc in documents {
            let doc_value = serde_json::to_value(doc).map_err(|e| {
                AppError::VectorDbError(format!("Failed to serialize document: {}", e))
            })?;
            self.add_document_to_collection(&self.query_params.collection_name, doc_value)
                .await?;
        }
        Ok(())
    }

    pub async fn search<T: for<'a> serde::Deserialize<'a> + Send + Sync>(
        &self,
        query: &str,
        limit: usize,
        _filter: Option<qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<(f32, T)>, AppError> {
        // Convert Qdrant Filter to JSON - for now just pass None
        // A proper implementation would convert the filter to JSON
        let results = self.search_values(query, limit, None).await?;
        let mut typed_results = Vec::new();
        for (score, val) in results {
            let doc: T = serde_json::from_value(val).map_err(|e| {
                AppError::VectorDbError(format!("Failed to deserialize document: {}", e))
            })?;
            typed_results.push((score, doc));
        }
        Ok(typed_results)
    }
}

#[async_trait]
impl VectorServiceTrait for RigQdrantService {
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        Ok(())
    }

    async fn ensure_collection_exists_named(&self, _collection_name: &str) -> Result<(), AppError> {
        Ok(())
    }

    async fn add_document(&self, document: serde_json::Value) -> Result<(), AppError> {
        self.add_document_to_collection(&self.query_params.collection_name, document)
            .await
    }

    async fn add_documents(&self, documents: Vec<serde_json::Value>) -> Result<(), AppError> {
        for doc in documents {
            self.add_document_to_collection(&self.query_params.collection_name, doc)
                .await?;
        }
        Ok(())
    }

    async fn add_document_to_collection(
        &self,
        collection_name: &str,
        document: serde_json::Value,
    ) -> Result<(), AppError> {
        // 1. Extract text for embedding from documents
        let text = document
            .get("content")
            .or_else(|| document.get("summary"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| document.to_string());

        // 2. Generate embeddings
        let embeddings = self
            .model
            .embed_texts(vec![text])
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to embed document: {}", e)))?;

        let embedding = embeddings
            .into_iter()
            .next()
            .ok_or_else(|| AppError::VectorDbError("No embedding returned".to_string()))?;

        // 3. Prepare Qdrant point
        let id = document
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let payload: qdrant_client::Payload = match document {
            serde_json::Value::Object(map) => {
                let mut payload_map: std::collections::HashMap<
                    String,
                    qdrant_client::qdrant::Value,
                > = std::collections::HashMap::new();
                for (k, v) in map {
                    payload_map.insert(k, v.into());
                }
                payload_map.into()
            }
            _ => {
                let mut payload_map: std::collections::HashMap<
                    String,
                    qdrant_client::qdrant::Value,
                > = std::collections::HashMap::new();
                payload_map.insert("document".to_string(), document.into());
                payload_map.into()
            }
        };

        let point = qdrant_client::qdrant::PointStruct::new(
            id,
            embedding
                .vec
                .into_iter()
                .map(|v| v as f32)
                .collect::<Vec<f32>>(),
            payload,
        );

        // 4. Store point
        self.client
            .upsert_points(qdrant_client::qdrant::UpsertPoints {
                collection_name: collection_name.to_string(),
                points: vec![point],
                ..Default::default()
            })
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to upsert point to Qdrant: {}", e))
            })?;

        Ok(())
    }

    async fn search_values(
        &self,
        query: &str,
        limit: usize,
        filter: Option<qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<(f32, serde_json::Value)>, AppError> {
        let query_embedding = self
            .model
            .embed_texts(vec![query.to_string()])
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to embed query: {}", e)))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                AppError::VectorDbError("No embedding returned for query".to_string())
            })?;

        let search_result = self
            .client
            .search_points(qdrant_client::qdrant::SearchPoints {
                collection_name: self.query_params.collection_name.clone(),
                vector: query_embedding
                    .vec
                    .into_iter()
                    .map(|v| v as f32)
                    .collect::<Vec<f32>>(),
                limit: limit as u64,
                filter,
                with_payload: Some(true.into()),
                ..Default::default()
            })
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to search Qdrant: {}", e)))?;

        let mut final_results = Vec::new();
        for res in search_result.result {
            let payload = res.payload;
            let doc_value = serde_json::Value::Object(
                payload
                    .into_iter()
                    .map(|(k, v)| (k, v.into()))
                    .collect::<serde_json::Map<String, serde_json::Value>>(),
            );
            final_results.push((res.score, doc_value));
        }

        Ok(final_results)
    }

    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>, AppError> {
        let search_result = self
            .client
            .search_points(qdrant_client::qdrant::SearchPoints {
                collection_name: self.query_params.collection_name.clone(),
                vector: vector.into_iter().map(|v| v as f32).collect::<Vec<f32>>(),
                limit,
                filter,
                score_threshold,
                with_payload: Some(true.into()),
                ..Default::default()
            })
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to search Qdrant: {}", e)))?;

        Ok(search_result.result)
    }

    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        _text_query: Option<String>,
        _text_fields: Vec<String>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>, AppError> {
        // For now, just use vector search if available
        if let Some(v) = vector {
            self.search_points_with_threshold(v, limit, filter, score_threshold)
                .await
        } else {
            // If only text query, we'd need a different implementation
            // For now return empty or implement basic text search if possible
            Ok(vec![])
        }
    }

    async fn retrieve_points(
        &self,
        filter: Option<qdrant_client::qdrant::Filter>,
        limit: u64,
        offset: Option<u64>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>, AppError> {
        let search_result = self
            .client
            .search_points(qdrant_client::qdrant::SearchPoints {
                collection_name: self.query_params.collection_name.clone(),
                vector: vec![0.0; self.model.ndims()], // Dummy vector for retrieval
                limit,
                offset,
                filter,
                score_threshold,
                with_payload: Some(true.into()),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to retrieve from Qdrant: {}", e))
            })?;

        Ok(search_result.result)
    }

    async fn delete_points(
        &self,
        ids: Vec<qdrant_client::qdrant::PointId>,
    ) -> Result<(), AppError> {
        self.client
            .delete_points(qdrant_client::qdrant::DeletePoints {
                collection_name: self.query_params.collection_name.clone(),
                points: Some(
                    ids.into_iter()
                        .map(|id| id.into())
                        .collect::<Vec<_>>()
                        .into(),
                ),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to delete points from Qdrant: {}", e))
            })?;
        Ok(())
    }

    async fn delete_by_filter(
        &self,
        filter: qdrant_client::qdrant::Filter,
    ) -> Result<(), AppError> {
        // Implement using low-level client
        self.client
            .delete_points(qdrant_client::qdrant::DeletePoints {
                collection_name: self.query_params.collection_name.clone(),
                points: Some(qdrant_client::qdrant::PointsSelector {
                    points_selector_one_of: Some(
                        qdrant_client::qdrant::points_selector::PointsSelectorOneOf::Filter(filter),
                    ),
                }),
                ..Default::default()
            })
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to delete from Qdrant: {}", e)))?;
        Ok(())
    }

    async fn delete_by_id(&self, _id: &str) -> Result<(), AppError> {
        Ok(())
    }

    async fn optimize_collection(&self) -> Result<(), AppError> {
        // Qdrant handles optimization automatically, but we can trigger a manual one if needed
        // For now, this can be a no-op or we can call update_collection
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        Ok(())
    }
}
