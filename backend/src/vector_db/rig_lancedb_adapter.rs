use super::utils::qdrant_value_to_serde_json;
use super::VectorServiceTrait;
use crate::config::Config;
use crate::errors::AppError;
use crate::llm::UnifiedEmbeddingModel;
use ::rig_lancedb::{LanceDbVectorIndex, SearchParams};
use arrow::array::{
    builder::{FixedSizeListBuilder, Float32Builder, StringBuilder},
    RecordBatch,
};
use arrow::datatypes::{DataType, Field, Schema};
use async_trait::async_trait;
use lancedb::query::{ExecutableQuery, QueryBase};
use qdrant_client::qdrant::{condition::ConditionOneOf, r#match::MatchValue, Filter, ScoredPoint};
use rig::embeddings::EmbeddingModel;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub struct RigLanceDbService {
    connection: lancedb::Connection,
    indices: Arc<RwLock<HashMap<String, Arc<LanceDbVectorIndex<UnifiedEmbeddingModel>>>>>,
    model: UnifiedEmbeddingModel,
    config: Arc<Config>,
}

impl RigLanceDbService {
    pub async fn new(
        config: Arc<Config>,
        embedding_model: UnifiedEmbeddingModel,
    ) -> Result<Self, AppError> {
        let data_dir = config.lancedb_data_dir.clone().unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("scribe")
                .join("lancedb")
        });

        std::fs::create_dir_all(&data_dir).map_err(|e| {
            AppError::ConfigError(format!(
                "Failed to create LanceDB data directory {:?}: {}",
                data_dir, e
            ))
        })?;

        let connection = lancedb::connect(data_dir.to_string_lossy().as_ref())
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to connect to LanceDB: {}", e)))?;

        let service = Self {
            connection,
            indices: Arc::new(RwLock::new(HashMap::new())),
            model: embedding_model,
            config,
        };

        // Initialize default table
        let default_table = service.config.qdrant_collection_name.clone();
        service.get_or_create_index(&default_table).await?;

        Ok(service)
    }

    async fn get_expected_schema(&self) -> Schema {
        Schema::new(vec![
            Field::new("id", DataType::Utf8, false),
            Field::new(
                "vector",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, true)),
                    self.model.ndims() as i32,
                ),
                false,
            ),
            Field::new("payload", DataType::Utf8, false),
        ])
    }

    async fn validate_schema(&self, table: &lancedb::Table) -> bool {
        match table.schema().await {
            Ok(schema) => {
                let _expected = self.get_expected_schema().await;

                // Check if basic fields exist and have correct types
                let has_id = schema
                    .field_with_name("id")
                    .map(|f| f.data_type() == &DataType::Utf8)
                    .unwrap_or(false);
                let has_payload = schema
                    .field_with_name("payload")
                    .map(|f| f.data_type() == &DataType::Utf8)
                    .unwrap_or(false);

                let vector_field = schema.field_with_name("vector");
                let vector_valid = if let Ok(f) = vector_field {
                    if let DataType::FixedSizeList(_, dims) = f.data_type() {
                        *dims == self.model.ndims() as i32
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !has_id || !has_payload || !vector_valid {
                    warn!(
                        "LanceDB schema mismatch for table: has_id={}, has_payload={}, vector_valid={}",
                        has_id, has_payload, vector_valid
                    );
                    return false;
                }
                true
            }
            Err(e) => {
                warn!("Failed to get schema for validation: {}", e);
                false
            }
        }
    }

    async fn get_or_create_index(
        &self,
        name: &str,
    ) -> Result<Arc<LanceDbVectorIndex<UnifiedEmbeddingModel>>, AppError> {
        // Read lock
        {
            let indices = self.indices.read().await;
            if let Some(index) = indices.get(name) {
                return Ok(index.clone());
            }
        }

        // Write lock
        let mut indices = self.indices.write().await;
        // Double check
        if let Some(index) = indices.get(name) {
            return Ok(index.clone());
        }

        debug!("Opening/Creating LanceDB table: {}", name);

        let table_names = self
            .connection
            .table_names()
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to list tables: {}", e)))?;

        let table = if table_names.contains(&name.to_string()) {
            let table = self
                .connection
                .open_table(name)
                .execute()
                .await
                .map_err(|e| {
                    AppError::VectorDbError(format!("Failed to open table {}: {}", name, e))
                })?;

            if self.validate_schema(&table).await {
                table
            } else {
                info!("Dropping incompatible table: {}", name);
                self.connection.drop_table(name, &[]).await.map_err(|e| {
                    AppError::VectorDbError(format!("Failed to drop table {}: {}", name, e))
                })?;

                let schema = Arc::new(self.get_expected_schema().await);
                self.connection
                    .create_empty_table(name, schema)
                    .execute()
                    .await
                    .map_err(|e| {
                        AppError::VectorDbError(format!("Failed to recreate table {}: {}", name, e))
                    })?
            }
        } else {
            let schema = Arc::new(self.get_expected_schema().await);
            self.connection
                .create_empty_table(name, schema)
                .execute()
                .await
                .map_err(|e| {
                    AppError::VectorDbError(format!("Failed to create table {}: {}", name, e))
                })?
        };

        let index = Arc::new(
            LanceDbVectorIndex::new(table, self.model.clone(), "vector", SearchParams::default())
                .await
                .map_err(|e| {
                    AppError::VectorDbError(format!("Failed to create index for {}: {}", name, e))
                })?,
        );

        indices.insert(name.to_string(), index.clone());
        Ok(index)
    }

    async fn add_documents_to_table(
        &self,
        table: &lancedb::Table,
        documents: Vec<serde_json::Value>,
    ) -> Result<(), AppError> {
        let ndims = self.model.ndims() as i32;
        let mut id_builder = StringBuilder::new();
        let mut vector_builder = FixedSizeListBuilder::new(Float32Builder::new(), ndims);
        let mut payload_builder = StringBuilder::new();

        for doc in documents {
            let id = doc["id"].as_str().unwrap_or("").to_string();
            let vector = doc["vector"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .map(|f| f.as_f64().unwrap_or(0.0) as f32)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| vec![0.0; ndims as usize]);
            let payload = serde_json::to_string(&doc["payload"]).unwrap_or_default();

            id_builder.append_value(id);
            for v in vector {
                vector_builder.values().append_value(v);
            }
            vector_builder.append(true);
            payload_builder.append_value(payload);
        }

        let schema = Arc::new(self.get_expected_schema().await);

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(vector_builder.finish()),
                Arc::new(payload_builder.finish()),
            ],
        )
        .map_err(|e| AppError::VectorDbError(format!("Failed to create record batch: {}", e)))?;

        let batches =
            arrow::record_batch::RecordBatchIterator::new(vec![Ok(batch)], schema.clone());

        table
            .add(Box::new(batches))
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to add to LanceDB: {}", e)))?;

        Ok(())
    }

    fn filter_to_sql(&self, filter: &Filter) -> String {
        let mut conditions = Vec::new();

        for condition in &filter.must {
            if let Some(ConditionOneOf::Field(field_cond)) = &condition.condition_one_of {
                if let Some(MatchValue::Keyword(k)) = field_cond
                    .r#match
                    .as_ref()
                    .and_then(|m| m.match_value.as_ref())
                {
                    conditions.push(format!("payload.{} = '{}'", field_cond.key, k));
                } else if let Some(MatchValue::Boolean(b)) = field_cond
                    .r#match
                    .as_ref()
                    .and_then(|m| m.match_value.as_ref())
                {
                    conditions.push(format!("payload.{} = {}", field_cond.key, b));
                }
            }
        }

        conditions.join(" AND ")
    }

    pub async fn add_documents_internal(
        &self,
        collection_name: &str,
        documents: Vec<serde_json::Value>,
    ) -> Result<(), AppError> {
        let _index = self.get_or_create_index(collection_name).await?;
        let ndims = self.model.ndims();
        let mut docs_with_vectors = Vec::new();
        let mut texts_to_embed = Vec::new();
        let mut indices_to_embed = Vec::new();

        for (i, doc) in documents.iter().enumerate() {
            if doc.get("vector").is_some() {
                docs_with_vectors.push(doc.clone());
            } else if let Some(content) = doc.get("content").and_then(|v| v.as_str()) {
                texts_to_embed.push(content.to_string());
                indices_to_embed.push(i);
                docs_with_vectors.push(doc.clone());
            } else if let Some(content) = doc.get("chunk_text").and_then(|v| v.as_str()) {
                texts_to_embed.push(content.to_string());
                indices_to_embed.push(i);
                docs_with_vectors.push(doc.clone());
            } else {
                let mut new_doc = doc.clone();
                new_doc["vector"] = serde_json::json!(vec![0.0; ndims]);
                docs_with_vectors.push(new_doc);
            }
        }

        if !texts_to_embed.is_empty() {
            let embeddings =
                self.model.embed_texts(texts_to_embed).await.map_err(|e| {
                    AppError::VectorDbError(format!("Failed to embed texts: {}", e))
                })?;

            for (i, embedding) in embeddings.into_iter().enumerate() {
                let original_index = indices_to_embed[i];
                let vec_values: Vec<f32> = embedding.vec.into_iter().map(|v| v as f32).collect();
                docs_with_vectors[original_index]["vector"] = serde_json::json!(vec_values);
            }
        }

        // We need to access the underlying lancedb::Table from rig_lancedb::LanceDbVectorIndex
        // rig-lancedb doesn't expose it directly, but RigLanceDbService was storing it.
        // Let's use the connection to open it again (it's fast).
        let table = self
            .connection
            .open_table(collection_name)
            .execute()
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!(
                    "Failed to open table for append {}: {}",
                    collection_name, e
                ))
            })?;

        self.add_documents_to_table(&table, docs_with_vectors).await
    }

    pub async fn search_points_with_threshold_internal(
        &self,
        collection_name: &str,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let _index = self.get_or_create_index(collection_name).await?;
        let table = self
            .connection
            .open_table(collection_name)
            .execute()
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!(
                    "Failed to open table for search {}: {}",
                    collection_name, e
                ))
            })?;

        let mut lancedb_query = table
            .query()
            .nearest_to(vector)
            .map_err(|e| AppError::VectorDbError(format!("Failed to create query: {}", e)))?
            .limit(limit as usize)
            .distance_type(lancedb::DistanceType::Cosine);

        if let Some(f) = filter {
            let sql_filter = self.filter_to_sql(&f);
            if !sql_filter.is_empty() {
                lancedb_query = lancedb_query.only_if(sql_filter);
            }
        }

        let mut results = lancedb_query
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to execute query: {}", e)))?;

        let mut final_results = Vec::new();

        use futures::StreamExt;
        while let Some(batch_result) = results.next().await {
            let batch = batch_result
                .map_err(|e| AppError::VectorDbError(format!("Failed to read batch: {}", e)))?;
            let num_rows = batch.num_rows();
            let distances = batch
                .column_by_name("_distance")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::Float32Array>());

            for i in 0..num_rows {
                let score = distances.map(|d| d.value(i)).unwrap_or(0.0);
                if let Some(threshold) = score_threshold {
                    if score < threshold {
                        continue;
                    }
                }

                let mut payload = std::collections::HashMap::new();
                for j in 0..batch.num_columns() {
                    let col_name = batch.schema().field(j).name().to_string();
                    if col_name == "vector" || col_name == "_distance" {
                        continue;
                    }
                    let col = batch.column(j);
                    let val = if let Some(s) =
                        col.as_any().downcast_ref::<arrow::array::StringArray>()
                    {
                        qdrant_client::qdrant::Value {
                            kind: Some(qdrant_client::qdrant::value::Kind::StringValue(
                                s.value(i).to_string(),
                            )),
                        }
                    } else if let Some(f) =
                        col.as_any().downcast_ref::<arrow::array::Float64Array>()
                    {
                        qdrant_client::qdrant::Value {
                            kind: Some(qdrant_client::qdrant::value::Kind::DoubleValue(f.value(i))),
                        }
                    } else {
                        qdrant_client::qdrant::Value {
                            kind: Some(qdrant_client::qdrant::value::Kind::NullValue(0)),
                        }
                    };
                    payload.insert(col_name, val);
                }

                final_results.push(ScoredPoint {
                    id: None,
                    version: 0,
                    score,
                    payload,
                    vectors: None,
                    shard_key: None,
                    order_value: None,
                });
            }
        }

        Ok(final_results)
    }
}

#[async_trait]
impl VectorServiceTrait for RigLanceDbService {
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        let name = self.config.qdrant_collection_name.clone();
        self.get_or_create_index(&name).await?;
        Ok(())
    }

    async fn ensure_collection_exists_named(&self, collection_name: &str) -> Result<(), AppError> {
        self.get_or_create_index(collection_name).await?;
        Ok(())
    }

    async fn add_document(&self, document: serde_json::Value) -> Result<(), AppError> {
        self.add_documents(vec![document]).await
    }

    async fn add_documents(&self, documents: Vec<serde_json::Value>) -> Result<(), AppError> {
        let name = self.config.qdrant_collection_name.clone();
        self.add_documents_internal(&name, documents).await
    }

    async fn add_document_to_collection(
        &self,
        collection_name: &str,
        document: serde_json::Value,
    ) -> Result<(), AppError> {
        self.add_documents_internal(collection_name, vec![document])
            .await
    }

    async fn search_values(
        &self,
        query: &str,
        limit: usize,
        filter: Option<Filter>,
    ) -> Result<Vec<(f32, serde_json::Value)>, AppError> {
        let name = self.config.qdrant_collection_name.clone();
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

        let results = self
            .search_points_with_threshold_internal(
                &name,
                query_embedding.vec.into_iter().map(|v| v as f32).collect(),
                limit as u64,
                filter,
                None,
            )
            .await?;

        Ok(results
            .into_iter()
            .map(|res| {
                let doc_value = qdrant_value_to_serde_json(qdrant_client::qdrant::Value {
                    kind: Some(qdrant_client::qdrant::value::Kind::StructValue(
                        qdrant_client::qdrant::Struct {
                            fields: res.payload,
                        },
                    )),
                });
                (res.score, doc_value)
            })
            .collect())
    }

    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let name = self.config.qdrant_collection_name.clone();
        self.search_points_with_threshold_internal(&name, vector, limit, filter, score_threshold)
            .await
    }

    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        text_query: Option<String>,
        _text_fields: Vec<String>,
        limit: u64,
        filter: Option<Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let name = self.config.qdrant_collection_name.clone();
        if let Some(v) = vector {
            self.search_points_with_threshold_internal(&name, v, limit, filter, score_threshold)
                .await
        } else if let Some(query) = text_query {
            let results = self.search_values(&query, limit as usize, filter).await?;
            Ok(results
                .into_iter()
                .map(|(score, _val)| ScoredPoint {
                    id: None,
                    version: 0,
                    score,
                    payload: std::collections::HashMap::new(),
                    vectors: None,
                    shard_key: None,
                    order_value: None,
                })
                .collect())
        } else {
            Ok(vec![])
        }
    }

    async fn retrieve_points(
        &self,
        filter: Option<Filter>,
        limit: u64,
        offset: Option<u64>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let name = self.config.qdrant_collection_name.clone();
        let _index = self.get_or_create_index(&name).await?;
        let table = self
            .connection
            .open_table(&name)
            .execute()
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!(
                    "Failed to open table for retrieve {}: {}",
                    name, e
                ))
            })?;

        let mut lancedb_query = table.query().limit(limit as usize);

        if let Some(o) = offset {
            lancedb_query = lancedb_query.offset(o as usize);
        }

        if let Some(f) = filter {
            let sql_filter = self.filter_to_sql(&f);
            if !sql_filter.is_empty() {
                lancedb_query = lancedb_query.only_if(sql_filter);
            }
        }

        let mut results = lancedb_query
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to execute query: {}", e)))?;

        let mut final_results = Vec::new();

        use futures::StreamExt;
        while let Some(batch_result) = results.next().await {
            let batch = batch_result
                .map_err(|e| AppError::VectorDbError(format!("Failed to read batch: {}", e)))?;
            let num_rows = batch.num_rows();
            for i in 0..num_rows {
                let mut payload = std::collections::HashMap::new();
                for j in 0..batch.num_columns() {
                    let col_name = batch.schema().field(j).name().to_string();
                    if col_name == "vector" || col_name == "_distance" {
                        continue;
                    }
                    let col = batch.column(j);
                    let val = if let Some(s) =
                        col.as_any().downcast_ref::<arrow::array::StringArray>()
                    {
                        qdrant_client::qdrant::Value {
                            kind: Some(qdrant_client::qdrant::value::Kind::StringValue(
                                s.value(i).to_string(),
                            )),
                        }
                    } else if let Some(f) =
                        col.as_any().downcast_ref::<arrow::array::Float64Array>()
                    {
                        qdrant_client::qdrant::Value {
                            kind: Some(qdrant_client::qdrant::value::Kind::DoubleValue(f.value(i))),
                        }
                    } else {
                        qdrant_client::qdrant::Value {
                            kind: Some(qdrant_client::qdrant::value::Kind::NullValue(0)),
                        }
                    };
                    payload.insert(col_name, val);
                }

                final_results.push(ScoredPoint {
                    id: None,
                    version: 0,
                    score: 1.0,
                    payload,
                    vectors: None,
                    shard_key: None,
                    order_value: None,
                });
            }
        }

        Ok(final_results)
    }

    async fn delete_points(
        &self,
        ids: Vec<qdrant_client::qdrant::PointId>,
    ) -> Result<(), AppError> {
        let name = self.config.qdrant_collection_name.clone();
        let _index = self.get_or_create_index(&name).await?;
        let table = self
            .connection
            .open_table(&name)
            .execute()
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to open table for delete {}: {}", name, e))
            })?;

        let id_strings: Vec<String> = ids
            .into_iter()
            .map(|id| match id.point_id_options {
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(u)) => u,
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Num(n)) => n.to_string(),
                None => "".to_string(),
            })
            .filter(|s| !s.is_empty())
            .collect();

        if id_strings.is_empty() {
            return Ok(());
        }

        let id_list = id_strings
            .iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(",");
        table
            .delete(&format!("id IN ({})", id_list))
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to delete from LanceDB: {}", e))
            })?;
        Ok(())
    }

    async fn delete_by_filter(&self, filter: Filter) -> Result<(), AppError> {
        let name = self.config.qdrant_collection_name.clone();
        let _index = self.get_or_create_index(&name).await?;
        let table = self
            .connection
            .open_table(&name)
            .execute()
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to open table for delete {}: {}", name, e))
            })?;

        let sql_filter = self.filter_to_sql(&filter);
        if !sql_filter.is_empty() {
            table.delete(&sql_filter).await.map_err(|e| {
                AppError::VectorDbError(format!("Failed to delete from LanceDB: {}", e))
            })?;
        }
        Ok(())
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AppError> {
        let name = self.config.qdrant_collection_name.clone();
        let _index = self.get_or_create_index(&name).await?;
        let table = self
            .connection
            .open_table(&name)
            .execute()
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to open table for delete {}: {}", name, e))
            })?;

        table.delete(&format!("id = '{}'", id)).await.map_err(|e| {
            AppError::VectorDbError(format!("Failed to delete from LanceDB: {}", e))
        })?;
        Ok(())
    }

    async fn optimize_collection(&self) -> Result<(), AppError> {
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        Ok(())
    }
}
