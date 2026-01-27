use super::VectorServiceTrait;
use crate::config::Config;
use crate::errors::AppError;
use crate::llm::UnifiedEmbeddingModel;
use ::rig_lancedb::LanceDbVectorIndex;
use arrow::array::{
    builder::{FixedSizeListBuilder, Float64Builder, StringBuilder},
    ArrayRef, RecordBatch,
};
use arrow::datatypes::{DataType, Field, Schema};
use async_trait::async_trait;
use lancedb::query::{ExecutableQuery, QueryBase};
use qdrant_client::qdrant::{
    condition::ConditionOneOf, r#match::MatchValue, Condition, FieldCondition, Filter,
};
use rig::embeddings::EmbeddingModel;
use std::path::PathBuf;
use std::sync::Arc;

pub struct RigLanceDbService {
    index: Arc<LanceDbVectorIndex<UnifiedEmbeddingModel>>,
    table: lancedb::Table,
    model: UnifiedEmbeddingModel,
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

        let table_name = config.qdrant_collection_name.clone();

        // Open the table first
        let table = connection
            .open_table(&table_name)
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to open LanceDB table: {}", e)))?;

        // Create index for reading
        let index = LanceDbVectorIndex::new(
            table.clone(),
            embedding_model.clone(),
            "id", // Use "id" as the id field
            Default::default(),
        )
        .await
        .map_err(|e| AppError::VectorDbError(format!("Failed to create LanceDB index: {}", e)))?;

        Ok(Self {
            index: Arc::new(index),
            table,
            model: embedding_model,
        })
    }

    pub fn index(&self) -> Arc<LanceDbVectorIndex<UnifiedEmbeddingModel>> {
        self.index.clone()
    }

    async fn add_documents_to_table(
        &self,
        table: &lancedb::Table,
        documents: Vec<serde_json::Value>,
    ) -> Result<(), AppError> {
        // 1. Extract text for embedding from documents
        let mut texts = Vec::new();
        for doc in &documents {
            let text = doc
                .get("content")
                .or_else(|| doc.get("summary"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| doc.to_string());
            texts.push(text);
        }

        // 2. Generate embeddings
        let embeddings =
            self.model.embed_texts(texts).await.map_err(|e| {
                AppError::VectorDbError(format!("Failed to embed documents: {}", e))
            })?;

        let mut rows = Vec::new();
        for (doc, embedding) in documents.into_iter().zip(embeddings) {
            let mut row = doc;
            if let serde_json::Value::Object(ref mut map) = row {
                map.insert(
                    "vector".to_string(),
                    serde_json::to_value(embedding.vec).unwrap(),
                );
            }
            rows.push(row);
        }

        if rows.is_empty() {
            return Ok(());
        }

        // Manual conversion to RecordBatch
        let ndims = self.model.ndims();
        let mut columns: std::collections::HashMap<String, Vec<serde_json::Value>> =
            std::collections::HashMap::new();
        let mut keys = Vec::new();

        for row in &rows {
            if let serde_json::Value::Object(map) = row {
                for (k, v) in map {
                    if !columns.contains_key(k) {
                        keys.push(k.clone());
                    }
                    columns.entry(k.clone()).or_default().push(v.clone());
                }
            }
        }

        let mut fields = Vec::new();
        let mut arrays = Vec::new();

        for name in keys {
            let values = columns.get(&name).unwrap();
            if name == "vector" {
                let mut builder = FixedSizeListBuilder::new(Float64Builder::new(), ndims as i32);
                for val in values {
                    if let serde_json::Value::Array(arr) = val {
                        let vec: Vec<f64> = arr.iter().map(|v| v.as_f64().unwrap_or(0.0)).collect();
                        builder.values().append_slice(&vec);
                        builder.append(true);
                    } else {
                        builder.append(false);
                    }
                }
                fields.push(Field::new(
                    name,
                    DataType::FixedSizeList(
                        Arc::new(Field::new("item", DataType::Float64, true)),
                        ndims as i32,
                    ),
                    false,
                ));
                arrays.push(Arc::new(builder.finish()) as ArrayRef);
            } else {
                let mut builder = StringBuilder::new();
                for val in values {
                    match val {
                        serde_json::Value::String(s) => builder.append_value(s),
                        serde_json::Value::Null => builder.append_null(),
                        _ => builder.append_value(val.to_string()),
                    }
                }
                fields.push(Field::new(name, DataType::Utf8, true));
                arrays.push(Arc::new(builder.finish()) as ArrayRef);
            }
        }

        let schema = Arc::new(Schema::new(fields));
        let batch = RecordBatch::try_new(schema.clone(), arrays)
            .map_err(|e| AppError::VectorDbError(format!("Failed to create RecordBatch: {}", e)))?;

        let batches = arrow::array::RecordBatchIterator::new(vec![Ok(batch)], schema);

        table.add(Box::new(batches)).execute().await.map_err(|e| {
            AppError::VectorDbError(format!("Failed to add documents to LanceDB: {}", e))
        })?;

        Ok(())
    }

    /// Convert Qdrant Filter to LanceDB SQL WHERE clause
    fn filter_to_sql(&self, filter: &Filter) -> String {
        let mut conditions = Vec::new();

        // Process MUST conditions (AND)
        if !filter.must.is_empty() {
            let must_conditions: Vec<String> = filter
                .must
                .iter()
                .filter_map(|c| self.condition_to_sql(c))
                .collect();
            if !must_conditions.is_empty() {
                conditions.push(format!("({})", must_conditions.join(" AND ")));
            }
        }

        // Process SHOULD conditions (OR)
        if !filter.should.is_empty() {
            let should_conditions: Vec<String> = filter
                .should
                .iter()
                .filter_map(|c| self.condition_to_sql(c))
                .collect();
            if !should_conditions.is_empty() {
                conditions.push(format!("({})", should_conditions.join(" OR ")));
            }
        }

        // Process MUST_NOT conditions (NOT)
        if !filter.must_not.is_empty() {
            let must_not_conditions: Vec<String> = filter
                .must_not
                .iter()
                .filter_map(|c| self.condition_to_sql(c))
                .collect();
            if !must_not_conditions.is_empty() {
                conditions.push(format!("NOT ({})", must_not_conditions.join(" OR ")));
            }
        }

        if conditions.is_empty() {
            String::new()
        } else {
            conditions.join(" AND ")
        }
    }

    /// Convert a single Qdrant Condition to SQL
    fn condition_to_sql(&self, condition: &Condition) -> Option<String> {
        match &condition.condition_one_of {
            Some(ConditionOneOf::Field(field_cond)) => self.field_condition_to_sql(field_cond),
            Some(ConditionOneOf::Filter(nested)) => {
                let sql = self.filter_to_sql(nested);
                if sql.is_empty() {
                    None
                } else {
                    Some(format!("({})", sql))
                }
            }
            _ => None,
        }
    }

    /// Convert a field condition to SQL
    fn field_condition_to_sql(&self, field_cond: &FieldCondition) -> Option<String> {
        let key = self.sanitize_column_name(&field_cond.key);

        if let Some(m) = &field_cond.r#match {
            if let Some(match_value) = &m.match_value {
                return match match_value {
                    MatchValue::Keyword(s) => {
                        Some(format!("{} = '{}'", key, self.escape_sql_string(s)))
                    }
                    MatchValue::Integer(i) => Some(format!("{} = {}", key, i)),
                    MatchValue::Boolean(b) => Some(format!("{} = {}", key, b)),
                    MatchValue::Text(s) => {
                        Some(format!("{} LIKE '%{}%'", key, self.escape_sql_string(s)))
                    }
                    _ => None,
                };
            }
        }
        None
    }

    /// Sanitize column name to prevent SQL injection
    fn sanitize_column_name(&self, name: &str) -> String {
        // Handle nested paths like "metadata.user_id" by using only the leaf name
        let leaf_name = name.rsplit('.').next().unwrap_or(name);
        // Only allow alphanumeric and underscore
        leaf_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect()
    }

    /// Escape SQL string values
    fn escape_sql_string(&self, s: &str) -> String {
        s.replace('\'', "''")
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
        let mut docs = Vec::new();
        for doc in documents {
            docs.push(serde_json::to_value(doc).map_err(|e| {
                AppError::VectorDbError(format!("Failed to serialize document: {}", e))
            })?);
        }
        self.add_documents_to_table(&self.table, docs).await
    }

    pub async fn search<T: for<'a> serde::Deserialize<'a> + Send + Sync>(
        &self,
        query: &str,
        limit: usize,
        filter: Option<qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<(f32, T)>, AppError> {
        let results = self.search_values(query, limit, filter).await?;
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
impl VectorServiceTrait for RigLanceDbService {
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        Ok(())
    }

    async fn ensure_collection_exists_named(&self, _collection_name: &str) -> Result<(), AppError> {
        Ok(())
    }

    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>, AppError> {
        let mut lancedb_query = self
            .table
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

                final_results.push(qdrant_client::qdrant::ScoredPoint {
                    id: None, // LanceDB doesn't have Qdrant PointId
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

    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        text_query: Option<String>,
        _text_fields: Vec<String>,
        limit: u64,
        filter: Option<qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>, AppError> {
        if let Some(v) = vector {
            self.search_points_with_threshold(v, limit, filter, score_threshold)
                .await
        } else if let Some(query) = text_query {
            // Fallback to search_values and convert
            let results = self.search_values(&query, limit as usize, filter).await?;
            Ok(results
                .into_iter()
                .map(|(score, val)| {
                    qdrant_client::qdrant::ScoredPoint {
                        id: None,
                        version: 0,
                        score,
                        payload: std::collections::HashMap::new(), // Simplified
                        vectors: None,
                        shard_key: None,
                        order_value: None,
                    }
                })
                .collect())
        } else {
            Ok(vec![])
        }
    }

    async fn add_document(&self, document: serde_json::Value) -> Result<(), AppError> {
        self.add_documents(vec![document]).await
    }

    async fn add_documents(&self, documents: Vec<serde_json::Value>) -> Result<(), AppError> {
        self.add_documents_to_table(&self.table, documents).await
    }

    async fn add_document_to_collection(
        &self,
        collection_name: &str,
        document: serde_json::Value,
    ) -> Result<(), AppError> {
        // For LanceDB, we'll just use the existing table if the name matches,
        // otherwise we'd need to open/create another table.
        // Since we don't easily have the connection here without storing it,
        // we'll just use the current table for now if it's the same name.
        self.add_documents_to_table(&self.table, vec![document])
            .await
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

        let results = self
            .search_points_with_threshold(
                query_embedding.vec.into_iter().map(|v| v as f32).collect(),
                limit as u64,
                filter,
                None,
            )
            .await?;

        Ok(results
            .into_iter()
            .map(|res| {
                let doc_value = serde_json::Value::Object(
                    res.payload
                        .into_iter()
                        .map(|(k, v)| (k, v.into()))
                        .collect(),
                );
                (res.score, doc_value)
            })
            .collect())
    }

    async fn retrieve_points(
        &self,
        filter: Option<qdrant_client::qdrant::Filter>,
        limit: u64,
        offset: Option<u64>,
        _score_threshold: Option<f32>,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>, AppError> {
        let mut lancedb_query = self.table.query().limit(limit as usize);

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

                final_results.push(qdrant_client::qdrant::ScoredPoint {
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
        self.table
            .delete(&format!("id IN ({})", id_list))
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to delete from LanceDB: {}", e))
            })?;
        Ok(())
    }

    async fn delete_by_filter(
        &self,
        filter: ::qdrant_client::qdrant::Filter,
    ) -> Result<(), AppError> {
        let sql_filter = self.filter_to_sql(&filter);
        if !sql_filter.is_empty() {
            self.table.delete(&sql_filter).await.map_err(|e| {
                AppError::VectorDbError(format!("Failed to delete from LanceDB: {}", e))
            })?;
        }
        Ok(())
    }

    async fn delete_by_id(&self, id: &str) -> Result<(), AppError> {
        self.table
            .delete(&format!("id = '{}'", id))
            .await
            .map_err(|e| {
                AppError::VectorDbError(format!("Failed to delete from LanceDB: {}", e))
            })?;
        Ok(())
    }

    async fn optimize_collection(&self) -> Result<(), AppError> {
        // LanceDB optimization (compaction)
        // self.table.optimize(lancedb::table::OptimizeOptions::default()).await
        //    .map_err(|e| AppError::VectorDbError(format!("Failed to optimize LanceDB: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        Ok(())
    }
}
