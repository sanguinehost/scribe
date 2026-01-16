// backend/src/vector_db/lancedb_client.rs
//
// LanceDB client implementation for embedded vector database functionality.
// This replaces Qdrant for desktop deployments, providing local vector storage.

use crate::config::Config;
use crate::errors::AppError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

// Re-export Qdrant types that we need to implement the trait
use qdrant_client::qdrant::{
    condition::ConditionOneOf, point_id::PointIdOptions, r#match::MatchValue, value::Kind,
    Condition, FieldCondition, Filter, Match, PointId, PointStruct, ScoredPoint, Value,
};

use arrow::array::{Array, ArrayRef, FixedSizeListArray, Float32Array, RecordBatch, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::{Connection, Table};

use super::qdrant_client::QdrantClientServiceTrait;

/// Default table name for embeddings
pub const DEFAULT_TABLE_NAME: &str = "scribe_embeddings";

/// LanceDB client for embedded vector database operations
#[derive(Clone)]
pub struct LanceDbClient {
    connection: Arc<Connection>,
    table: Arc<RwLock<Option<Table>>>,
    table_name: String,
    embedding_dimension: u64,
}

impl LanceDbClient {
    /// Create a new LanceDB client
    ///
    /// # Arguments
    /// * `config` - Application configuration containing embedding dimension and optional data directory
    ///
    /// # Returns
    /// * `Result<Self, AppError>` - The client instance or an error
    pub async fn new(config: Arc<Config>) -> Result<Self, AppError> {
        // Determine data directory - use config override or default to platform data dir
        let data_dir = config.lancedb_data_dir.clone().unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("scribe")
                .join("lancedb")
        });

        // Ensure directory exists
        std::fs::create_dir_all(&data_dir).map_err(|e| {
            AppError::ConfigError(format!(
                "Failed to create LanceDB data directory {:?}: {}",
                data_dir, e
            ))
        })?;

        info!("Initializing LanceDB at {:?}", data_dir);

        // Connect to LanceDB
        let connection = lancedb::connect(data_dir.to_string_lossy().as_ref())
            .execute()
            .await
            .map_err(|e| AppError::VectorDbError(format!("Failed to connect to LanceDB: {}", e)))?;

        let table_name = config.qdrant_collection_name.clone();
        let embedding_dimension = config.embedding_dimension;

        let client = Self {
            connection: Arc::new(connection),
            table: Arc::new(RwLock::new(None)),
            table_name,
            embedding_dimension,
        };

        info!(
            "LanceDB client initialized: table={}, dimension={}",
            client.table_name, client.embedding_dimension
        );

        Ok(client)
    }

    /// Get the Arrow schema for the embeddings table
    fn get_schema(&self) -> Schema {
        Schema::new(vec![
            Field::new("id", DataType::Utf8, false),
            Field::new(
                "vector",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, false)),
                    self.embedding_dimension as i32,
                ),
                false,
            ),
            // Payload fields as separate columns for filtering
            Field::new("user_id", DataType::Utf8, true),
            Field::new("session_id", DataType::Utf8, true),
            Field::new("message_id", DataType::Utf8, true),
            Field::new("lorebook_id", DataType::Utf8, true),
            Field::new("original_lorebook_entry_id", DataType::Utf8, true),
            Field::new("chronicle_id", DataType::Utf8, true),
            Field::new("source_type", DataType::Utf8, true),
            Field::new("chunk_text", DataType::Utf8, true),
            Field::new("entry_title", DataType::Utf8, true),
            Field::new("speaker", DataType::Utf8, true),
            Field::new("keywords", DataType::Utf8, true),
            Field::new("is_enabled", DataType::Boolean, true),
            Field::new("is_constant", DataType::Boolean, true),
            Field::new("timestamp", DataType::Utf8, true),
            // Encrypted fields
            Field::new("encrypted_chunk_text", DataType::Utf8, true),
            Field::new("chunk_text_nonce", DataType::Utf8, true),
            Field::new("encrypted_title", DataType::Utf8, true),
            Field::new("title_nonce", DataType::Utf8, true),
            // Full payload as JSON for flexibility
            Field::new("payload_json", DataType::Utf8, true),
        ])
    }

    /// Get or create the table, caching it for reuse
    async fn get_table(&self) -> Result<Table, AppError> {
        // Check if we already have the table cached
        {
            let read_guard = self.table.read().await;
            if let Some(table) = read_guard.as_ref() {
                return Ok(table.clone());
            }
        }

        // Try to open existing table, or create if it doesn't exist
        let mut write_guard = self.table.write().await;

        // Double-check after acquiring write lock
        if let Some(table) = write_guard.as_ref() {
            return Ok(table.clone());
        }

        let table = match self.connection.open_table(&self.table_name).execute().await {
            Ok(table) => {
                debug!("Opened existing LanceDB table: {}", self.table_name);
                // Validate schema - if incompatible, we need to recreate
                if self.validate_schema(&table).await {
                    table
                } else {
                    warn!(
                        "LanceDB table schema mismatch, dropping and recreating table: {}",
                        self.table_name
                    );
                    // Drop the incompatible table using LanceDB API
                    let _ = self.connection.drop_table(&self.table_name, &[]).await;

                    // Recreate empty table
                    self.create_empty_table().await?
                }
            }
            Err(_) => {
                // Table doesn't exist, create it with empty data
                info!("Creating new LanceDB table: {}", self.table_name);
                self.create_empty_table().await?
            }
        };

        *write_guard = Some(table.clone());
        Ok(table)
    }

    /// Validate that the table schema matches our expected schema
    async fn validate_schema(&self, table: &Table) -> bool {
        let table_schema = match table.schema().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to get LanceDB table schema: {}", e);
                return false;
            }
        };
        let expected_schema = self.get_schema();

        // Check if all expected fields are present in the table schema
        for field in expected_schema.fields() {
            if table_schema.field_with_name(field.name()).is_err() {
                warn!("LanceDB table is missing field: {}", field.name());
                return false;
            }
        }
        true
    }

    /// Create an empty table with the correct schema
    async fn create_empty_table(&self) -> Result<Table, AppError> {
        let schema = Arc::new(self.get_schema());

        // Create empty arrays for each column
        let id_array: ArrayRef = Arc::new(StringArray::from(Vec::<&str>::new()));
        let vector_array = self.create_empty_vector_array();
        let user_id_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let session_id_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let message_id_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let lorebook_id_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let original_lorebook_entry_id_array: ArrayRef =
            Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let chronicle_id_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let source_type_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let chunk_text_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let entry_title_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let speaker_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let keywords_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let is_enabled_array: ArrayRef =
            Arc::new(arrow::array::BooleanArray::from(Vec::<Option<bool>>::new()));
        let is_constant_array: ArrayRef =
            Arc::new(arrow::array::BooleanArray::from(Vec::<Option<bool>>::new()));
        let timestamp_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let encrypted_chunk_text_array: ArrayRef =
            Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let chunk_text_nonce_array: ArrayRef =
            Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let encrypted_title_array: ArrayRef =
            Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let title_nonce_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));
        let payload_json_array: ArrayRef = Arc::new(StringArray::from(Vec::<Option<&str>>::new()));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                id_array,
                vector_array,
                user_id_array,
                session_id_array,
                message_id_array,
                lorebook_id_array,
                original_lorebook_entry_id_array,
                chronicle_id_array,
                source_type_array,
                chunk_text_array,
                entry_title_array,
                speaker_array,
                keywords_array,
                is_enabled_array,
                is_constant_array,
                timestamp_array,
                encrypted_chunk_text_array,
                chunk_text_nonce_array,
                encrypted_title_array,
                title_nonce_array,
                payload_json_array,
            ],
        )
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Failed to create empty RecordBatch: {}",
                e
            ))
        })?;

        let batches = arrow::record_batch::RecordBatchIterator::new(
            vec![Ok(batch)],
            Arc::new(self.get_schema()),
        );

        let table = self
            .connection
            .create_table(&self.table_name, Box::new(batches))
            .execute()
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to create LanceDB table: {}", e))
            })?;

        Ok(table)
    }

    /// Create an empty vector array with the correct dimension
    fn create_empty_vector_array(&self) -> ArrayRef {
        let values = Float32Array::from(Vec::<f32>::new());
        let field = Arc::new(Field::new("item", DataType::Float32, false));
        Arc::new(
            FixedSizeListArray::try_new(
                field,
                self.embedding_dimension as i32,
                Arc::new(values),
                None,
            )
            .expect("Failed to create empty FixedSizeListArray"),
        )
    }

    /// Convert PointStruct vectors to Arrow RecordBatch
    fn points_to_record_batch(&self, points: &[PointStruct]) -> Result<RecordBatch, AppError> {
        if points.is_empty() {
            return Err(AppError::BadRequest(
                "Cannot create RecordBatch from empty points".to_string(),
            ));
        }

        let schema = Arc::new(self.get_schema());
        let num_points = points.len();

        // Extract data from points
        let mut ids: Vec<String> = Vec::with_capacity(num_points);
        let mut vectors: Vec<f32> = Vec::new();
        let mut user_ids: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut session_ids: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut message_ids: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut lorebook_ids: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut original_lorebook_entry_ids: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut chronicle_ids: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut source_types: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut chunk_texts: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut entry_titles: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut speakers: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut keywords_list: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut is_enabled_list: Vec<Option<bool>> = Vec::with_capacity(num_points);
        let mut is_constant_list: Vec<Option<bool>> = Vec::with_capacity(num_points);
        let mut timestamps: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut encrypted_chunk_texts: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut chunk_text_nonces: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut encrypted_titles: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut title_nonces: Vec<Option<String>> = Vec::with_capacity(num_points);
        let mut payload_jsons: Vec<Option<String>> = Vec::with_capacity(num_points);

        for point in points {
            // Extract ID
            let id = match &point.id {
                Some(id) => match &id.point_id_options {
                    Some(PointIdOptions::Uuid(uuid)) => uuid.clone(),
                    Some(PointIdOptions::Num(num)) => num.to_string(),
                    None => uuid::Uuid::new_v4().to_string(),
                },
                None => uuid::Uuid::new_v4().to_string(),
            };
            ids.push(id);

            // Extract vector and ensure it's the right dimension
            let mut vector = match &point.vectors {
                Some(vectors_struct) => {
                    use qdrant_client::qdrant::vectors::VectorsOptions;
                    match &vectors_struct.vectors_options {
                        Some(VectorsOptions::Vector(v)) => {
                            let data = v.data.clone();
                            if data.is_empty() {
                                error!("CRITICAL: Qdrant point has an empty Vector (VectorsOptions::Vector). Point ID: {:?}", point.id);
                            }
                            data
                        }
                        Some(VectorsOptions::Vectors(nv)) => {
                            error!("CRITICAL: Qdrant point has NamedVectors (VectorsOptions::Vectors), expected single Vector. Found keys: {:?}", nv.vectors.keys().collect::<Vec<_>>());
                            vec![0.0; self.embedding_dimension as usize]
                        }
                        None => {
                            error!("CRITICAL: Qdrant point has Vectors but VectorsOptions is None");
                            vec![0.0; self.embedding_dimension as usize]
                        }
                    }
                }
                None => {
                    error!("CRITICAL: Qdrant point has no vectors (None)");
                    vec![0.0; self.embedding_dimension as usize]
                }
            };

            // Check for NaN in the vector before storing
            if vector.iter().any(|&x| x.is_nan()) {
                error!(
                    "CRITICAL: Vector for point {:?} contains NaN values! Replacing with zeros.",
                    point.id
                );
                vector = vec![0.0; self.embedding_dimension as usize];
            }

            // Ensure vector has the correct dimension
            let expected_dim = self.embedding_dimension as usize;
            if vector.len() != expected_dim {
                error!(
                    "CRITICAL: Vector dimension mismatch: got {}, expected {}. Padding/truncating. Point ID: {:?}",
                    vector.len(),
                    expected_dim,
                    point.id
                );
                vector.resize(expected_dim, 0.0);
            }

            vectors.extend(vector);

            // Extract payload fields
            let payload = &point.payload;
            user_ids.push(Self::extract_string_from_payload(payload, "user_id"));
            session_ids.push(Self::extract_string_from_payload(payload, "session_id"));
            message_ids.push(Self::extract_string_from_payload(payload, "message_id"));
            lorebook_ids.push(Self::extract_string_from_payload(payload, "lorebook_id"));
            original_lorebook_entry_ids.push(Self::extract_string_from_payload(
                payload,
                "original_lorebook_entry_id",
            ));
            chronicle_ids.push(Self::extract_string_from_payload(payload, "chronicle_id"));
            source_types.push(Self::extract_string_from_payload(payload, "source_type"));
            chunk_texts.push(Self::extract_string_from_payload(payload, "chunk_text"));
            entry_titles.push(Self::extract_string_from_payload(payload, "entry_title"));
            speakers.push(Self::extract_string_from_payload(payload, "speaker"));
            keywords_list.push(Self::extract_string_from_payload(payload, "keywords"));
            encrypted_chunk_texts.push(Self::extract_string_from_payload(
                payload,
                "encrypted_chunk_text",
            ));
            chunk_text_nonces.push(Self::extract_string_from_payload(
                payload,
                "chunk_text_nonce",
            ));
            encrypted_titles.push(Self::extract_string_from_payload(
                payload,
                "encrypted_title",
            ));
            title_nonces.push(Self::extract_string_from_payload(payload, "title_nonce"));
            is_enabled_list.push(Self::extract_bool_from_payload(payload, "is_enabled"));
            is_constant_list.push(Self::extract_bool_from_payload(payload, "is_constant"));
            timestamps.push(Self::extract_string_from_payload(payload, "timestamp"));

            // Store full payload as JSON
            let payload_json = serde_json::to_string(payload).ok();
            payload_jsons.push(payload_json);
        }

        // Create Arrow arrays
        let id_array: ArrayRef = Arc::new(StringArray::from(ids));
        let vector_array = self.create_vector_array(&vectors, num_points)?;
        let user_id_array: ArrayRef = Arc::new(StringArray::from(user_ids));
        let session_id_array: ArrayRef = Arc::new(StringArray::from(session_ids));
        let message_id_array: ArrayRef = Arc::new(StringArray::from(message_ids));
        let lorebook_id_array: ArrayRef = Arc::new(StringArray::from(lorebook_ids));
        let original_lorebook_entry_id_array: ArrayRef =
            Arc::new(StringArray::from(original_lorebook_entry_ids));
        let chronicle_id_array: ArrayRef = Arc::new(StringArray::from(chronicle_ids));
        let source_type_array: ArrayRef = Arc::new(StringArray::from(source_types));
        let chunk_text_array: ArrayRef = Arc::new(StringArray::from(chunk_texts));
        let entry_title_array: ArrayRef = Arc::new(StringArray::from(entry_titles));
        let speaker_array: ArrayRef = Arc::new(StringArray::from(speakers));
        let keywords_array: ArrayRef = Arc::new(StringArray::from(keywords_list));
        let is_enabled_array: ArrayRef =
            Arc::new(arrow::array::BooleanArray::from(is_enabled_list));
        let is_constant_array: ArrayRef =
            Arc::new(arrow::array::BooleanArray::from(is_constant_list));
        let timestamp_array: ArrayRef = Arc::new(StringArray::from(timestamps));
        let encrypted_chunk_text_array: ArrayRef =
            Arc::new(StringArray::from(encrypted_chunk_texts));
        let chunk_text_nonce_array: ArrayRef = Arc::new(StringArray::from(chunk_text_nonces));
        let encrypted_title_array: ArrayRef = Arc::new(StringArray::from(encrypted_titles));
        let title_nonce_array: ArrayRef = Arc::new(StringArray::from(title_nonces));
        let payload_json_array: ArrayRef = Arc::new(StringArray::from(payload_jsons));

        RecordBatch::try_new(
            schema,
            vec![
                id_array,
                vector_array,
                user_id_array,
                session_id_array,
                message_id_array,
                lorebook_id_array,
                original_lorebook_entry_id_array,
                chronicle_id_array,
                source_type_array,
                chunk_text_array,
                entry_title_array,
                speaker_array,
                keywords_array,
                is_enabled_array,
                is_constant_array,
                timestamp_array,
                encrypted_chunk_text_array,
                chunk_text_nonce_array,
                encrypted_title_array,
                title_nonce_array,
                payload_json_array,
            ],
        )
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to create RecordBatch: {}", e))
        })
    }

    /// Create a FixedSizeList vector array from flat f32 data
    fn create_vector_array(
        &self,
        flat_data: &[f32],
        num_rows: usize,
    ) -> Result<ArrayRef, AppError> {
        let expected_len = num_rows * self.embedding_dimension as usize;

        // Validate that we have the correct amount of data
        if flat_data.len() != expected_len {
            error!(
                "Vector data length mismatch: got {} floats, expected {} ({}  rows × {} dims)",
                flat_data.len(),
                expected_len,
                num_rows,
                self.embedding_dimension
            );
            return Err(AppError::InternalServerErrorGeneric(format!(
                "Vector data length mismatch: {} vs expected {}",
                flat_data.len(),
                expected_len
            )));
        }

        let values = Float32Array::from(flat_data.to_vec());
        let field = Arc::new(Field::new("item", DataType::Float32, false));

        FixedSizeListArray::try_new(
            field,
            self.embedding_dimension as i32,
            Arc::new(values),
            None,
        )
        .map(|arr| Arc::new(arr) as ArrayRef)
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to create vector array: {}", e))
        })
    }

    /// Extract a string value from the Qdrant payload
    fn extract_string_from_payload(payload: &HashMap<String, Value>, key: &str) -> Option<String> {
        payload.get(key).and_then(|v| {
            v.kind.as_ref().and_then(|k| match k {
                Kind::StringValue(s) => Some(s.clone()),
                Kind::IntegerValue(i) => Some(i.to_string()),
                Kind::DoubleValue(d) => Some(d.to_string()),
                Kind::BoolValue(b) => Some(b.to_string()),
                _ => None,
            })
        })
    }

    /// Extract a boolean value from the Qdrant payload
    fn extract_bool_from_payload(payload: &HashMap<String, Value>, key: &str) -> Option<bool> {
        payload.get(key).and_then(|v| {
            v.kind.as_ref().and_then(|k| match k {
                Kind::BoolValue(b) => Some(*b),
                Kind::StringValue(s) => s.parse::<bool>().ok(),
                _ => None,
            })
        })
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

    /// Convert LanceDB result rows to Qdrant ScoredPoints
    fn rows_to_scored_points(
        &self,
        batch: &RecordBatch,
        distances: Option<&[f32]>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let mut results = Vec::new();
        let num_rows = batch.num_rows();

        // Get column arrays
        let id_array = batch
            .column_by_name("id")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());

        let payload_json_array = batch
            .column_by_name("payload_json")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());

        for i in 0..num_rows {
            // Extract ID
            let id = id_array
                .and_then(|a| a.value(i).parse::<uuid::Uuid>().ok())
                .map(|u| PointId {
                    point_id_options: Some(PointIdOptions::Uuid(u.to_string())),
                });

            // Extract payload from JSON
            let payload: HashMap<String, Value> = payload_json_array
                .and_then(|a| {
                    if a.is_null(i) {
                        None
                    } else {
                        serde_json::from_str(a.value(i)).ok()
                    }
                })
                .unwrap_or_default();

            // Calculate score from distance (cosine distance to cosine similarity)
            let distance = distances.and_then(|d| d.get(i)).copied();
            let score = distance
                .map(|d| 1.0 - d) // Cosine distance to similarity
                .unwrap_or(1.0);

            if score.is_nan() {
                error!(
                    point_id = ?id,
                    distance = ?distance,
                    "LanceDB result has NaN score! Skipping point."
                );
                continue;
            }

            results.push(ScoredPoint {
                id,
                payload,
                score,
                version: 0,
                vectors: None,
                shard_key: None,
                order_value: None,
            });
        }

        Ok(results)
    }
}

#[async_trait]
impl QdrantClientServiceTrait for LanceDbClient {
    #[instrument(skip(self), name = "lancedb_ensure_collection")]
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        // Getting table will create it if it doesn't exist
        self.get_table().await?;
        info!("LanceDB table '{}' is ready", self.table_name);
        Ok(())
    }

    #[instrument(skip(self, points), name = "lancedb_store_points", fields(point_count = points.len()))]
    async fn store_points(&self, points: Vec<PointStruct>) -> Result<(), AppError> {
        if points.is_empty() {
            debug!("No points to store, skipping");
            return Ok(());
        }

        let table = self.get_table().await?;
        let batch = self.points_to_record_batch(&points)?;

        let batches = arrow::record_batch::RecordBatchIterator::new(
            vec![Ok(batch)],
            Arc::new(self.get_schema()),
        );

        table
            .add(Box::new(batches))
            .execute()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to store points: {}", e)))?;

        debug!("Stored {} points in LanceDB", points.len());
        Ok(())
    }

    #[instrument(skip(self, vector), name = "lancedb_search_points")]
    async fn search_points(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        self.search_points_with_threshold(vector, limit, filter, None)
            .await
    }

    #[instrument(skip(self, vector), name = "lancedb_search_threshold")]
    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        if vector.iter().any(|&x| x.is_nan()) {
            error!("CRITICAL: Search vector contains NaN values!");
        }

        let magnitude = (vector.iter().map(|&x| x * x).sum::<f32>()).sqrt();
        if magnitude < 1e-6 {
            error!(
                "CRITICAL: Search vector has near-zero magnitude: {}!",
                magnitude
            );
        } else {
            debug!("Search vector magnitude: {}", magnitude);
        }

        let table = self.get_table().await?;

        let mut query = table
            .query()
            .nearest_to(vector)
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to create query: {}", e)))?
            .limit(limit as usize)
            .distance_type(lancedb::DistanceType::Cosine);

        // Apply filter if provided
        if let Some(f) = filter {
            let sql_filter = self.filter_to_sql(&f);
            if !sql_filter.is_empty() {
                info!("LanceDB search SQL filter: {}", sql_filter);
                query = query.only_if(sql_filter);
            }
        }

        let results = query
            .execute()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Search failed: {}", e)))?;

        // Collect results into batches
        use tokio_stream::StreamExt;
        let batches: Vec<RecordBatch> = results
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        let mut scored_points = Vec::new();
        for batch in batches {
            // Extract distances from the _distance column
            let distances: Option<Vec<f32>> = batch
                .column_by_name("_distance")
                .and_then(|c| c.as_any().downcast_ref::<Float32Array>())
                .map(|a| (0..a.len()).map(|i| a.value(i)).collect());

            let points = self.rows_to_scored_points(&batch, distances.as_deref())?;
            scored_points.extend(points);
        }

        // Apply score threshold if provided
        if let Some(threshold) = score_threshold {
            let initial_count = scored_points.len();

            // Sort by score descending for better logging of "what we almost found"
            scored_points.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            if initial_count > 0 {
                info!(
                    "Top 5 raw scores before threshold ({}): {:?}",
                    threshold,
                    scored_points
                        .iter()
                        .take(5)
                        .map(|p| format!("{:.3}", p.score))
                        .collect::<Vec<_>>()
                );
            }

            scored_points.retain(|p| p.score >= threshold);

            if scored_points.len() < initial_count {
                info!(
                    "Filtered out {} results below threshold {}",
                    initial_count - scored_points.len(),
                    threshold
                );
            }
        }

        info!("LanceDB search returned {} results", scored_points.len());
        Ok(scored_points)
    }

    #[instrument(skip(self, vector), name = "lancedb_hybrid_search")]
    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        text_query: Option<String>,
        text_fields: Vec<String>,
        limit: u64,
        filter: Option<Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // For now, implement hybrid search as vector search with text-based filter
        // TODO: Implement proper full-text search when LanceDB FTS is available

        if let Some(v) = vector {
            // Vector search with optional text filter
            let mut combined_filter = filter.unwrap_or_default();

            if let Some(text) = text_query.as_ref() {
                // Add text conditions to the filter
                for field in &text_fields {
                    combined_filter.should.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: field.clone(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Text(text.clone())),
                            }),
                            ..Default::default()
                        })),
                    });
                }
            }

            // Increase limit significantly to compensate for post-filtering
            // and ensure we find matches that might have low vector similarity
            let search_limit = (limit * 5).max(100);
            info!("Hybrid search using internal limit: {}", search_limit);

            // Call search without threshold first, so we can boost before thresholding
            self.search_points_with_threshold(v, search_limit, Some(combined_filter), None)
                .await
                .map(|mut points| {
                    let initial_count = points.len();

                    // If we have a text query, boost points that match it
                    if let Some(text) = text_query.as_ref() {
                        let text_lower = text.to_lowercase();
                        for point in &mut points {
                            let mut matched = false;
                            for field in &text_fields {
                                if let Some(val) = point.payload.get(field).and_then(|v| v.as_str())
                                {
                                    if val.to_lowercase().contains(&text_lower) {
                                        matched = true;
                                        break;
                                    }
                                }
                            }

                            if matched {
                                // Boost score for text matches to ensure they survive thresholds
                                // and appear higher in results
                                let old_score = point.score;
                                point.score = (point.score + 0.5).min(1.0);
                                info!(
                                    point_id = ?point.id,
                                    old_score = %old_score,
                                    new_score = %point.score,
                                    "Boosted score for text match in hybrid search"
                                );
                            }
                        }
                    }

                    // Re-sort after boosting
                    points.sort_by(|a, b| {
                        b.score
                            .partial_cmp(&a.score)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });

                    // Apply threshold after boosting
                    if let Some(threshold) = score_threshold {
                        if initial_count > 0 {
                            info!(
                                "Top 5 raw scores before threshold ({}): {:?}",
                                threshold,
                                points
                                    .iter()
                                    .take(5)
                                    .map(|p| format!("{:.3}", p.score))
                                    .collect::<Vec<_>>()
                            );
                        }

                        points.retain(|p| p.score >= threshold);

                        if points.len() < initial_count {
                            info!(
                                "Filtered out {} results below threshold {} after boosting",
                                initial_count - points.len(),
                                threshold
                            );
                        }
                    }

                    // Truncate to requested limit
                    points.truncate(limit as usize);
                    points
                })
        } else if text_query.is_some() {
            // Text-only search - retrieve with filter
            let mut combined_filter = filter.unwrap_or_default();

            if let Some(text) = text_query {
                for field in &text_fields {
                    combined_filter.should.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: field.clone(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Text(text.clone())),
                            }),
                            ..Default::default()
                        })),
                    });
                }
            }

            self.retrieve_points(Some(combined_filter), limit, None)
                .await
        } else {
            // No search criteria
            Ok(vec![])
        }
    }

    #[instrument(skip(self), name = "lancedb_retrieve_points")]
    async fn retrieve_points(
        &self,
        filter: Option<Filter>,
        limit: u64,
        offset: Option<u64>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let table = self.get_table().await?;

        let mut query = table.query();

        // Apply filter
        if let Some(f) = filter {
            let sql_filter = self.filter_to_sql(&f);
            if !sql_filter.is_empty() {
                query = query.only_if(sql_filter);
            }
        }

        query = query.limit(limit as usize);

        if let Some(off) = offset {
            query = query.offset(off as usize);
        }

        let results = query
            .execute()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Retrieve failed: {}", e)))?;

        use tokio_stream::StreamExt;
        let batches: Vec<RecordBatch> = results
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        let mut scored_points = Vec::new();
        for batch in batches {
            let points = self.rows_to_scored_points(&batch, None)?;
            scored_points.extend(points);
        }

        debug!("LanceDB retrieve returned {} results", scored_points.len());
        Ok(scored_points)
    }

    #[instrument(skip(self, point_ids), name = "lancedb_delete_points")]
    async fn delete_points(&self, point_ids: Vec<PointId>) -> Result<(), AppError> {
        if point_ids.is_empty() {
            return Ok(());
        }

        let table = self.get_table().await?;

        // Build deletion filter
        let id_strings: Vec<String> = point_ids
            .iter()
            .filter_map(|id| match &id.point_id_options {
                Some(PointIdOptions::Uuid(s)) => Some(format!("'{}'", self.escape_sql_string(s))),
                Some(PointIdOptions::Num(n)) => Some(format!("'{}'", n)),
                None => None,
            })
            .collect();

        if id_strings.is_empty() {
            return Ok(());
        }

        let delete_filter = format!("id IN ({})", id_strings.join(", "));

        table
            .delete(&delete_filter)
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Delete failed: {}", e)))?;

        debug!("Deleted {} points from LanceDB", point_ids.len());
        Ok(())
    }

    #[instrument(skip(self), name = "lancedb_delete_by_filter")]
    async fn delete_points_by_filter(&self, filter: Filter) -> Result<(), AppError> {
        self.delete_points_by_filter_from_collection(&self.table_name, filter)
            .await
    }

    async fn delete_points_from_collection(
        &self,
        collection_name: &str,
        points: Vec<PointId>,
    ) -> Result<(), AppError> {
        let table = self
            .connection
            .open_table(collection_name)
            .execute()
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!(
                    "Failed to open table {}: {}",
                    collection_name, e
                ))
            })?;

        // Convert PointIds to a format LanceDB can use for deletion
        // For now, we'll just use a filter with 'id IN (...)'
        let ids: Vec<String> = points
            .into_iter()
            .filter_map(|p| match p.point_id_options {
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(u)) => Some(u),
                _ => None,
            })
            .collect();

        if ids.is_empty() {
            return Ok(());
        }

        let sql_filter = format!(
            "id IN ({})",
            ids.iter()
                .map(|id| format!("'{}'", id))
                .collect::<Vec<_>>()
                .join(", ")
        );

        table
            .delete(&sql_filter)
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Delete by IDs failed: {}", e)))?;

        debug!(
            "Deleted points by IDs from LanceDB table {}",
            collection_name
        );
        Ok(())
    }

    async fn delete_points_by_filter_from_collection(
        &self,
        collection_name: &str,
        filter: Filter,
    ) -> Result<(), AppError> {
        let table = self
            .connection
            .open_table(collection_name)
            .execute()
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!(
                    "Failed to open table {}: {}",
                    collection_name, e
                ))
            })?;

        let sql_filter = self.filter_to_sql(&filter);

        if sql_filter.is_empty() {
            warn!("Empty filter for delete_points_by_filter_from_collection, skipping");
            return Ok(());
        }

        table
            .delete(&sql_filter)
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Delete by filter failed: {}", e)))?;

        debug!(
            "Deleted points matching filter from LanceDB table {}",
            collection_name
        );
        Ok(())
    }

    async fn update_collection_settings(&self) -> Result<(), AppError> {
        // LanceDB doesn't have the same collection settings concept as Qdrant
        debug!("LanceDbClient: update_collection_settings (no-op)");
        Ok(())
    }

    #[instrument(skip(self), name = "lancedb_get_point_by_id")]
    async fn get_point_by_id(
        &self,
        _point_id: PointId,
    ) -> Result<Option<qdrant_client::qdrant::RetrievedPoint>, AppError> {
        // LanceDB doesn't return RetrievedPoint directly - this would need conversion
        // For now, return None as this is rarely used
        debug!("LanceDbClient: get_point_by_id (returning None - not fully implemented)");
        Ok(None)
    }

    async fn optimize_collection(&self) -> Result<(), AppError> {
        debug!("LanceDbClient: optimize_collection (no-op)");
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        // Check that we can access the database
        self.get_table().await?;
        debug!("LanceDB health check passed");
        Ok(())
    }

    async fn store_points_to_collection(
        &self,
        collection_name: &str,
        points: Vec<PointStruct>,
    ) -> Result<(), AppError> {
        if points.is_empty() {
            return Ok(());
        }

        // In LanceDB, we treat collection_name as table_name
        let table = self
            .connection
            .open_table(collection_name)
            .execute()
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!(
                    "Failed to open table {}: {}",
                    collection_name, e
                ))
            })?;

        let batch = self.points_to_record_batch(&points)?;
        let batches = arrow::record_batch::RecordBatchIterator::new(
            vec![Ok(batch)],
            Arc::new(self.get_schema()),
        );

        table.add(Box::new(batches)).execute().await.map_err(|e| {
            AppError::DatabaseQueryError(format!(
                "Failed to store points to {}: {}",
                collection_name, e
            ))
        })?;

        Ok(())
    }

    async fn search_points_in_collection(
        &self,
        collection_name: &str,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        let table = self
            .connection
            .open_table(collection_name)
            .execute()
            .await
            .map_err(|e| {
                AppError::DatabaseQueryError(format!(
                    "Failed to open table {}: {}",
                    collection_name, e
                ))
            })?;

        let mut query = table
            .query()
            .nearest_to(vector)
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to create query: {}", e)))?
            .limit(limit as usize);

        if let Some(f) = filter {
            let sql_filter = self.filter_to_sql(&f);
            if !sql_filter.is_empty() {
                query = query.only_if(sql_filter);
            }
        }

        let results = query
            .execute()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Search failed: {}", e)))?;

        use futures::StreamExt;
        let batches: Vec<RecordBatch> = results
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to collect search results: {}", e))
            })?;

        let mut scored_points = Vec::new();
        for batch in batches {
            scored_points.extend(self.rows_to_scored_points(&batch, None)?);
        }

        Ok(scored_points)
    }

    async fn ensure_collection_exists_named(&self, collection_name: &str) -> Result<(), AppError> {
        // Check if table exists
        match self.connection.open_table(collection_name).execute().await {
            Ok(_) => Ok(()),
            Err(_) => {
                // Table doesn't exist, create it
                // This is a bit complex as create_empty_table uses self.table_name
                // I'll just use a simplified version here or refactor create_empty_table
                let schema = Arc::new(self.get_schema());
                let batches = arrow::record_batch::RecordBatchIterator::new(
                    vec![], // Empty
                    schema.clone(),
                );

                self.connection
                    .create_table(collection_name, Box::new(batches))
                    .execute()
                    .await
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!(
                            "Failed to create table {}: {}",
                            collection_name, e
                        ))
                    })?;
                Ok(())
            }
        }
    }
}

#[cfg(all(test, feature = "postgres-backend"))]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_column_name() {
        let client = LanceDbClient {
            connection: unsafe { std::mem::zeroed() }, // This is a unit test, we won't use connection
            table: Arc::new(RwLock::new(None)),
            table_name: "test".to_string(),
            embedding_dimension: 768,
        };

        assert_eq!(client.sanitize_column_name("user_id"), "user_id");
        assert_eq!(client.sanitize_column_name("metadata.user_id"), "user_id");
        assert_eq!(
            client.sanitize_column_name("'; DROP TABLE users;--"),
            "DROPTABLEusers"
        );
    }

    #[test]
    fn test_escape_sql_string() {
        let client = LanceDbClient {
            connection: unsafe { std::mem::zeroed() },
            table: Arc::new(RwLock::new(None)),
            table_name: "test".to_string(),
            embedding_dimension: 768,
        };

        assert_eq!(client.escape_sql_string("hello"), "hello");
        assert_eq!(client.escape_sql_string("it's"), "it''s");
        assert_eq!(
            client.escape_sql_string("'; DROP TABLE users;--"),
            "''; DROP TABLE users;--"
        );
    }

    #[test]
    fn test_create_vector_array_correct_dimension() {
        let client = LanceDbClient {
            connection: unsafe { std::mem::zeroed() },
            table: Arc::new(RwLock::new(None)),
            table_name: "test".to_string(),
            embedding_dimension: 4, // Small dimension for testing
        };

        // Correct data: 2 rows × 4 dimensions = 8 floats
        let flat_data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let result = client.create_vector_array(&flat_data, 2);
        assert!(result.is_ok(), "Should succeed with correct dimensions");

        let array = result.unwrap();
        assert_eq!(array.len(), 2, "Should have 2 rows");
    }

    #[test]
    fn test_create_vector_array_dimension_mismatch() {
        let client = LanceDbClient {
            connection: unsafe { std::mem::zeroed() },
            table: Arc::new(RwLock::new(None)),
            table_name: "test".to_string(),
            embedding_dimension: 4,
        };

        // Wrong data: 2 rows × 4 dimensions expected = 8 floats, but only 6 provided
        let flat_data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let result = client.create_vector_array(&flat_data, 2);
        assert!(result.is_err(), "Should fail with mismatched dimensions");

        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("length mismatch"),
            "Error should mention length mismatch"
        );
    }
}
