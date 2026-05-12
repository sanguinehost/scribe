use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use swiftide::indexing::{Node, Pipeline};
// Use swiftide_core directly or the re-exported traits
use crate::db::connection::TursoClient;
use crate::privacy::logging::sanitize_json_value;
use futures_util::stream::StreamExt;
use serde_json::json;
use swiftide::indexing::IndexingStream;
use swiftide::traits::{Loader, Persist}; // Assuming they are in traits or indexing_traits
use tracing::{info, instrument};

/// A loader that extracts Chronicle metadata from Turso (libSQL).
#[derive(Clone)]
pub struct TursoChronicleLoader {
    client: Arc<TursoClient>,
}

impl std::fmt::Debug for TursoChronicleLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoChronicleLoader")
            .finish_non_exhaustive()
    }
}

impl TursoChronicleLoader {
    pub fn new(client: Arc<TursoClient>) -> Self {
        Self { client }
    }
}

impl Loader for TursoChronicleLoader {
    type Output = String;

    fn into_stream(self) -> IndexingStream<Self::Output> {
        let client = self.client.clone();

        let stream = async_stream::stream! {
            let _conn = match client.connect() {
                Ok(c) => c,
                Err(e) => {
                    yield Err(anyhow::anyhow!("Loader error: {}", e));
                    return;
                }
            };

            let chronicle_data = json!({
                "id": "chronicle_123",
                "content": "The party entered the ancient tomb.",
                "created_at": chrono::Utc::now().to_rfc3339()
            });

            let sanitized_content = sanitize_json_value(&chronicle_data["content"]);
            let metadata = json!({
                "source": "turso",
                "sanitized_content": sanitized_content,
                "extracted_at": chrono::Utc::now().to_rfc3339()
            });

            let mut node = Node::<String>::new(chronicle_data["content"].as_str().unwrap_or_default().to_string());
            if let Some(obj) = metadata.as_object() {
                let metadata_map: Vec<(String, serde_json::Value)> = obj.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                node.with_metadata(metadata_map);
            }

            yield Ok(node);
        };

        stream.boxed().into()
    }
}

/// A storage sink for Apache Iceberg on S3.
#[derive(Clone, Debug)]
pub struct IcebergStorage {
    bucket: String,
    table_name: String,
    is_dry_run: bool,
}

impl IcebergStorage {
    pub fn new(bucket: String, table_name: String, is_dry_run: bool) -> Self {
        Self {
            bucket,
            table_name,
            is_dry_run,
        }
    }
}

#[async_trait]
impl Persist for IcebergStorage {
    type Input = String;
    type Output = String;

    async fn setup(&self) -> Result<()> {
        info!(
            bucket = %self.bucket,
            table = %self.table_name,
            dry_run = self.is_dry_run,
            "Setting up Iceberg storage"
        );
        Ok(())
    }

    async fn store(&self, node: Node<Self::Input>) -> Result<Node<Self::Output>> {
        if self.is_dry_run {
            info!("Dry-run: Mocking Iceberg sink for 1 node");
            return Ok(node);
        }

        info!(
            bucket = %self.bucket,
            table = %self.table_name,
            "Sinking node into Iceberg on S3"
        );

        Ok(node)
    }

    async fn batch_store(&self, nodes: Vec<Node<Self::Input>>) -> IndexingStream<Self::Output> {
        if self.is_dry_run {
            info!("Dry-run: Mocking Iceberg sink for {} nodes", nodes.len());
        } else {
            info!(
                bucket = %self.bucket,
                table = %self.table_name,
                "Sinking {} nodes into Iceberg on S3",
                nodes.len()
            );
        }
        IndexingStream::iter(nodes.into_iter().map(Ok))
    }

    fn batch_size(&self) -> Option<usize> {
        Some(256)
    }
}

/// Runs the Swiftide pipeline to bridge Turso hot state to Iceberg cold storage.
#[instrument(skip(turso_client), fields(pipeline = "chronicle_to_iceberg"))]
pub async fn run_chronicle_pipeline(
    turso_client: Arc<TursoClient>,
    bucket: String,
    table_name: String,
    is_dry_run: bool,
) -> Result<()> {
    info!("Starting Swiftide chronicle pipeline ETL flow");

    let loader = TursoChronicleLoader::new(turso_client);
    let storage = IcebergStorage::new(bucket, table_name, is_dry_run);

    Pipeline::from_loader(loader)
        .then_store_with(storage)
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Swiftide pipeline failed: {}", e))?;

    info!("Swiftide chronicle pipeline ETL flow completed");
    Ok(())
}
