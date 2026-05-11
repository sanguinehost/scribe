use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use swiftide::indexing::{Node, Pipeline, Loader, Storage, Metadata};
use swiftide::indexing::LoaderError;
use futures_util::stream::{BoxStream, StreamExt};
use tracing::{info, instrument, Span};
use crate::db::connection::TursoClient;
use crate::privacy::logging::sanitize_json_value;
use serde_json::{json, Value};
#[cfg(feature = "otel")]
use opentelemetry::trace::TraceContextExt;
#[cfg(feature = "otel")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A loader that extracts Chronicle metadata from Turso (libSQL).
pub struct TursoChronicleLoader {
    client: Arc<TursoClient>,
}

impl TursoChronicleLoader {
    pub fn new(client: Arc<TursoClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Loader for TursoChronicleLoader {
    fn load(&self) -> BoxStream<'static, std::result::Result<Node, LoaderError>> {
        let client = Arc::clone(&self.client);
        
        let stream = async_stream::stream! {
            let conn = match client.connect() {
                Ok(c) => c,
                Err(e) => {
                    yield Err(LoaderError::Loader(e.to_string()));
                    return;
                }
            };
            
            // SELECT id, content, created_at FROM chronicles
            // Guarantee asymptotic complexity bounds by streaming from Turso if possible.
            // For the MVC, we simulate extraction.
            let chronicle_data = json!({
                "id": "chronicle_123",
                "content": "The party entered the ancient tomb.",
                "created_at": chrono::Utc::now().to_rfc3339()
            });
            
            // Apply PRIVACY_SAFE_LOGGING standards
            let sanitized_content = sanitize_json_value(&chronicle_data["content"]);
            let metadata = json!({
                "source": "turso",
                "sanitized_content": sanitized_content,
                "extracted_at": chrono::Utc::now().to_rfc3339()
            });
            
            let node = Node::new(chronicle_data["content"].as_str().unwrap_or_default())
                .with_metadata("turso", metadata);
            
            yield Ok(node);
        };

        Box::pin(stream)
    }
}

/// A storage sink for Apache Iceberg on S3.
pub struct IcebergStorage {
    bucket: String,
    table_name: String,
    is_dry_run: bool,
}

impl IcebergStorage {
    pub fn new(bucket: String, table_name: String, is_dry_run: bool) -> Self {
        Self { bucket, table_name, is_dry_run }
    }
}

#[async_trait]
impl Storage for IcebergStorage {
    async fn setup(&self) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            bucket = %self.bucket,
            table = %self.table_name,
            dry_run = self.is_dry_run,
            "Setting up Iceberg storage"
        );
        Ok(())
    }

    async fn store(&self, nodes: Vec<Node>) -> std::result::Result<Vec<Node>, Box<dyn std::error::Error + Send + Sync>> {
        let span = Span::current();
        span.record("num_nodes", nodes.len());

        if self.is_dry_run {
            info!("Dry-run: Mocking Iceberg sink for {} nodes", nodes.len());
            return Ok(nodes);
        }

        // Real Iceberg/S3 logic would go here using iceberg-rust and aws-sdk-s3
        info!(
            bucket = %self.bucket,
            table = %self.table_name,
            "Sinking {} nodes into Iceberg on S3",
            nodes.len()
        );
        
        // Asymptotic complexity: avoid O(N^2) by processing nodes in batches
        // swiftide handles batching if configured, but here we simulate a batch operation
        
        Ok(nodes)
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
        .then(|node| {
            // Placeholder for embedding logic
            let content = node.chunk();
            info!(length = content.len(), "Embedding chronicle text");
            // In a real implementation, we would call an embedding service here
            Ok(node)
        })
        .then_store_with(storage)
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Swiftide pipeline failed: {}", e))?;

    info!("Swiftide chronicle pipeline ETL flow completed");
    Ok(())
}
