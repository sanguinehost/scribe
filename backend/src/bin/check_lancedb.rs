#[cfg(feature = "embedded-vector")]
use scribe_backend::config::Config;
#[cfg(feature = "embedded-vector")]
#[cfg(feature = "embedded-vector")]
use std::sync::Arc;

#[cfg(feature = "embedded-vector")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let config = Arc::new(Config::load()?);
    let embedding_model = scribe_backend::llm::UnifiedEmbeddingModel::Cloud(
        scribe_backend::llm::cloud_embedding_client::build_cloud_embedding_client(config.clone())?,
    );
    let client = scribe_backend::vector_db::create_vector_service(config, embedding_model).await?;

    // Retrieve some points
    let points = client.retrieve_points(None, 100, None, None).await?;
    println!("Retrieved {} points from LanceDB", points.len());

    for (i, point) in points.iter().enumerate() {
        println!("Point {}: id={:?}, score={}", i, point.id, point.score);
        println!("  Payload: {:?}", point.payload);
    }

    Ok(())
}

#[cfg(not(feature = "embedded-vector"))]
fn main() {
    println!("LanceDB check binary requires 'embedded-vector' feature.");
}
