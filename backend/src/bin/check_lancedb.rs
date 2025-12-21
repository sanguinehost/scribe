
use scribe_backend::config::Config;
use scribe_backend::vector_db::LanceDbClient;
use scribe_backend::vector_db::qdrant_client::QdrantClientServiceTrait;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let config = Arc::new(Config::load()?);
    let client = LanceDbClient::new(config).await?;
    
    // Retrieve some points
    let points = client.retrieve_points(None, 100).await?;
    println!("Retrieved {} points from LanceDB", points.len());
    
    for (i, point) in points.iter().enumerate() {
        println!("Point {}: id={:?}, score={}", i, point.id, point.score);
        println!("  Payload: {:?}", point.payload);
    }
    
    Ok(())
}
