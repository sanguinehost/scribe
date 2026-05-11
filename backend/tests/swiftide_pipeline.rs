use std::sync::Arc;
use scribe_backend::db::connection::TursoClient;
use scribe_backend::services::pipeline::run_chronicle_pipeline;
use tempfile::tempdir;

#[tokio::test]
async fn test_swiftide_extract_embed_load() {
    // Setup a mock Turso source
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("test_pipeline.db");
    let path_str = path.to_str().expect("Invalid path");
    
    let client = Arc::new(TursoClient::new(path_str, None, None)
        .await
        .expect("Failed to create Turso client"));
    
    // Prepare the database with mock chronicle data
    let conn = client.connect().expect("Failed to connect");
    client.execute_safe(
        &conn,
        "CREATE TABLE chronicles (id TEXT PRIMARY KEY, content TEXT, created_at TEXT)",
        serde_json::json!({})
    ).await.expect("Failed to create table");
    
    client.execute_safe(
        &conn,
        "INSERT INTO chronicles (id, content, created_at) VALUES ('1', 'Test chronicle content', '2024-01-01T00:00:00Z')",
        serde_json::json!({})
    ).await.expect("Failed to insert data");

    // Run the pipeline in dry-run mode (local mock sink)
    let result = run_chronicle_pipeline(
        client,
        "mock-bucket".to_string(),
        "mock-table".to_string(),
        true, // is_dry_run
    ).await;

    assert!(result.is_ok(), "Pipeline should complete successfully in dry-run mode");
}
