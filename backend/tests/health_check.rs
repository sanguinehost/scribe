//! Integration tests for the health check endpoint

// Helper function to spawn the app in the background
fn spawn_app() {
    // Run the server in a separate thread
    // TODO: Implement proper server spawning for tests
    // For now, assume the server is running externally
}

#[tokio::test]
async fn health_check_works() {
    // Arrange
    // spawn_app(); // TODO: Call this when implemented
    let client = reqwest::Client::new();
    let server_address = "http://127.0.0.1:3000"; // Match the address in main.rs

    // Act
    let response = client
        .get(&format!("{}/api/health", server_address))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    assert_eq!(Some(15), response.content_length()); // Check for `{"status":"ok"}` length

    let body_text = response.text().await.expect("Failed to read response body");
    // Optionally, parse the JSON and check the value
    let json: serde_json::Value = serde_json::from_str(&body_text).expect("Failed to parse JSON");
    assert_eq!(json["status"], "ok");
} 