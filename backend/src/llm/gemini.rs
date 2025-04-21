/// Sends a simple text prompt and gets a response.
pub async fn generate_simple_response(&self, prompt: &str) -> Result<String, AppError> {
    // --- Mocking Hook for Testing ---
    #[cfg(test)]
    {
        // Check if a mock response is set in the (hypothetical) shared test state
        // This requires passing the AppState or the mock field container somehow.
        // Simpler approach: Use an environment variable or a static mutex for tests.
        // Let's assume AppState access is feasible via context or modification.
        
        // If AppState had `mock_llm_response: Arc<Mutex<Option<String>>>`:
        // if let Some(mock_state_ref) = self.mock_state.as_ref() { // Assuming mock_state is passed during test setup
        //     let mut mock_guard = mock_state_ref.lock().await;
        //     if let Some(mock_resp) = mock_guard.take() {
        //         println!("--- Using Mock LLM Response ---"); 
        //         return Ok(mock_resp);
        //     }
        // }
        // Since direct AppState access isn't trivial here without bigger refactor,
        // let's rely on the test setting the mock response in the AppState 
        // *before* calling the endpoint that uses this client.
        // We'll add the check *inside* the endpoint handler instead.
        // This keeps the client itself clean.
        // The below is the original logic.
    }
    // --- End Mocking Hook ---
    
    let request_payload = json!({
        "contents": [{
            "prompt": prompt,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "n": self.n,
            "stop": self.stop,
            "presence_penalty": self.presence_penalty,
            "frequency_penalty": self.frequency_penalty,
            "best_of": self.best_of,
            "logit_bias": self.logit_bias,
            "user": self.user
        }],
        "model": self.model
    });

    let client = reqwest::Client::new();
    let response = client.post(&self.endpoint)
        .header("Authorization", format!("Bearer {}", self.api_key))
        .header("Content-Type", "application/json")
        .body(request_payload.to_string())
        .send()
        .await;

    match response {
        Ok(res) => {
            if res.status().is_success() {
                let text = res.text().await?;
                Ok(text)
            } else {
                Err(AppError::LlmError(format!("Request failed with status: {}", res.status())))
            }
        },
        Err(e) => Err(AppError::LlmError(format!("Failed to send request: {}", e))),
    }
} 