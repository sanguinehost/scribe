use dotenvy::dotenv;
use scribe_backend::services::gemini_token_client::GeminiTokenClient;
use scribe_backend::services::hybrid_token_counter::{CountingMode, HybridTokenCounter};
use scribe_backend::services::tokenizer_service::TokenizerService;
use std::path::PathBuf;

#[tokio::test]
async fn test_hybrid_token_counter_local() {
    // Helper function to convert duration to token count safely
    fn duration_to_tokens(duration: f64, tokens_per_second: f64) -> usize {
        let total_tokens = duration * tokens_per_second;
        if total_tokens >= 0.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let tokens_u64 = total_tokens.round() as u64;
            usize::try_from(tokens_u64).unwrap_or(0)
        } else {
            0
        }
    }

    // Initialize the tokenizer service
    let model_path = PathBuf::from(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    );
    let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

    // Create a hybrid counter with local-only mode
    let counter = HybridTokenCounter::new_local_only(tokenizer);

    // Test text token counting
    let text = "This is a test of the hybrid token counter.";
    let token_count = counter
        .count_tokens(text, CountingMode::LocalOnly, None)
        .await
        .expect("Failed to count tokens");

    println!("Text token count: {}", token_count.total);
    assert!(token_count.total > 0);

    // Test chat token counting
    let messages = vec![
        ("user".to_string(), "Hello, how are you?".to_string()),
        (
            "model".to_string(),
            "I'm doing well, thank you for asking!".to_string(),
        ),
        (
            "user".to_string(),
            "Tell me about token counting.".to_string(),
        ),
    ];

    let chat_token_count = counter
        .count_tokens_chat(&messages, CountingMode::LocalOnly, None)
        .await
        .expect("Failed to count chat tokens");

    println!("Chat token count: {}", chat_token_count.total);
    assert!(chat_token_count.total > 0);
    assert!(chat_token_count.total > token_count.total);

    // Test multimodal token counting
    let video_duration = 5.0; // 5 seconds of video
    let audio_duration = 10.0; // 10 seconds of audio

    let multimodal_token_count = counter
        .count_tokens_multimodal(
            text,
            None, // No images
            Some(video_duration),
            Some(audio_duration),
            CountingMode::LocalOnly,
            None,
        )
        .await
        .expect("Failed to count multimodal tokens");

    println!("Multimodal token count breakdown:");
    println!("  Text: {} tokens", multimodal_token_count.text);
    println!("  Video: {} tokens", multimodal_token_count.video);
    println!("  Audio: {} tokens", multimodal_token_count.audio);
    println!("  Total: {} tokens", multimodal_token_count.total);

    // Verify text token count matches the earlier test
    assert_eq!(multimodal_token_count.text, token_count.text);

    // Verify video token count (263 tokens per second)
    assert_eq!(
        multimodal_token_count.video,
        duration_to_tokens(video_duration, 263.0)
    );

    // Verify audio token count (32 tokens per second)
    assert_eq!(
        multimodal_token_count.audio,
        duration_to_tokens(audio_duration, 32.0)
    );

    // Verify total = text + video + audio
    assert_eq!(
        multimodal_token_count.total,
        multimodal_token_count.text + multimodal_token_count.video + multimodal_token_count.audio
    );
}

// This test requires an API key and is ignored by default
// To run it: cargo test --test token_counter_tests test_hybrid_token_counter_api -- --ignored
#[tokio::test]
#[ignore]
async fn test_hybrid_token_counter_api() {
    // Load .env file
    dotenv().ok();

    // Get API key from environment
    let Ok(api_key) = std::env::var("GEMINI_API_KEY") else {
        println!("Skipping API test: GEMINI_API_KEY environment variable not set");
        return;
    };

    // Initialize the tokenizer service
    let model_path = PathBuf::from(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    );
    let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

    // Create API client
    let api_client = GeminiTokenClient::new(api_key);

    // Create a hybrid counter
    let counter = HybridTokenCounter::new(
        tokenizer,
        Some(api_client),
        "gemini-2.5-flash-preview-04-17".to_string(),
    );

    // Test different text samples with API vs local counting
    let test_texts = vec![
        (
            "The quick brown fox jumps over the lazy dog.",
            "Simple English sentence",
        ),
        (
            "This is a longer text sample that contains multiple sentences. It has punctuation, numbers like 1234, and should test the tokenizer more thoroughly. How well does it handle this?",
            "Longer English text",
        ),
        ("特殊字符和多语言支持测试。", "Chinese text"),
        ("1234567890!@#$%^&*()", "Numbers and symbols"),
    ];

    println!("\n=== TOKEN COUNT COMPARISON (API vs LOCAL) ===\n");

    for (text, description) in &test_texts {
        println!("\nTest case: {description}");

        // Local counting
        let local_count = counter
            .count_tokens(text, CountingMode::LocalOnly, None)
            .await
            .expect("Failed to count tokens locally");

        // API counting
        let api_count = counter
            .count_tokens(text, CountingMode::ApiOnly, None)
            .await
            .expect("Failed to count tokens with API");

        // Hybrid counting (prefer API)
        let hybrid_count = counter
            .count_tokens(text, CountingMode::HybridPreferApi, None)
            .await
            .expect("Failed to count tokens with hybrid approach");

        // Print the difference percentage
        let difference_percent = ((f64::from(u32::try_from(api_count.total).unwrap_or(u32::MAX)) - f64::from(u32::try_from(local_count.total).unwrap_or(u32::MAX))).abs()
            / f64::from(u32::try_from(local_count.total).unwrap_or(u32::MAX)))
            * 100.0;

        println!("Text: '{}' (length: {} chars)", text, text.len());
        println!("- API count: {} tokens", api_count.total);
        println!("- Local count: {} tokens", local_count.total);
        println!("- Hybrid count: {} tokens", hybrid_count.total);
        println!("- Difference: {difference_percent:.2}%");
        println!(
            "- Tokens per character (API): {:.2}",
            f64::from(u32::try_from(api_count.total).unwrap_or(u32::MAX)) / f64::from(u32::try_from(text.len()).unwrap_or(u32::MAX))
        );
        println!(
            "- Tokens per character (Local): {:.2}",
            f64::from(u32::try_from(local_count.total).unwrap_or(u32::MAX)) / f64::from(u32::try_from(text.len()).unwrap_or(u32::MAX))
        );

        // All methods should return non-zero counts
        assert!(local_count.total > 0);
        assert!(api_count.total > 0);
        assert!(hybrid_count.total > 0);
    }

    // Test chat token counting with API
    let messages = vec![
        ("user".to_string(), "Hello, how are you?".to_string()),
        (
            "model".to_string(),
            "I'm doing well, thank you for asking!".to_string(),
        ),
        (
            "user".to_string(),
            "Tell me about token counting.".to_string(),
        ),
    ];

    let chat_token_count = counter
        .count_tokens_chat(&messages, CountingMode::HybridPreferApi, None)
        .await
        .expect("Failed to count chat tokens");

    println!("Chat token count (API): {}", chat_token_count.total);
    assert!(chat_token_count.total > 0);
}
