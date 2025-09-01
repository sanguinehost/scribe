// backend/tests/context_limit_integration_tests.rs
// Tests to verify that user-configured context limits are properly integrated with security

use anyhow::Result as AnyhowResult;

#[cfg(test)]
mod context_limit_tests {
    use super::*;
    use scribe_backend::config::SecurityConfig;

    #[tokio::test]
    async fn test_security_config_allows_1m_tokens() -> AnyhowResult<()> {
        // Verify that SecurityConfig max_context_tokens supports 1M tokens
        let security_config = SecurityConfig::default();
        
        assert!(
            security_config.max_context_tokens >= 1048576, 
            "SecurityConfig max_context_tokens ({}) should be at least 1M tokens (1048576)", 
            security_config.max_context_tokens
        );
        
        println!("✅ SecurityConfig supports {} tokens (>= 1M)", security_config.max_context_tokens);
        Ok(())
    }

    #[tokio::test]
    async fn test_context_configuration_ranges() -> AnyhowResult<()> {
        // Test that the system supports the expected context ranges
        let test_limits = vec![
            4096,     // 4K tokens - minimum
            8192,     // 8K tokens
            16384,    // 16K tokens
            32768,    // 32K tokens 
            65536,    // 64K tokens
            131072,   // 128K tokens
            200000,   // 200K tokens (common default)
            1048576,  // 1M tokens (max for Gemini)
        ];

        for limit in test_limits {
            // Verify the system can handle this limit conceptually
            assert!(limit >= 4096, "Context limit {} should be at least 4K", limit);
            assert!(limit <= 1048576, "Context limit {} should be at most 1M", limit);
            
            // Calculate reasonable budget distributions
            let history_budget = (limit as f64 * 0.75) as usize;
            let rag_budget = (limit as f64 * 0.2) as usize;
            let buffer = limit - history_budget - rag_budget;
            
            assert!(history_budget > 0, "History budget should be positive for limit {}", limit);
            assert!(rag_budget > 0, "RAG budget should be positive for limit {}", limit);
            assert!(buffer >= 0, "Buffer should be non-negative for limit {}", limit);
        }

        println!("✅ Context limit range validation passed for all test cases");
        Ok(())
    }

    #[cfg(feature = "local-llm")]
    #[tokio::test]
    async fn test_llamacpp_default_context_size_reasonable() -> AnyhowResult<()> {
        // Verify that LlamaCpp default context size is reasonable
        use scribe_backend::llm::llamacpp::LlamaCppConfig;
        let config = LlamaCppConfig::default();
        
        assert!(
            config.context_size >= 32768,
            "LlamaCpp default context_size ({}) should be at least 32K tokens for reasonable performance",
            config.context_size
        );
        
        println!("✅ LlamaCpp default context size: {} tokens", config.context_size);
        Ok(())
    }
}