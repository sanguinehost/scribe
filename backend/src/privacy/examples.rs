/// Examples showing how to transform logging to use privacy-safe patterns
///
/// This file demonstrates the before/after of updating logging statements
/// to protect user privacy while maintaining debuggability.
use crate::privacy::logging::{
    loggable_session_id, loggable_user_id, sanitize_content, sanitize_system_prompt,
};
use crate::{privacy_debug, privacy_error, privacy_info, privacy_warn};
use uuid::Uuid;

/// Example 1: AI Client Factory logging transformation
pub mod ai_client_factory_example {
    use super::*;

    pub fn demonstrate_user_logging_transformation() {
        let user_id = Uuid::new_v4();

        // BEFORE: Logs actual user ID
        // warn!(%user_id, error = ?e, "Failed to get user settings, using fallback client");

        // AFTER: Logs obfuscated user ID
        privacy_warn!(
            user_id = %loggable_user_id(user_id),
            error = "connection_timeout", // Sanitized error message
            "Failed to get user settings, using fallback client"
        );

        // BEFORE: Logs actual user ID
        // info!(%user_id, "Created local LLM client for user");

        // AFTER: Privacy-safe logging
        privacy_info!(
            user_id = %loggable_user_id(user_id),
            "Created local LLM client for user"
        );
    }
}

/// Example 2: Chat generation logging transformation  
pub mod chat_generation_example {
    use super::*;

    pub fn demonstrate_chat_logging_transformation() {
        let session_id = Uuid::new_v4();
        let user_content = "Tell me about quantum physics";
        let system_prompt = "You are a helpful AI assistant...";

        // BEFORE: Logs actual session ID and content
        // debug!(%session_id, content_length = content.len(), "Processing chat request");

        // AFTER: Privacy-safe session logging
        privacy_debug!(
            session_id = %loggable_session_id(session_id),
            content = %sanitize_content(user_content),
            "Processing chat request"
        );

        // BEFORE: System prompt exposure
        // debug!("System prompt: {}", system_prompt);

        // AFTER: Redacted system prompt
        privacy_debug!(
            system_prompt = %sanitize_system_prompt(system_prompt),
            "Using system prompt for chat generation"
        );
    }
}

/// Example 3: Admin routes logging transformation
pub mod admin_routes_example {
    use super::*;

    pub fn demonstrate_admin_logging_transformation() {
        let user_id = Uuid::new_v4();
        let admin_user_id = Uuid::new_v4();
        let username = "john.doe";

        // BEFORE: Logs actual user IDs and username
        // debug!(user_id = %user_id, username = %username, "User has Administrator role, access granted");

        // AFTER: Privacy-safe admin logging
        privacy_debug!(
            user_id = %loggable_user_id(user_id),
            username = "<username-redacted>", // Always redact usernames
            "User has Administrator role, access granted"
        );

        // BEFORE: Logs actual user IDs
        // info!(user_id = %admin_user_id, target_user_id = %user_id, "Admin locking user account");

        // AFTER: Both IDs obfuscated
        privacy_info!(
            admin_user_id = %loggable_user_id(admin_user_id),
            target_user_id = %loggable_user_id(user_id),
            "Admin locking user account"
        );
    }
}

/// Example 4: Request correlation with privacy
pub mod request_correlation_example {
    use super::*;
    use crate::privacy::PrivacyContext;

    pub fn demonstrate_request_correlation() {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        // Create privacy context for request
        let privacy_ctx = PrivacyContext::new(crate::privacy::PrivacyConfig::default());

        // BEFORE: No correlation, actual IDs logged
        // info!("Processing request for user {}", user_id);
        // debug!("Session {} processing message", session_id);

        // AFTER: Request correlation with privacy
        privacy_info!(
            request_id = %privacy_ctx.request_id(),
            user_id = %privacy_ctx.obfuscate_user_id(user_id),
            "Processing request for user"
        );

        privacy_debug!(
            request_id = %privacy_ctx.request_id(),
            session_id = %privacy_ctx.obfuscate_session_id(session_id),
            "Session processing message"
        );
    }
}

/// Example 5: Error handling with privacy
pub mod error_handling_example {
    use super::*;

    pub fn demonstrate_error_logging_transformation() {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        // BEFORE: Potentially exposes user data in error messages
        // error!(
        //     %user_id,
        //     %session_id,
        //     error = ?e,
        //     "Database query failed: {}",
        //     e.to_string()
        // );

        // AFTER: Privacy-safe error logging
        privacy_error!(
            user_id = %loggable_user_id(user_id),
            session_id = %loggable_session_id(session_id),
            error_type = "database_query_failed",
            error_code = "PG_CONNECTION_TIMEOUT", // Sanitized error details
            "Database query failed"
        );
    }
}

/// Example 6: Authentication logging
pub mod auth_example {
    use super::*;

    pub fn demonstrate_auth_logging_transformation() {
        let user_id = Uuid::new_v4();
        let email = "user@example.com";
        let ip_address = "192.168.1.100";

        // BEFORE: Logs email and IP directly
        // info!(user_id = %user_id, email = %email, ip = %ip_address, "User login successful");

        // AFTER: Privacy-safe authentication logging
        privacy_info!(
            user_id = %loggable_user_id(user_id),
            email = "<email-redacted>",
            ip = "<ip-redacted>", // IP addresses are PII
            login_success = true,
            "User authentication completed"
        );

        // For security events, we might keep more detail in a separate audit log
        // but the operational logs should be privacy-safe
    }
}

/// Shows the transformation pattern for the most common logging scenarios
pub fn show_transformation_patterns() {
    println!("=== Privacy-Safe Logging Transformation Examples ===\n");

    println!("1. User ID Logging:");
    println!("   BEFORE: info!(%user_id, \"Processing request\");");
    println!(
        "   AFTER:  privacy_info!(user_id = %loggable_user_id(user_id), \"Processing request\");\n"
    );

    println!("2. Session ID Logging:");
    println!("   BEFORE: debug!(%session_id, \"Session started\");");
    println!(
        "   AFTER:  privacy_debug!(session_id = %loggable_session_id(session_id), \"Session started\");\n"
    );

    println!("3. Content Logging:");
    println!("   BEFORE: debug!(\"User message: {{}}\", content);");
    println!(
        "   AFTER:  privacy_debug!(content = %sanitize_content(content), \"User message received\");\n"
    );

    println!("4. System Prompt Logging:");
    println!("   BEFORE: debug!(\"System prompt: {{}}\", prompt);");
    println!(
        "   AFTER:  privacy_debug!(system_prompt = %sanitize_system_prompt(prompt), \"Using system prompt\");\n"
    );

    println!("5. Personal Info Logging:");
    println!("   BEFORE: info!(email = %email, username = %username, \"User registered\");");
    println!(
        "   AFTER:  privacy_info!(email = \"<email-redacted>\", username = \"<username-redacted>\", \"User registered\");\n"
    );

    println!("6. Error Logging:");
    println!("   BEFORE: error!(error = ?e, \"Database error: {{}}\", e);");
    println!(
        "   AFTER:  privacy_error!(error_type = \"database_connection\", \"Database operation failed\");\n"
    );
}

/// Demonstrates output format differences
pub fn demonstrate_log_output_differences() {
    let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let session_id = Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();

    println!("=== Log Output Format Comparison ===\n");

    println!("BEFORE (Privacy Risk):");
    println!("INFO  Processing request [user_id=550e8400-e29b-41d4-a716-446655440000]");
    println!("DEBUG Session started [session_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8]");
    println!("DEBUG User message: 'Tell me about my account balance'");
    println!(
        "ERROR Database query failed: Connection timeout for user 550e8400-e29b-41d4-a716-446655440000\n"
    );

    println!("AFTER (Privacy Protected):");
    println!("INFO  Processing request [request_id=a1b2c3d4, user_id=user#7f2e8a91bc4d]");
    println!("DEBUG Session started [request_id=a1b2c3d4, session_id=session#9k4p2x7m]");
    println!(
        "DEBUG User message received [request_id=a1b2c3d4, content=<content-redacted:33-chars>]"
    );
    println!(
        "ERROR Database operation failed [request_id=a1b2c3d4, user_id=user#7f2e8a91bc4d, error_type=connection_timeout]"
    );

    println!("\nKey Improvements:");
    println!("✓ User IDs are one-way hashed (irreversible)");
    println!("✓ Content is redacted but length preserved for debugging");
    println!("✓ Request correlation ID enables tracing without exposing user data");
    println!("✓ Structured error types replace sensitive error messages");
    println!("✓ All logs can be safely stored and analyzed without privacy concerns");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_obfuscation_consistency() {
        let user_id = Uuid::new_v4();
        let loggable1 = loggable_user_id(user_id);
        let loggable2 = loggable_user_id(user_id);

        // Same UUID should produce same obfuscated output
        assert_eq!(loggable1.to_string(), loggable2.to_string());

        // Should not contain the original UUID
        assert!(!loggable1.to_string().contains(&user_id.to_string()));

        // Should be prefixed correctly
        assert!(loggable1.to_string().starts_with("user#"));
    }

    #[test]
    fn test_content_redaction() {
        let sensitive_content = "My credit card number is 4532-1234-5678-9012";
        let sanitized = sanitize_content(sensitive_content);

        // Should show redacted message with length
        let output = sanitized.to_string();
        assert!(output.contains("<content-redacted:"));
        assert!(output.contains("-chars>"));
        assert!(!output.contains("4532-1234-5678-9012"));

        // Original content should be accessible for business logic
        assert_eq!(sanitized.expose(), sensitive_content);
    }

    #[test]
    fn test_different_ids_produce_different_hashes() {
        let user_id1 = Uuid::new_v4();
        let user_id2 = Uuid::new_v4();

        let loggable1 = loggable_user_id(user_id1);
        let loggable2 = loggable_user_id(user_id2);

        // Different UUIDs should produce different outputs
        assert_ne!(loggable1.to_string(), loggable2.to_string());
    }
}
