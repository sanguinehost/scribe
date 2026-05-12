// Safety settings utilities for consistent configuration across all AI services
// Rig handles safety settings through provider-specific configurations.

/// Creates standard safety settings that disable all safety filters for roleplay content.
/// Returns a vector of JSON values that can be passed to Rig's additional_params.
pub fn create_unrestricted_safety_settings() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "category": "HARM_CATEGORY_HARASSMENT",
            "threshold": "BLOCK_NONE"
        }),
        serde_json::json!({
            "category": "HARM_CATEGORY_HATE_SPEECH",
            "threshold": "BLOCK_NONE"
        }),
        serde_json::json!({
            "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
            "threshold": "BLOCK_NONE"
        }),
        serde_json::json!({
            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
            "threshold": "BLOCK_NONE"
        }),
        serde_json::json!({
            "category": "HARM_CATEGORY_CIVIC_INTEGRITY",
            "threshold": "BLOCK_NONE"
        }),
    ]
}
