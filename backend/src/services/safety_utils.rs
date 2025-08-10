// Safety settings utilities for consistent configuration across all AI services
// 
// Research findings (Aug 2025):
// - We use Google Gemini API v1beta (NOT Vertex AI)  
// - Vertex AI docs mention OFF for gemini-2.5+ models
// - Gemini API docs suggest BLOCK_NONE works for newer models
// - Since we use Gemini API, BLOCK_NONE is the correct choice
// - SillyTavern issue #3267 mentioned gemini-2.0 needing OFF, but that's for different API setup

use genai::chat::{HarmBlockThreshold, HarmCategory, SafetySetting};

/// Creates standard safety settings that disable all safety filters for roleplay content.
/// Uses BLOCK_NONE as appropriate for Gemini API (not Vertex AI).
/// 
/// This configuration allows legitimate creative writing and roleplay scenarios 
/// while relying on our jailbreak + prefill patterns for content control.
pub fn create_unrestricted_safety_settings() -> Vec<SafetySetting> {
    vec![
        SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
        SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
        SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
        SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
        SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
    ]
}

/// Creates safety settings with specified threshold for all categories.
/// Useful for testing different safety levels if needed.
pub fn create_safety_settings_with_threshold(threshold: HarmBlockThreshold) -> Vec<SafetySetting> {
    vec![
        SafetySetting::new(HarmCategory::Harassment, threshold.clone()),
        SafetySetting::new(HarmCategory::HateSpeech, threshold.clone()),
        SafetySetting::new(HarmCategory::SexuallyExplicit, threshold.clone()),
        SafetySetting::new(HarmCategory::DangerousContent, threshold.clone()),
        SafetySetting::new(HarmCategory::CivicIntegrity, threshold),
    ]
}

/// Gets the appropriate safety threshold based on model name.
/// Currently returns BLOCK_NONE for all models based on Gemini API documentation.
/// 
/// Note: If we experience safety filtering issues in production, this function
/// can be updated to use different thresholds for different model versions.
#[allow(unused)]
pub fn get_safety_threshold_for_model(model_name: &str) -> HarmBlockThreshold {
    // Research conclusion: Use BLOCK_NONE for Gemini API regardless of model version
    // This is based on Google Gemini API documentation (not Vertex AI docs)
    HarmBlockThreshold::BlockNone
    
    // Future consideration: If safety filtering becomes an issue, we could implement:
    // if model_name.starts_with("gemini-2.5") || model_name.starts_with("gemini-2.0") {
    //     HarmBlockThreshold::Off  // If we determine OFF is actually needed
    // } else {
    //     HarmBlockThreshold::BlockNone
    // }
}