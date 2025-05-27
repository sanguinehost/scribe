use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct SillyTavernLorebookFile {
    pub entries: HashMap<String, SillyTavernEntry>,
}

#[derive(Debug, Deserialize, Clone, Default)] // Added Default
#[serde(rename_all = "camelCase")]
pub struct SillyTavernEntry {
    #[serde(default)] // Add default for robustness
    pub uid: Option<i64>,
    #[serde(default)]
    pub key: Vec<String>, // Changed to Vec<String> and default
    #[serde(alias = "keysecondary", default)]
    pub key_secondary: Vec<String>, // Changed to Vec<String> and default
    #[serde(default)]
    pub comment: Option<String>,
    pub content: String,
    #[serde(default)]
    pub constant: Option<bool>,
    #[serde(default)]
    pub selective: Option<bool>, // Though not directly used, good to capture
    #[serde(default)]
    pub order: Option<i32>,
    #[serde(default)]
    pub disable: Option<bool>,
    // Other fields from SillyTavern format can be added here if needed for more complex logic
    // For now, focusing on fields that map to CreateLorebookEntryPayload
    // SillyTavern's "disable" field maps to "is_enabled" (inverted)
    // SillyTavern's "order" maps to "insertion_order"
    // SillyTavern's "key" + "keySecondary" can be combined for "keys_text"
    // SillyTavern's "comment" maps to "comment"
    // SillyTavern's "content" maps to "content"
    // SillyTavern's "constant" maps to "is_constant"
    // placement_hint is not in this ST format, will default in CreateLorebookEntryPayload
}
