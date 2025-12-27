use crate::errors::AppError;
use minijinja::Environment;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Narrative style variables for template customization
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tense {
    PastTense,
    PresentTense,
    FutureTense,
}

impl Default for Tense {
    fn default() -> Self {
        Self::PastTense
    }
}

impl Tense {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PastTense => "past-tense",
            Self::PresentTense => "present-tense",
            Self::FutureTense => "future-tense",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Narration {
    FirstPerson,
    SecondPerson,
    ThirdPerson,
}

impl Default for Narration {
    fn default() -> Self {
        Self::ThirdPerson
    }
}

impl Narration {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstPerson => "first-person",
            Self::SecondPerson => "second-person",
            Self::ThirdPerson => "third-person",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Perspective {
    Omniscient,
    LimitedCharacter,
    LimitedUser,
}

impl Default for Perspective {
    fn default() -> Self {
        Self::Omniscient
    }
}

impl Perspective {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Omniscient => "omniscient narration",
            Self::LimitedCharacter => "limited narration from the character's perspective",
            Self::LimitedUser => "limited narration from the user's perspective",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseLength {
    Flexible,
    Concise,
    Moderate,
    Extended,
}

impl Default for ResponseLength {
    fn default() -> Self {
        Self::Flexible
    }
}

impl ResponseLength {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Flexible => {
                "flexible, varying based on the scene (concise during dialogue/action, detailed during transitions/descriptions)"
            }
            Self::Concise => "concise (under 150 words)",
            Self::Moderate => "moderate (150-300 words)",
            Self::Extended => "extended (300+ words)",
        }
    }
}

/// Narrative style variables that can be customized per user/character
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NarrativeStyle {
    #[serde(default)]
    pub tense: Tense,
    #[serde(default)]
    pub narration: Narration,
    #[serde(default)]
    pub perspective: Perspective,
    #[serde(default)]
    pub length: ResponseLength,
}

impl Default for NarrativeStyle {
    fn default() -> Self {
        Self {
            tense: Tense::default(),
            narration: Narration::default(),
            perspective: Perspective::default(),
            length: ResponseLength::default(),
        }
    }
}

/// Template compatibility requirements
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TemplateCompatibility {
    pub requires_character: bool,
    pub supports_rag: bool,
    pub supports_personas: bool,
}

/// A prompt template definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptTemplate {
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub compatibility: TemplateCompatibility,
    pub sections: HashMap<String, String>,
}

/// Information about a template (for API responses)
#[derive(Debug, Clone, Serialize)]
pub struct TemplateInfo {
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub compatibility: TemplateCompatibility,
}

impl From<&PromptTemplate> for TemplateInfo {
    fn from(template: &PromptTemplate) -> Self {
        Self {
            id: template.id.clone(),
            version: template.version.clone(),
            name: template.name.clone(),
            description: template.description.clone(),
            compatibility: template.compatibility.clone(),
        }
    }
}

/// Template manager that handles loading, caching, and rendering templates
pub struct TemplateManager {
    env: Environment<'static>,
    templates: HashMap<String, PromptTemplate>,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new() -> Self {
        Self {
            env: Environment::new(),
            templates: HashMap::new(),
        }
    }

    /// Load embedded default templates
    fn load_embedded_templates(&mut self) {
        let embedded_templates = [
            (
                "neutral_roleplay",
                include_str!("../data/prompt_templates/neutral_roleplay.json"),
            ),
            (
                "chatbot_dialogue",
                include_str!("../data/prompt_templates/chatbot_dialogue.json"),
            ),
            (
                "creative_narrative",
                include_str!("../data/prompt_templates/creative_narrative.json"),
            ),
        ];

        for (template_id, template_json) in embedded_templates {
            if let Err(e) = self.load_template_from_string(template_json) {
                error!(template_id, error = %e, "Failed to load embedded template");
            } else {
                debug!(template_id, "Loaded embedded template");
            }
        }
    }

    /// Load templates from files (overrides embedded ones)
    fn load_file_templates(&mut self) {
        let templates_dir = std::path::Path::new("data/prompt_templates");

        if !templates_dir.exists() {
            debug!("No prompt_templates directory found, using embedded defaults only");
            return;
        }

        match std::fs::read_dir(templates_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if let Some(extension) = entry.path().extension() {
                        if extension == "json" {
                            match std::fs::read_to_string(&entry.path()) {
                                Ok(content) => {
                                    if let Err(e) = self.load_template_from_string(&content) {
                                        error!(file = ?entry.path(), error = %e, "Failed to load template from file");
                                    } else {
                                        info!(file = ?entry.path(), "Loaded template from file");
                                    }
                                }
                                Err(e) => {
                                    error!(file = ?entry.path(), error = %e, "Failed to read template file");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to read templates directory");
            }
        }
    }

    /// Reload all templates (embedded + files)
    pub fn reload(&mut self) {
        info!("Reloading prompt templates...");
        // Reset environment and templates
        self.env = Environment::new();
        self.templates.clear();

        // Re-load everything
        self.load_embedded_templates();
        self.load_file_templates();

        info!(
            template_count = self.templates.len(),
            templates = ?self.templates.keys().collect::<Vec<_>>(),
            "Template manager reloaded"
        );
    }

    /// Load a template from a JSON string
    pub fn load_template_from_string(&mut self, content: &str) -> Result<(), AppError> {
        let template: PromptTemplate = serde_json::from_str(content)
            .map_err(|e| AppError::BadRequest(format!("Invalid template JSON: {}", e)))?;

        // Validate template has required sections
        if !template.sections.contains_key("main") {
            return Err(AppError::BadRequest(
                "Template must have a 'main' section".to_string(),
            ));
        }

        // Add all sections to minijinja environment
        for (section_name, section_content) in &template.sections {
            let template_key = format!("{}/{}", template.id, section_name);

            self.env
                .add_template_owned(template_key, section_content.clone())
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!(
                        "Failed to add template section: {}",
                        e
                    ))
                })?;
        }

        debug!(template_id = %template.id, version = %template.version, "Added template");
        self.templates.insert(template.id.clone(), template);
        Ok(())
    }

    /// Check if a template exists
    pub fn has_template(&self, template_id: &str) -> bool {
        self.templates.contains_key(template_id)
    }

    /// Get template info for a specific template
    pub fn get_template_info(&self, template_id: &str) -> Option<TemplateInfo> {
        self.templates.get(template_id).map(TemplateInfo::from)
    }

    /// List all available templates
    pub fn list_templates(&self) -> Vec<TemplateInfo> {
        self.templates.values().map(TemplateInfo::from).collect()
    }

    /// Sanitizes context values to prevent template injection attacks
    /// Skips sanitization for the 'self' key which contains template sections
    fn sanitize_context(&self, value: crate::DbJson, skip_keys: &[&str]) -> crate::DbJson {
        let value_inner = value.0.clone();
        match &value_inner {
            serde_json::Value::String(s) => {
                // Remove or escape potentially dangerous template injection patterns
                let sanitized = s
                    .replace("{%", "{ %") // Escape Jinja control structures
                    .replace("{{", "{ {") // Escape Jinja expressions
                    .replace("%}", "% }") // Escape closing control structures
                    .replace("}}", "} }") // Escape closing expressions
                    .replace("#!", "# !") // Escape shebang attempts
                    .chars()
                    .filter(|&c| {
                        c.is_ascii()
                            || c.is_alphanumeric()
                            || " \t\n\r!@#$%^&*()-_+=[]{}|\\:;\"'<>,.?/~`".contains(c)
                    })
                    .collect::<String>();

                // Limit length to prevent memory exhaustion
                if sanitized.len() > 200000 {
                    crate::db::Json(serde_json::Value::String(format!(
                        "{}...[truncated]",
                        &sanitized[..200000]
                    )))
                } else {
                    crate::db::Json(serde_json::Value::String(sanitized))
                }
            }
            serde_json::Value::Array(arr) => {
                crate::db::Json(serde_json::Value::Array(
                    arr.iter()
                        .take(500) // Limit array size
                        .map(|v| self.sanitize_context(crate::db::Json(v.clone()), skip_keys))
                        .map(|v| v.0)
                        .collect(),
                ))
            }
            serde_json::Value::Object(obj) => {
                crate::db::Json(serde_json::Value::Object(
                    obj.iter()
                        .take(500) // Limit object size
                        .map(|(k, v)| {
                            if skip_keys.contains(&k.as_str()) {
                                // Don't sanitize template sections - they need Jinja2 syntax
                                (k.clone(), v.clone())
                            } else {
                                let sanitized =
                                    self.sanitize_context(crate::db::Json(v.clone()), skip_keys);
                                (k.clone(), sanitized.0)
                            }
                        })
                        .collect(),
                ))
            }
            // Numbers, booleans, and null are safe
            _ => value,
        }
    }

    /// Render a template with the given context (with security hardening)
    ///
    /// Security measures:
    /// - Input sanitization to prevent template injection
    /// - Context size limits to prevent DoS
    /// - Template fallback to prevent errors
    /// - Logging for security monitoring
    ///
    /// # Arguments
    /// * `template_id` - The ID of the template to render
    /// * `context` - The context data for rendering
    /// * `style` - Optional narrative style variables (tense, narration, perspective, length)
    pub fn render(&self, template_id: &str, context: crate::DbJson) -> Result<String, AppError> {
        self.render_with_style(template_id, context, None)
    }

    /// Render a template with narrative style variables
    pub fn render_with_style(
        &self,
        template_id: &str,
        context: crate::DbJson,
        style: Option<NarrativeStyle>,
    ) -> Result<String, AppError> {
        // Validate template_id format for security
        if template_id.is_empty() || template_id.len() > 50 {
            warn!(template_id = %template_id, "Invalid template_id format");
            return Err(AppError::BadRequest(
                "Invalid template ID format".to_string(),
            ));
        }

        // Fall back to neutral_roleplay if template not found
        let actual_template_id = if self.has_template(template_id) {
            template_id
        } else {
            warn!(
                requested = template_id,
                "Template not found, falling back to neutral_roleplay"
            );
            "neutral_roleplay"
        };

        // Get the template object and add sections to context first
        let template_obj = self.templates.get(actual_template_id).ok_or_else(|| {
            AppError::InternalServerErrorGeneric(
                "Template disappeared during rendering".to_string(),
            )
        })?;

        // Convert input context to map for manipulation
        let context_value: &serde_json::Value = &context.0;
        let mut context_map: serde_json::Map<String, serde_json::Value> = match context_value {
            serde_json::Value::Object(map) => map.clone(),
            _ => serde_json::Map::new(),
        };

        // Add narrative style variables to context
        let narrative_style = style.unwrap_or_default();
        context_map.insert(
            "tense".to_string(),
            serde_json::Value::String(narrative_style.tense.as_str().to_string()),
        );
        context_map.insert(
            "narration".to_string(),
            serde_json::Value::String(narrative_style.narration.as_str().to_string()),
        );
        context_map.insert(
            "perspective".to_string(),
            serde_json::Value::String(narrative_style.perspective.as_str().to_string()),
        );
        context_map.insert(
            "length".to_string(),
            serde_json::Value::String(narrative_style.length.as_str().to_string()),
        );

        // For templates with complex Jinja2 in sections, render each section with the full context
        let mut rendered_sections = std::collections::HashMap::new();
        debug!(template_id = %actual_template_id, section_count = template_obj.sections.len(), "Starting section pre-rendering");

        for (section_name, section_content) in &template_obj.sections {
            if section_name == "main" {
                continue; // Skip main section
            }

            debug!(
                section = section_name,
                template_id = actual_template_id,
                "Attempting to render section"
            );

            // Create a temporary environment to render this section
            let mut temp_env = minijinja::Environment::new();
            match temp_env.add_template("temp", section_content) {
                Ok(()) => {
                    if let Ok(temp_template) = temp_env.get_template("temp") {
                        match temp_template.render(crate::db::Json(serde_json::Value::Object(
                            context_map.clone(),
                        ))) {
                            Ok(rendered_content) => {
                                debug!(
                                    section = section_name,
                                    template_id = actual_template_id,
                                    rendered_length = rendered_content.len(),
                                    "Section rendered successfully"
                                );
                                rendered_sections.insert(section_name.clone(), rendered_content);
                            }
                            Err(e) => {
                                // If rendering fails, use raw content
                                debug!(section = section_name, template_id = actual_template_id, error = %e, "Section failed to render, using raw content");
                                rendered_sections
                                    .insert(section_name.clone(), section_content.clone());
                            }
                        }
                    } else {
                        debug!(
                            section = section_name,
                            template_id = actual_template_id,
                            "Failed to get template from temp environment"
                        );
                        rendered_sections.insert(section_name.clone(), section_content.clone());
                    }
                }
                Err(e) => {
                    // If template creation fails, use raw content
                    debug!(section = section_name, template_id = actual_template_id, error = %e, "Failed to add template to temp environment");
                    rendered_sections.insert(section_name.clone(), section_content.clone());
                }
            }
        }

        // Add rendered sections to context
        context_map.insert(
            "self".to_string(),
            serde_json::to_value(&rendered_sections).unwrap_or(serde_json::Value::Null),
        );

        let enhanced_context = crate::db::Json(serde_json::Value::Object(context_map));

        // Sanitize context to prevent template injection, but skip the 'self' key containing template sections
        let sanitized_context = self.sanitize_context(enhanced_context, &["self"]);

        let template_key = format!("{}/main", actual_template_id);

        let template = self.env.get_template(&template_key).map_err(|e| {
            error!(template_key = %template_key, error = %e, "Failed to get template");
            AppError::InternalServerErrorGeneric(format!(
                "Failed to get template '{}': {}",
                template_key, e
            ))
        })?;

        debug!(template_id = %actual_template_id, context_keys = ?sanitized_context.as_object().map(|o| o.keys().collect::<Vec<_>>()), "Rendering template with context");

        let rendered = template.render(sanitized_context).map_err(|e| {
            error!(template_id = %actual_template_id, error = %e, "Failed to render template");
            AppError::InternalServerErrorGeneric(format!("Failed to render template: {}", e))
        })?;

        debug!(template_id = %actual_template_id, rendered_length = rendered.len(), "Template rendered successfully");
        Ok(rendered)
    }
}

/// Global template manager instance
pub static TEMPLATE_MANAGER: Lazy<RwLock<TemplateManager>> = Lazy::new(|| {
    let mut manager = TemplateManager::new();

    // Load embedded templates first
    manager.load_embedded_templates();

    // Load file overrides
    manager.load_file_templates();

    info!(
        template_count = manager.templates.len(),
        templates = ?manager.templates.keys().collect::<Vec<_>>(),
        "Template manager initialized"
    );

    RwLock::new(manager)
});

#[cfg(all(test, feature = "postgres-backend"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_template_manager_creation() {
        let manager = TemplateManager::new();
        assert_eq!(manager.templates.len(), 0);
    }

    #[test]
    fn test_template_loading() {
        let template_json = r#"{
            "id": "test_template",
            "version": "1.0.0",
            "name": "Test Template",
            "description": "A test template",
            "compatibility": {
                "requires_character": false,
                "supports_rag": true,
                "supports_personas": true
            },
            "sections": {
                "main": "Hello {{ user.name | default('User') }}!"
            }
        }"#;

        let mut manager = TemplateManager::new();
        let result = manager.load_template_from_string(template_json);
        assert!(result.is_ok());
        assert!(manager.has_template("test_template"));
    }

    #[test]
    fn test_template_rendering() {
        let template_json = r#"{
            "id": "test_template",
            "version": "1.0.0",
            "name": "Test Template",
            "description": "A test template",
            "compatibility": {
                "requires_character": false,
                "supports_rag": true,
                "supports_personas": true
            },
            "sections": {
                "main": "Hello {{ user.name | default('User') }}!"
            }
        }"#;

        let mut manager = TemplateManager::new();
        manager.load_template_from_string(template_json).unwrap();

        let context = json!({
            "user": {"name": "TestUser"}
        });

        let result = manager.render("test_template", crate::db::Json(context));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello TestUser!");
    }

    #[test]
    fn test_fallback_to_default() {
        // This test ensures the global template manager falls back properly
        let manager = TEMPLATE_MANAGER.read().unwrap();

        let context = json!({
            "user": {"name": "TestUser"}
        });

        // Should fallback to neutral_roleplay
        let result = manager.render("nonexistent_template", crate::db::Json(context));
        assert!(result.is_ok());
        // Just ensure it doesn't error, content will vary
    }

    #[test]
    fn test_global_template_manager() {
        let manager = TEMPLATE_MANAGER.read().unwrap();

        // Should have at least the embedded templates
        assert!(manager.has_template("neutral_roleplay"));
        assert!(manager.has_template("chatbot_dialogue"));
        assert!(manager.has_template("creative_narrative"));

        // Should have at least 3 templates
        assert!(manager.list_templates().len() >= 3);
    }

    #[test]
    fn test_template_info_conversion() {
        let template = PromptTemplate {
            id: "test".to_string(),
            version: "1.0.0".to_string(),
            name: "Test Template".to_string(),
            description: "A test".to_string(),
            compatibility: TemplateCompatibility {
                requires_character: true,
                supports_rag: false,
                supports_personas: true,
            },
            sections: HashMap::new(),
        };

        let info = TemplateInfo::from(&template);
        assert_eq!(info.id, "test");
        assert_eq!(info.name, "Test Template");
        assert!(info.compatibility.requires_character);
        assert!(!info.compatibility.supports_rag);
    }
}
