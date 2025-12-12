#![cfg(feature = "postgres-backend")]
use scribe_backend::models::chats::UpdateChatSettingsRequest;
use scribe_backend::prompt_templates::TEMPLATE_MANAGER;
use validator::Validate;

#[test]
fn test_template_manager_basics() {
    // Test that templates are loaded
    let templates = TEMPLATE_MANAGER.list_templates();
    assert!(!templates.is_empty(), "No templates loaded");

    // Test that default templates exist
    assert!(
        TEMPLATE_MANAGER.has_template("neutral_roleplay"),
        "neutral_roleplay template not found"
    );
    assert!(
        TEMPLATE_MANAGER.has_template("chatbot_dialogue"),
        "chatbot_dialogue template not found"
    );
    assert!(
        TEMPLATE_MANAGER.has_template("creative_narrative"),
        "creative_narrative template not found"
    );

    // Test fallback behavior for non-existent template
    assert!(
        !TEMPLATE_MANAGER.has_template("non_existent_template"),
        "Non-existent template should not exist"
    );
}

#[test]
fn test_template_rendering() {
    let context = serde_json::json!({
        "user": {"name": "TestUser"},
        "char": {"name": "TestChar"},
        "character_definition": "A test character",
    });

    // Test rendering existing template
    let result = TEMPLATE_MANAGER.render("neutral_roleplay", context.clone());
    assert!(
        result.is_ok(),
        "Failed to render neutral_roleplay template: {:?}",
        result
    );

    let rendered = result.unwrap();
    assert!(
        !rendered.is_empty(),
        "Rendered template should not be empty"
    );

    // Test fallback to default for non-existent template
    let result = TEMPLATE_MANAGER.render("non_existent", context);
    assert!(
        result.is_ok(),
        "Should fallback to neutral_roleplay for non-existent template"
    );
}

#[test]
fn test_template_id_validation_valid() {
    let valid_request = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: None,
        model_provider: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
        agent_mode: None,
        active_custom_persona_id: None,
        prompt_template_id: Some("neutral_roleplay".to_string()),
    };

    let result = valid_request.validate();
    assert!(
        result.is_ok(),
        "Valid template ID should pass validation: {:?}",
        result
    );
}

#[test]
fn test_template_id_validation_invalid() {
    // Test empty template ID
    let invalid_request = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: None,
        model_provider: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
        agent_mode: None,
        active_custom_persona_id: None,
        prompt_template_id: Some("".to_string()),
    };

    let result = invalid_request.validate();
    assert!(result.is_err(), "Empty template ID should fail validation");

    // Test invalid characters
    let invalid_request = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: None,
        model_provider: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
        agent_mode: None,
        active_custom_persona_id: None,
        prompt_template_id: Some("invalid-template".to_string()),
    };

    let result = invalid_request.validate();
    assert!(
        result.is_err(),
        "Template ID with dash should fail validation"
    );

    // Test non-existent template
    let invalid_request = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: None,
        model_provider: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
        agent_mode: None,
        active_custom_persona_id: None,
        prompt_template_id: Some("non_existent_template".to_string()),
    };

    let result = invalid_request.validate();
    assert!(
        result.is_err(),
        "Non-existent template should fail validation"
    );
}

#[test]
fn test_template_info_structure() {
    let template_info = TEMPLATE_MANAGER.get_template_info("neutral_roleplay");
    assert!(
        template_info.is_some(),
        "Should get template info for neutral_roleplay"
    );

    let info = template_info.unwrap();
    assert_eq!(info.id, "neutral_roleplay");
    assert!(!info.name.is_empty(), "Template name should not be empty");
    assert!(
        !info.description.is_empty(),
        "Template description should not be empty"
    );
    assert!(
        info.compatibility.supports_rag,
        "neutral_roleplay should support RAG"
    );
    assert!(
        info.compatibility.supports_personas,
        "neutral_roleplay should support personas"
    );
    assert!(
        info.compatibility.requires_character,
        "neutral_roleplay should require character"
    );
}

#[test]
fn test_all_templates_have_valid_structure() {
    let templates = TEMPLATE_MANAGER.list_templates();

    for template in templates {
        // Each template should have basic metadata
        assert!(!template.id.is_empty(), "Template ID should not be empty");
        assert!(
            !template.name.is_empty(),
            "Template name should not be empty for {}",
            template.id
        );
        assert!(
            !template.description.is_empty(),
            "Template description should not be empty for {}",
            template.id
        );
        assert!(
            !template.version.is_empty(),
            "Template version should not be empty for {}",
            template.id
        );

        // Each template should be renderable
        let context = serde_json::json!({
            "user": {"name": "TestUser"},
            "char": {"name": "TestChar"},
            "character_definition": "A test character",
        });

        let result = TEMPLATE_MANAGER.render(&template.id, context);
        assert!(
            result.is_ok(),
            "Template {} should be renderable: {:?}",
            template.id,
            result
        );

        let rendered = result.unwrap();
        assert!(
            !rendered.is_empty(),
            "Rendered template {} should not be empty",
            template.id
        );
    }
}
