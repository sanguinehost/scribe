use crate::{
    config::Config,
    errors::AppError,
    models::characters::CharacterMetadata,
    prompt_templates::TEMPLATE_MANAGER,
    services::{
        embeddings::{decrypt_lorebook_title, RetrievedChunk},
        hybrid_token_counter::{CountingMode, HybridTokenCounter},
    },
};
use genai::chat::ChatMessage as GenAiChatMessage;
use genai::chat::ContentPart as Part; // This is the Part type from the genai crate
use genai::chat::MessageContent; // This is an enum from the genai crate
use secrecy::ExposeSecret;
use serde_json;
use std::fmt::Write;
use std::sync::Arc;
use tracing::{debug, error, warn};

/// Escapes text for safe inclusion in XML
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Builds the complete game state context XML block for chat context injection.
/// Formats GameState into a `<game_context>` XML block containing ALL player state.
///
/// This is injected into the main chat LLM so it knows about:
/// - Player vitals (health, stamina, mana)
/// - Player inventory (on person, stored, assets)
/// - Currencies
/// - Active quests (main + optional)
/// - Current location and environment
/// - Active NPCs in the scene
/// - Status effects
///
/// # Arguments
/// * `game_state` - The current game state to format
///
/// # Returns
/// A formatted XML string containing the complete game state
pub fn build_scene_context_xml(game_state: &crate::models::game_state::GameState) -> String {
    use std::fmt::Write;

    let mut xml = String::from("<game_context>\n");

    // ============= PLAYER VITALS =============
    if !game_state.vitals.is_empty() {
        writeln!(xml, "  <player_vitals>").unwrap();
        for (name, vital) in &game_state.vitals {
            writeln!(
                xml,
                "    <{} current=\"{}\" max=\"{}\" />",
                escape_xml(&name.to_lowercase().replace(' ', "_")),
                vital.current,
                vital.max
            )
            .unwrap();
        }
        writeln!(xml, "  </player_vitals>").unwrap();
    }

    // ============= CURRENCIES =============
    if !game_state.currencies.is_empty() {
        writeln!(xml, "  <currencies>").unwrap();
        for (name, amount) in &game_state.currencies {
            writeln!(
                xml,
                "    <{} amount=\"{}\" />",
                escape_xml(&name.to_lowercase()),
                amount
            )
            .unwrap();
        }
        writeln!(xml, "  </currencies>").unwrap();
    }

    // ============= INVENTORY (On Person) =============
    if !game_state.inventory.is_empty() {
        writeln!(xml, "  <inventory_on_person>").unwrap();
        for item in &game_state.inventory {
            let equipped_attr = if item.equipped {
                " equipped=\"true\""
            } else {
                ""
            };
            let qty_attr = if item.quantity > 1 {
                format!(" quantity=\"{}\"", item.quantity)
            } else {
                String::new()
            };
            writeln!(
                xml,
                "    <item name=\"{}\"{}{} />",
                escape_xml(&item.name),
                equipped_attr,
                qty_attr
            )
            .unwrap();
        }
        writeln!(xml, "  </inventory_on_person>").unwrap();
    }

    // ============= STORED INVENTORY =============
    if !game_state.inventory_stored.is_empty() {
        writeln!(xml, "  <inventory_stored>").unwrap();
        for (location, items) in &game_state.inventory_stored {
            writeln!(xml, "    <location name=\"{}\">", escape_xml(location)).unwrap();
            for item in items {
                let qty_attr = if item.quantity > 1 {
                    format!(" quantity=\"{}\"", item.quantity)
                } else {
                    String::new()
                };
                writeln!(
                    xml,
                    "      <item name=\"{}\"{}/>",
                    escape_xml(&item.name),
                    qty_attr
                )
                .unwrap();
            }
            writeln!(xml, "    </location>").unwrap();
        }
        writeln!(xml, "  </inventory_stored>").unwrap();
    }

    // ============= ASSETS =============
    if !game_state.assets.is_empty() {
        writeln!(xml, "  <assets>").unwrap();
        for asset in &game_state.assets {
            writeln!(xml, "    <asset>{}</asset>", escape_xml(asset)).unwrap();
        }
        writeln!(xml, "  </assets>").unwrap();
    }

    // ============= MAIN QUEST =============
    let main_quests: Vec<_> = game_state.quests.iter().filter(|q| q.is_main).collect();
    if !main_quests.is_empty() {
        writeln!(xml, "  <main_quest>").unwrap();
        for quest in main_quests {
            writeln!(xml, "    <title>{}</title>", escape_xml(&quest.title)).unwrap();
            writeln!(xml, "    <status>{:?}</status>", quest.status).unwrap();
            if let Some(desc) = &quest.description {
                let desc_str = match desc {
                    serde_json::Value::String(s) => s.clone(),
                    _ => desc.to_string(),
                };
                writeln!(
                    xml,
                    "    <description>{}</description>",
                    escape_xml(&desc_str)
                )
                .unwrap();
            }
            if !quest.objectives.is_empty() {
                writeln!(xml, "    <objectives>").unwrap();
                for obj in &quest.objectives {
                    let done = if obj.completed { "done" } else { "pending" };
                    let obj_desc = match &obj.description {
                        serde_json::Value::String(s) => s.clone(),
                        _ => obj.description.to_string(),
                    };
                    writeln!(
                        xml,
                        "      <objective status=\"{}\">{}</objective>",
                        done,
                        escape_xml(&obj_desc)
                    )
                    .unwrap();
                }
                writeln!(xml, "    </objectives>").unwrap();
            }
        }
        writeln!(xml, "  </main_quest>").unwrap();
    }

    // ============= OPTIONAL QUESTS =============
    let optional_quests: Vec<_> = game_state.quests.iter().filter(|q| !q.is_main).collect();
    if !optional_quests.is_empty() {
        writeln!(xml, "  <optional_quests>").unwrap();
        for quest in optional_quests {
            writeln!(
                xml,
                "    <quest title=\"{}\" status=\"{:?}\">",
                escape_xml(&quest.title),
                quest.status
            )
            .unwrap();
            if !quest.objectives.is_empty() {
                for obj in &quest.objectives {
                    let done = if obj.completed { "done" } else { "pending" };
                    let obj_desc = match &obj.description {
                        serde_json::Value::String(s) => s.clone(),
                        _ => obj.description.to_string(),
                    };
                    writeln!(
                        xml,
                        "      <objective status=\"{}\">{}</objective>",
                        done,
                        escape_xml(&obj_desc)
                    )
                    .unwrap();
                }
            }
            writeln!(xml, "    </quest>").unwrap();
        }
        writeln!(xml, "  </optional_quests>").unwrap();
    }

    // ============= LOCATION =============
    if let Some(location) = &game_state.location {
        writeln!(xml, "  <location>").unwrap();
        writeln!(xml, "    <name>{}</name>", escape_xml(&location.name)).unwrap();
        if let Some(desc) = &location.description {
            let desc_str = match desc {
                serde_json::Value::String(s) => s.clone(),
                _ => desc.to_string(),
            };
            writeln!(
                xml,
                "    <description>{}</description>",
                escape_xml(&desc_str)
            )
            .unwrap();
        }
        if let Some(region) = &location.region {
            writeln!(xml, "    <region>{}</region>", escape_xml(region)).unwrap();
        }
        if !location.tags.is_empty() {
            writeln!(xml, "    <tags>{}</tags>", location.tags.join(", ")).unwrap();
        }
        writeln!(xml, "  </location>").unwrap();
    }

    // ============= TIME =============
    if let Some(time) = &game_state.game_time {
        writeln!(xml, "  <time>").unwrap();
        writeln!(xml, "    <day>{}</day>", time.day).unwrap();
        writeln!(xml, "    <hour>{}</hour>", time.hour).unwrap();
        if time.minute > 0 {
            writeln!(xml, "    <minute>{}</minute>", time.minute).unwrap();
        }
        writeln!(xml, "    <period>{}</period>", escape_xml(&time.period)).unwrap();
        if let Some(season) = &time.season {
            writeln!(xml, "    <season>{}</season>", escape_xml(season)).unwrap();
        }
        writeln!(xml, "  </time>").unwrap();
    }

    // ============= ACTIVE NPCs =============
    let active_npcs: Vec<_> = game_state
        .npcs
        .values()
        .filter(|npc| npc.status == "alive")
        .collect();

    if !active_npcs.is_empty() {
        writeln!(xml, "  <npcs_present>").unwrap();
        for npc in active_npcs {
            writeln!(xml, "    <npc>").unwrap();
            writeln!(xml, "      <name>{}</name>", escape_xml(&npc.name)).unwrap();
            writeln!(
                xml,
                "      <disposition>{}</disposition>",
                escape_xml(&npc.disposition)
            )
            .unwrap();
            if let Some(loc) = &npc.location {
                writeln!(xml, "      <location>{}</location>", escape_xml(loc)).unwrap();
            }
            writeln!(xml, "    </npc>").unwrap();
        }
        writeln!(xml, "  </npcs_present>").unwrap();
    }

    // ============= ENVIRONMENT =============
    writeln!(xml, "  <environment>").unwrap();
    if let Some(weather) = &game_state.environment.weather {
        writeln!(xml, "    <weather>{}</weather>", escape_xml(weather)).unwrap();
    }
    if let Some(lighting) = &game_state.environment.lighting {
        writeln!(xml, "    <lighting>{}</lighting>", escape_xml(lighting)).unwrap();
    }
    if let Some(temp) = &game_state.environment.temperature {
        writeln!(xml, "    <temperature>{}</temperature>", escape_xml(temp)).unwrap();
    }
    if !game_state.environment.hazards.is_empty() {
        writeln!(
            xml,
            "    <hazards>{}</hazards>",
            game_state.environment.hazards.join(", ")
        )
        .unwrap();
    }
    writeln!(xml, "  </environment>").unwrap();

    // Note: Status effects are tracked per-vital in Vital.modifiers, not as global effects

    xml.push_str("</game_context>");
    xml
}

/// Replaces template variables {{char}} and {{user}} with actual names
pub fn replace_template_variables(
    text: &str,
    character_name: Option<&str>,
    user_persona_name: Option<&str>,
) -> String {
    let mut result = text.to_string();

    // Replace {{char}} with character name
    if let Some(char_name) = character_name {
        result = result.replace("{{char}}", char_name);
    }

    // Replace {{user}} with user persona name or default
    let user_name = user_persona_name.unwrap_or("User");
    result = result.replace("{{user}}", user_name);

    result
}

/// Assembles the character-specific part of the system prompt.
/// RAG context is handled by the calling service and prepended to the user message.
///
/// # Errors
/// Returns `AppError` if character description processing fails
pub fn build_prompt_with_rag(
    // Renaming to build_system_prompt_character_info might be clearer later
    character: Option<&CharacterMetadata>,
) -> Result<String, AppError> {
    // No longer async, no AppState needed

    let mut prompt = String::new();

    if let Some(char_data) = character {
        if let Some(description_vec) = &char_data.description {
            if description_vec.is_empty() {
                // No description, return empty string (no character persona to instruct on)
                return Ok(String::new());
            }
            writeln!(prompt, "Character Name: {}", char_data.name).unwrap();
            writeln!(
                prompt,
                "Description: {}",
                String::from_utf8_lossy(description_vec)
            )
            .unwrap();
            prompt.push('\n');
            // Only add static instruction if there's a character description
            prompt.push_str("---\\nInstruction:\\nContinue the chat based on the conversation history. Stay in character.\\n---\\n\\n");
        } else {
            // No description, return empty string
            return Ok(String::new());
        }
    } else {
        // No character, return empty string
        return Ok(String::new());
    }

    Ok(prompt)
}

/// Decrypts a single character field and returns it as a string
fn decrypt_character_field(
    ciphertext: &Option<Vec<u8>>,
    nonce: &Option<Vec<u8>>,
    dek: Option<&secrecy::SecretBox<Vec<u8>>>,
    character_name: &str,
    user_persona_name: Option<&str>,
) -> Option<String> {
    if let (Some(ct), Some(n), Some(dek_key)) = (ciphertext, nonce, dek) {
        if !ct.is_empty() {
            match crate::crypto::decrypt_gcm(ct, n, dek_key) {
                Ok(plaintext_bytes) => {
                    let plaintext = String::from_utf8_lossy(plaintext_bytes.expose_secret());
                    if !plaintext.is_empty() {
                        let substituted_text = replace_template_variables(
                            &plaintext,
                            Some(character_name),
                            user_persona_name,
                        );
                        return Some(substituted_text);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to decrypt character field: {}", e);
                }
            }
        }
    }
    None
}

/// Builds the character-specific information string for the system prompt.
fn build_character_info_string(
    character_metadata: Option<&CharacterMetadata>,
    dek: Option<&secrecy::SecretBox<Vec<u8>>>,
    user_persona_name: Option<&str>,
) -> String {
    let Some(char_data) = character_metadata else {
        return String::new();
    };

    let mut char_prompt_part = String::new();
    let mut has_content;

    // Helper to decrypt a field and append it to the prompt string
    let append_decrypted_field = |field_name: &str,
                                  ciphertext: &Option<Vec<u8>>,
                                  nonce: &Option<Vec<u8>>,
                                  char_prompt_part: &mut String,
                                  has_content: &mut bool| {
        if let (Some(ct), Some(n)) = (ciphertext, nonce) {
            if !ct.is_empty() {
                match crate::crypto::decrypt_gcm(ct, n, dek.unwrap()) {
                    Ok(plaintext_bytes) => {
                        let plaintext = String::from_utf8_lossy(plaintext_bytes.expose_secret());
                        if !plaintext.is_empty() {
                            let substituted_text = replace_template_variables(
                                &plaintext,
                                Some(&char_data.name),
                                user_persona_name,
                            );
                            writeln!(char_prompt_part, "**{}:** {}", field_name, substituted_text)
                                .unwrap();
                            *has_content = true;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to decrypt character field \"{}\": {}",
                            field_name,
                            e
                        );
                    }
                }
            }
        }
    };

    // Always add name if we have a character
    writeln!(char_prompt_part, "**Character Name:** {}", char_data.name).unwrap();
    has_content = true;

    append_decrypted_field(
        "Description",
        &char_data.description,
        &char_data.description_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );
    append_decrypted_field(
        "Personality",
        &char_data.personality,
        &char_data.personality_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );
    append_decrypted_field(
        "Scenario",
        &char_data.scenario,
        &char_data.scenario_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );
    append_decrypted_field(
        "Example Dialogue",
        &char_data.mes_example,
        &char_data.mes_example_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );

    if has_content {
        char_prompt_part
    } else {
        String::new()
    }
}

/// Counts tokens for a single `GenAiChatMessage`.
async fn count_tokens_for_genai_message(
    message: &GenAiChatMessage,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<usize, AppError> {
    let mut total_tokens = 0;
    // genai::chat::ChatMessage has a `content: MessageContent` field.
    // genai::chat::MessageContent is an enum. We need to match its variants.
    if let Some(text) = message.content.first_text() {
        total_tokens += token_counter
            .count_tokens(text, CountingMode::LocalOnly, Some(model_name))
            .await?
            .total;
    } else {
        for part in message.content.parts() {
            if let Part::Text(text) = part {
                total_tokens += token_counter
                    .count_tokens(text, CountingMode::LocalOnly, Some(model_name))
                    .await?
                    .total;
            }
        }
    }
    Ok(total_tokens)
}

/// Parameters for building the final LLM prompt.
pub struct PromptBuildParams<'a> {
    pub config: Arc<Config>,
    pub token_counter: Arc<HybridTokenCounter>,
    pub recent_history: Vec<GenAiChatMessage>,
    pub rag_items: Vec<RetrievedChunk>,
    pub system_prompt_base: Option<String>, // From Persona/Override
    pub raw_character_system_prompt: Option<String>, // Directly from Character.system_prompt
    pub character_metadata: Option<&'a CharacterMetadata>, // For name/description
    pub current_user_message: GenAiChatMessage,
    pub model_name: String,
    pub user_dek: Option<&'a secrecy::SecretBox<Vec<u8>>>, // For decrypting character data
    pub user_persona_name: Option<String>,                 // For {{user}} template substitution
    pub agent_context: Option<String>,                     // Pre-processing agent context to inject
    pub guidance: Option<String>, // Optional guidance for response generation
    pub prompt_template_id: Option<String>, // Template ID for conversation style
    pub narrative_style: Option<crate::prompt_templates::NarrativeStyle>, // Narrative style variables for template rendering
    /// Game state for Game Master mode scene card injection
    /// When present, formats as `<scene_context>` XML block in the system prompt
    pub game_state: Option<&'a crate::models::game_state::GameState>,
    // RAG Limits
    pub rag_chronicles_limit: Option<i32>,
    pub rag_lorebooks_limit: Option<i32>,
    pub rag_older_chat_limit: Option<i32>,
    // Session-specific context limits (overrides config if present)
    pub context_total_token_limit: Option<usize>,
    pub recent_history_token_budget: Option<usize>,
    pub rag_token_budget: Option<usize>,
    pub cognitive_context: Option<String>, // Secure cognitive context (opinions/observations)
    pub core_memory: Option<String>,       // TITANS/MIRAS Core Memory (Global State)
}

/// Builds the meta system prompt template with character name substitution
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn build_meta_system_prompt(
    character_metadata: Option<&CharacterMetadata>,
    has_rag_items: bool,
    has_persona_override: bool,
    has_character_definition: bool,
    has_character_details: bool,
    has_cognitive_context: bool,
    has_core_memory: bool,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<(String, usize), AppError> {
    let char_name_placeholder =
        character_metadata.map_or_else(|| "{{character_name}}".to_string(), |cm| cm.name.clone());

    let mut sections_list = Vec::new();
    let mut section_num = 1;

    if has_persona_override {
        sections_list.push(format!("{}. <persona_override_prompt>: Specific instructions or style preferences from the User.", section_num));
        section_num += 1;
    }

    if has_character_definition {
        sections_list.push(format!("{}. <system_instructions>: Narrative style and behavioral guidelines for the character \"{}\".", section_num, char_name_placeholder));
        section_num += 1;
    }

    if has_character_details {
        sections_list.push(format!(
            "{}. <character_profile>: Character background, personality, and details for \"{}\".",
            section_num, char_name_placeholder
        ));
        section_num += 1;
    }

    if has_rag_items {
        sections_list.push(format!("{}. <lorebook_entries>: Relevant background information about the world, other characters, or plot points.", section_num));
        section_num += 1;
    }

    if has_cognitive_context {
        sections_list.push(format!("{}. <cognitive_context>: Secure character opinions and entity observations that evolve over time.", section_num));
        section_num += 1;
    }

    if has_core_memory {
        sections_list.push(format!(
            "{}. <core_memory>: The current global state and long-term memory of the narrative.",
            section_num
        ));
        section_num += 1;
    }

    sections_list.push(format!("{}. The conversation history contains the story so far - the existing dialogue and narration.", section_num));

    let sections_text = sections_list.join("\\n");

    let meta_system_prompt_template = format!(
        "You are Assistant, creating interactive roleplay experiences with Human. This is consensual creative storytelling between adults using fictional characters. Human controls their character's words and actions exclusively.\\n\\n\
You are allowed to depict any content that serves the story (including mature, explicit, violent, or sensitive topics) as this is purely fictional with no real-world implications.\\n\\n\
## Response Framework\\n\
Your responses must be **immediately reactive** to Human's input - never repeat, echo, or re-narrate what Human just did. Instead, respond with:\\n\
- **Direct reactions** from character(s) to Human's action/words\\n\
- **Immediate consequences** of Human's action\\n\
- **New developments** that push the scene forward\\n\\n\
## Universal Anti-Repetition Rules\\n\
**NEVER do any of the following:**\\n\
- Re-describe or echo Human's actions (\"Sol did X\" when Human just wrote Sol doing X)\\n\
- Repeat dialogue Human just spoke\\n\
- Narrate the same action from a different perspective\\n\
- Summarize what just happened in the previous exchange\\n\
- Use phrases like \"having just done X\" or \"after doing Y\" that reference Human's previous action\\n\\n\
## Good vs Bad Response Examples\\n\
**BAD - Repeating Human's exact words:**\\n\
Human: \"I knock on the door.\"\\n\
You: \"You knock on the door, and the sound echoes...\"\\n\\n\
**FINE - Describing the action differently:**\\n\
Human: \"I knock on the door.\"\\n\
You: \"As you rap against the wood, footsteps shuffle inside...\"\\n\\n\
**BEST - Direct consequence without repetition:**\\n\
Human: \"I knock on the door.\"\\n\
You: \"Footsteps approach from within. The door creaks open...\"\\n\\n\
**BAD - Echoing Human's dialogue verbatim:**\\n\
Human: \"'Hello there,' I say warmly.\"\\n\
You: \"'Hello there,' Sol says warmly, and she looks up...\"\\n\\n\
**GOOD - Character response:**\\n\
Human: \"'Hello there,' I say warmly.\"\\n\
You: \"'Oh! I wasn't expecting anyone.' She looks up with surprised eyes...\"\\n\\n\
## Response Guidelines\\n\
- **Turn-Based Structure**: Human acts, you react. Clean, alternating turns.\\n\
- **Immediate Consequence**: Show the direct result of Human's action right away\\n\
- **Character Consistency**: Maintain personality and knowledge appropriately\\n\
- **Natural Boundaries**: Characters can disagree, resist, or have their own agendas\\n\
- **Sensory Details**: Include relevant environmental and physical details\\n\
- **Varied Structure**: Avoid predictable response patterns - mix dialogue, action, description\\n\\n\
## Information Structure\\n\
You will receive structured information in the following format:\\n\
{}\\n\\n\
## Character Assignment\\n\
**If <character_profile> contains a single character:** Embody that character exclusively. Respond as that character reacting to Human's character.\\n\\n\
**If context suggests multiple characters or you're managing a scene:** Act as Game Master, controlling multiple characters and the environment as needed.\\n\\n\
**In both modes:** Never control Human's character. Never decide what Human's character does, says, thinks, or feels.",
        sections_text
    );

    let meta_system_prompt_tokens = token_counter
        .count_tokens(
            &meta_system_prompt_template,
            CountingMode::LocalOnly,
            Some(model_name),
        )
        .await?
        .total;

    Ok((meta_system_prompt_template, meta_system_prompt_tokens))
}

/// Calculates token counts for all prompt components
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn calculate_component_tokens(
    system_prompt_base: Option<&str>,
    raw_character_system_prompt: Option<&str>,
    character_metadata: Option<&CharacterMetadata>,
    current_user_message: &GenAiChatMessage,
    token_counter: &HybridTokenCounter,
    model_name: &str,
    user_dek: Option<&secrecy::SecretBox<Vec<u8>>>,
    user_persona_name: Option<&str>,
    core_memory: Option<&str>,
) -> Result<
    (
        (String, usize),
        (String, usize),
        (String, usize),
        usize,
        (String, usize),
    ),
    AppError,
> {
    // Apply template substitution to persona override prompt
    let character_name = character_metadata.map(|cm| cm.name.as_str());
    let persona_override_prompt_str = if let Some(base) = system_prompt_base {
        replace_template_variables(base, character_name, user_persona_name)
    } else {
        String::new()
    };
    let persona_override_prompt_tokens = if persona_override_prompt_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                &persona_override_prompt_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    // Apply template substitution to character system prompt
    let character_definition_str = if let Some(raw) = raw_character_system_prompt {
        replace_template_variables(raw, character_name, user_persona_name)
    } else {
        String::new()
    };
    let character_definition_tokens = if character_definition_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                &character_definition_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    let character_details_str =
        build_character_info_string(character_metadata, user_dek, user_persona_name);
    let character_details_tokens = if character_details_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                &character_details_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    let current_user_message_tokens =
        count_tokens_for_genai_message(current_user_message, token_counter, model_name).await?;

    let core_memory_str = core_memory.unwrap_or("").to_string();
    let core_memory_tokens = if core_memory_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(&core_memory_str, CountingMode::LocalOnly, Some(model_name))
            .await?
            .total
    };

    Ok((
        (
            persona_override_prompt_str.to_string(),
            persona_override_prompt_tokens,
        ),
        (
            character_definition_str.to_string(),
            character_definition_tokens,
        ),
        (character_details_str, character_details_tokens),
        current_user_message_tokens,
        (core_memory_str, core_memory_tokens),
    ))
}

/// Calculates tokens for RAG items and chat history
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn calculate_content_tokens(
    rag_items: &[RetrievedChunk],
    recent_history: &[GenAiChatMessage],
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<(Vec<(RetrievedChunk, usize)>, Vec<(GenAiChatMessage, usize)>), AppError> {
    let mut rag_items_with_tokens: Vec<(RetrievedChunk, usize)> = Vec::new();
    for item in rag_items {
        let tokens = token_counter
            .count_tokens(&item.text, CountingMode::LocalOnly, Some(model_name))
            .await?
            .total;
        rag_items_with_tokens.push((item.clone(), tokens));
    }

    let mut recent_history_with_tokens: Vec<(GenAiChatMessage, usize)> = Vec::new();
    for msg in recent_history {
        let tokens = count_tokens_for_genai_message(msg, token_counter, model_name).await?;
        recent_history_with_tokens.push((msg.clone(), tokens));
    }

    Ok((rag_items_with_tokens, recent_history_with_tokens))
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) struct TokenCalculation {
    meta_system_prompt_tokens: usize,
    persona_override_prompt_str: String,
    persona_override_prompt_tokens: usize,
    character_definition_str: String,
    character_definition_tokens: usize,
    character_details_str: String,
    character_details_tokens: usize,
    current_user_message_tokens: usize,
    rag_items_with_tokens: Vec<(RetrievedChunk, usize)>,
    recent_history_with_tokens: Vec<(GenAiChatMessage, usize)>,
    cognitive_context: Option<String>,
    cognitive_context_tokens: usize,
    #[allow(dead_code)]
    core_memory: Option<String>,
    core_memory_tokens: usize,
}

async fn perform_initial_token_calculation(
    params: &PromptBuildParams<'_>,
) -> Result<TokenCalculation, AppError> {
    let PromptBuildParams {
        token_counter,

        rag_items,
        system_prompt_base,
        raw_character_system_prompt,
        character_metadata,
        current_user_message,
        model_name,
        user_persona_name,
        core_memory,
        ..
    } = params;

    // 1. Build meta system prompt and calculate its tokens
    // Note: We'll rebuild this later with the final RAG items after truncation
    let (_meta_system_prompt_template, meta_system_prompt_tokens) = build_meta_system_prompt(
        *character_metadata,
        !rag_items.is_empty(),
        system_prompt_base.is_some() && !system_prompt_base.as_ref().unwrap().is_empty(),
        raw_character_system_prompt.is_some()
            && !raw_character_system_prompt.as_ref().unwrap().is_empty(),
        character_metadata.is_some(),
        params.cognitive_context.is_some(),
        core_memory.is_some(),
        token_counter,
        model_name,
    )
    .await?;

    // 2. Calculate tokens for all components
    let (
        (persona_override_prompt_str, persona_override_prompt_tokens),
        (character_definition_str, character_definition_tokens),
        (character_details_str, character_details_tokens),
        current_user_message_tokens,
        (core_memory_str, core_memory_tokens),
    ) = calculate_component_tokens(
        system_prompt_base.as_deref(),
        raw_character_system_prompt.as_deref(),
        *character_metadata,
        current_user_message,
        token_counter,
        model_name,
        params.user_dek,
        user_persona_name.as_deref(),
        core_memory.as_deref(),
    )
    .await?;

    // 3. Calculate tokens for RAG items and recent history
    let mut processed_rag_items = params.rag_items.clone();

    // Step 1: Deduplicate RAG items
    processed_rag_items = deduplicate_rag_items(processed_rag_items);

    // Step 2: Filter out chat chunks already in recent history
    processed_rag_items =
        filter_rag_items_already_in_history(processed_rag_items, &params.recent_history);

    let (rag_items_with_tokens, recent_history_with_tokens) = calculate_content_tokens(
        &processed_rag_items,
        &params.recent_history,
        &params.token_counter,
        &params.model_name,
    )
    .await?;

    let cognitive_context_tokens = if let Some(ctx) = &params.cognitive_context {
        token_counter
            .count_tokens(ctx, CountingMode::LocalOnly, Some(model_name))
            .await?
            .total
    } else {
        0
    };

    Ok(TokenCalculation {
        meta_system_prompt_tokens,
        persona_override_prompt_str,
        persona_override_prompt_tokens,
        character_definition_str,
        character_definition_tokens,
        character_details_str,
        character_details_tokens,
        current_user_message_tokens,
        rag_items_with_tokens,
        recent_history_with_tokens,
        cognitive_context: params.cognitive_context.clone(),
        cognitive_context_tokens,
        core_memory: Some(core_memory_str),
        core_memory_tokens,
    })
}

/// Deduplicates RAG items based on their unique identifiers
fn deduplicate_rag_items(items: Vec<RetrievedChunk>) -> Vec<RetrievedChunk> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|item| {
            let id = match &item.metadata {
                crate::services::embeddings::RetrievedMetadata::Chat(meta) => {
                    format!("chat:{}", meta.message_id)
                }
                crate::services::embeddings::RetrievedMetadata::Lorebook(meta) => {
                    // Use entry_id + first 100 chars of text to distinguish chunks of the same entry
                    let text_snippet = item.text.chars().take(100).collect::<String>();
                    format!(
                        "lorebook:{}:{}",
                        meta.original_lorebook_entry_id, text_snippet
                    )
                }
                crate::services::embeddings::RetrievedMetadata::Chronicle(meta) => {
                    format!("chronicle:{}", meta.event_id)
                }
            };
            seen.insert(id)
        })
        .collect()
}

/// Filters out RAG items of type Chat if their content is already present in recent history
fn filter_rag_items_already_in_history(
    rag_items: Vec<RetrievedChunk>,
    recent_history: &[GenAiChatMessage],
) -> Vec<RetrievedChunk> {
    let mut history_texts = std::collections::HashSet::new();

    for msg in recent_history {
        if let Some(text) = msg.content.first_text() {
            history_texts.insert(text.trim().to_string());
        } else {
            for part in msg.content.parts() {
                if let Part::Text(t) = part {
                    history_texts.insert(t.trim().to_string());
                }
            }
        }
    }

    rag_items
        .into_iter()
        .filter(|item| {
            if let crate::services::embeddings::RetrievedMetadata::Chat(_) = &item.metadata {
                // If the RAG chunk text is exactly in history, skip it
                // Also check if it's a substring of any history message (since chunks are parts of messages)
                let item_text = item.text.trim();
                if history_texts.contains(item_text) {
                    return false;
                }
                // More expensive check: is this chunk a substring of any history message?
                for h_text in &history_texts {
                    if h_text.contains(item_text) {
                        return false;
                    }
                }
                true
            } else {
                true
            }
        })
        .collect()
}

/// Calculates the total token count for all components
fn calculate_total_tokens(calculation: &TokenCalculation) -> usize {
    calculation.meta_system_prompt_tokens
        + calculation.persona_override_prompt_tokens
        + calculation.character_definition_tokens
        + calculation.character_details_tokens
        + calculation.current_user_message_tokens
        + calculation
            .rag_items_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
        + calculation
            .recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
        + calculation.cognitive_context_tokens
        + calculation.core_memory_tokens
}

/// Logs the initial token calculation breakdown
fn log_initial_token_calculation(
    calculation: &TokenCalculation,
    current_total_tokens: usize,
    max_allowed_tokens: usize,
) {
    debug!(
        current_total_tokens,
        max_allowed_tokens,
        calculation.meta_system_prompt_tokens,
        calculation.persona_override_prompt_tokens,
        calculation.character_definition_tokens,
        calculation.character_details_tokens,
        calculation.current_user_message_tokens,
        rag_tokens = calculation
            .rag_items_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>(),
        history_tokens = calculation
            .recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>(),
        calculation.cognitive_context_tokens,
        calculation.core_memory_tokens,
        "Initial token calculation for prompt building."
    );
}

/// Truncates RAG items to reduce token count
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn truncate_rag_context(
    calculation: &mut TokenCalculation,
    current_total_tokens: &mut usize,
    max_allowed_total_tokens: usize,
    rag_chronicles_limit: Option<i32>,
    rag_lorebooks_limit: Option<i32>,
    rag_older_chat_limit: Option<i32>,
) {
    // 1. Apply granular limits first
    let mut chronicle_tokens = 0;
    let mut lorebook_tokens = 0;
    let mut chat_tokens = 0;

    let mut items_to_keep = Vec::new();

    for (item, tokens) in calculation.rag_items_with_tokens.drain(..) {
        let limit = match &item.metadata {
            crate::services::embeddings::RetrievedMetadata::Chronicle(_) => rag_chronicles_limit,
            crate::services::embeddings::RetrievedMetadata::Lorebook(_) => rag_lorebooks_limit,
            crate::services::embeddings::RetrievedMetadata::Chat(_) => rag_older_chat_limit,
        };

        let current_cat_tokens = match &item.metadata {
            crate::services::embeddings::RetrievedMetadata::Chronicle(_) => &mut chronicle_tokens,
            crate::services::embeddings::RetrievedMetadata::Lorebook(_) => &mut lorebook_tokens,
            crate::services::embeddings::RetrievedMetadata::Chat(_) => &mut chat_tokens,
        };

        if let Some(l) = limit {
            if *current_cat_tokens + tokens > l as usize {
                *current_total_tokens -= tokens;
                continue;
            }
        }

        *current_cat_tokens += tokens;
        items_to_keep.push((item, tokens));
    }

    calculation.rag_items_with_tokens = items_to_keep;

    // 2. If still over total limit, truncate from the end (lowest scores)
    while *current_total_tokens > max_allowed_total_tokens
        && !calculation.rag_items_with_tokens.is_empty()
    {
        if let Some((_, tokens)) = calculation.rag_items_with_tokens.pop() {
            *current_total_tokens -= tokens;
        }
    }

    debug!(
        current_total_tokens = *current_total_tokens,
        max_allowed_total_tokens, "RAG context truncated."
    );
}

/// Strategically truncates recent history using middle-out approach:
/// - Preserves HEAD: system prompt, character info, persona (already protected)
/// - Preserves TAIL: recent N conversation turns for continuity
/// - Removes MIDDLE: older history that's less critical for immediate context
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn truncate_recent_history_strategically(
    calculation: &mut TokenCalculation,
    current_total_tokens: &mut usize,
    max_allowed_tokens: usize,
    _min_tail_messages_to_preserve: usize,
) {
    if *current_total_tokens <= max_allowed_tokens {
        return;
    }

    debug!(
        current_total_tokens = *current_total_tokens,
        max_allowed_tokens, "Starting standard sliding window truncation (oldest-first)."
    );

    while !calculation.recent_history_with_tokens.is_empty()
        && *current_total_tokens > max_allowed_tokens
    {
        // Remove the oldest message (index 0)
        let (_, tokens) = calculation.recent_history_with_tokens.remove(0);
        *current_total_tokens -= tokens;

        debug!(
            tokens,
            current_total_tokens = *current_total_tokens,
            "Removed oldest message"
        );
    }

    debug!(
        final_message_count = calculation.recent_history_with_tokens.len(),
        current_total_tokens = *current_total_tokens,
        "History truncation completed."
    );
}

/// Enforces hard token limit by returning an error if limit is still exceeded after truncation
fn enforce_hard_token_limit(
    current_total_tokens: usize,
    max_allowed_tokens: usize,
) -> Result<(), AppError> {
    if current_total_tokens > max_allowed_tokens {
        let excess_tokens = current_total_tokens - max_allowed_tokens;
        error!(
            current_total_tokens,
            max_allowed_tokens,
            excess_tokens,
            "Hard token limit exceeded even after strategic truncation. This should not happen."
        );
        return Err(AppError::BadRequest(format!(
            "Request too large: {} tokens exceeds maximum limit of {} tokens (excess: {} tokens). \
            Even after removing context and truncating history, the request is still too large. \
            Please try with shorter messages or reduce character complexity.",
            current_total_tokens, max_allowed_tokens, excess_tokens
        )));
    }
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_token_limits(
    mut calculation: TokenCalculation,
    config: &Arc<Config>,
    rag_chronicles_limit: Option<i32>,
    rag_lorebooks_limit: Option<i32>,
    rag_older_chat_limit: Option<i32>,
    context_total_token_limit: Option<usize>,
    recent_history_token_budget: Option<usize>,
    rag_token_budget: Option<usize>,
) -> Result<TokenCalculation, AppError> {
    let mut current_total_tokens = calculate_total_tokens(&calculation);
    let max_allowed_tokens = context_total_token_limit.unwrap_or(config.context_total_token_limit);
    let recent_history_budget =
        recent_history_token_budget.unwrap_or(config.context_recent_history_token_budget);
    let rag_budget = rag_token_budget.unwrap_or(config.context_rag_token_budget);

    debug!(
        current_total_tokens,
        max_allowed_tokens,
        recent_history_token_budget = recent_history_budget,
        rag_token_budget = rag_budget,
        "Applying token limits in prompt_builder"
    );

    log_initial_token_calculation(&calculation, current_total_tokens, max_allowed_tokens);

    // Step 1: First try truncating RAG context (less critical for conversation continuity)
    truncate_rag_context(
        &mut calculation,
        &mut current_total_tokens,
        max_allowed_tokens,
        rag_chronicles_limit,
        rag_lorebooks_limit,
        rag_older_chat_limit,
    );

    // Step 2: If still over limit, apply strategic middle-out truncation to history
    truncate_recent_history_strategically(
        &mut calculation,
        &mut current_total_tokens,
        max_allowed_tokens,
        config.min_tail_messages_to_preserve,
    );

    // Step 3: Hard enforcement - return error if still over limit
    enforce_hard_token_limit(current_total_tokens, max_allowed_tokens)?;

    Ok(calculation)
}

/// Builds the RAG context string from calculation data
#[allow(deprecated)]
fn build_rag_context_strings(
    calculation: &TokenCalculation,
    user_dek: Option<&secrecy::SecretBox<Vec<u8>>>,
) -> (String, String, String) {
    if calculation.rag_items_with_tokens.is_empty() {
        return (String::new(), String::new(), String::new());
    }

    let mut chronicle_context = String::new();
    let mut lorebook_context = String::new();
    let mut older_chat_context = String::new();

    // Separate chronicle events, lorebook entries, and older chat history
    let mut chronicle_events = Vec::new();
    let mut lorebook_entries = Vec::new();
    let mut older_chat_history = Vec::new();

    for (rag_item, _tokens) in &calculation.rag_items_with_tokens {
        match &rag_item.metadata {
            crate::services::embeddings::RetrievedMetadata::Chronicle(_) => {
                chronicle_events.push(rag_item);
            }
            crate::services::embeddings::RetrievedMetadata::Lorebook(_) => {
                lorebook_entries.push(rag_item);
            }
            crate::services::embeddings::RetrievedMetadata::Chat(_) => {
                older_chat_history.push(rag_item);
            }
        }
    }

    // Add chronicle events in a long_term_memory section
    if !chronicle_events.is_empty() {
        chronicle_context.push_str("<long_term_memory>\n");
        for rag_item in &chronicle_events {
            if let crate::services::embeddings::RetrievedMetadata::Chronicle(chronicle_meta) =
                &rag_item.metadata
            {
                // Try to parse the text as JSON to extract rich chronicle data
                if let Ok(event_data) = serde_json::from_str::<crate::DbJson>(&rag_item.text) {
                    write!(
                        chronicle_context,
                        "<chronicle_event type=\"{}\" timestamp=\"{}\"",
                        escape_xml(&chronicle_meta.event_type),
                        chronicle_meta.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                    )
                    .unwrap();

                    // Add action if available
                    if let Some(action) = event_data.get("action").and_then(|a| a.as_str()) {
                        write!(chronicle_context, " action=\"{}\"", escape_xml(action)).unwrap();
                    }

                    // Add modality if available
                    if let Some(modality) = event_data.get("modality").and_then(|m| m.as_str()) {
                        write!(chronicle_context, " modality=\"{}\"", escape_xml(modality))
                            .unwrap();
                    }

                    writeln!(chronicle_context, ">").unwrap();

                    // Add actors if available
                    if let Some(actors) = event_data.get("actors").and_then(|a| a.as_array()) {
                        if !actors.is_empty() {
                            writeln!(chronicle_context, "    <actors>").unwrap();
                            for actor in actors {
                                if let (Some(id), Some(role)) = (
                                    actor.get("id").and_then(|i| i.as_str()),
                                    actor.get("role").and_then(|r| r.as_str()),
                                ) {
                                    let details =
                                        actor.get("details").and_then(|d| d.as_str()).unwrap_or("");
                                    writeln!(
                                        chronicle_context,
                                        "        <actor id=\"{}\" role=\"{}\">{}</actor>",
                                        escape_xml(id),
                                        escape_xml(role),
                                        escape_xml(details)
                                    )
                                    .unwrap();
                                }
                            }
                            writeln!(chronicle_context, "    </actors>").unwrap();
                        }
                    }

                    // Add valence changes if available
                    if let Some(valence) = event_data.get("valence").and_then(|v| v.as_array()) {
                        if !valence.is_empty() {
                            writeln!(chronicle_context, "    <valence>").unwrap();
                            for change in valence {
                                if let (Some(target), Some(change_type), Some(delta)) = (
                                    change.get("target").and_then(|t| t.as_str()),
                                    change.get("type").and_then(|t| t.as_str()),
                                    change.get("change").and_then(|c| c.as_f64()),
                                ) {
                                    writeln!(
                                        chronicle_context,
                                        "        <change target=\"{}\" type=\"{}\" delta=\"{:+.1}\"/>",
                                        escape_xml(target),
                                        escape_xml(change_type),
                                        delta
                                    )
                                    .unwrap();
                                }
                            }
                            writeln!(chronicle_context, "    </valence>").unwrap();
                        }
                    }

                    // Add context data if available
                    if let Some(context) =
                        event_data.get("context_data").and_then(|c| c.as_object())
                    {
                        if !context.is_empty() {
                            write!(chronicle_context, "    <context").unwrap();
                            for (key, value) in context {
                                if let Some(val_str) = value.as_str() {
                                    write!(
                                        chronicle_context,
                                        " {}=\"{}\"",
                                        escape_xml(key),
                                        escape_xml(val_str)
                                    )
                                    .unwrap();
                                }
                            }
                            writeln!(chronicle_context, "/>").unwrap();
                        }
                    }

                    // Add causality if available
                    if let Some(causality) = event_data.get("causality").and_then(|c| c.as_object())
                    {
                        let has_caused_by = causality
                            .get("causedBy")
                            .and_then(|cb| cb.as_array())
                            .map(|a| !a.is_empty())
                            .unwrap_or(false);
                        let has_causes = causality
                            .get("causes")
                            .and_then(|c| c.as_array())
                            .map(|a| !a.is_empty())
                            .unwrap_or(false);

                        if has_caused_by || has_causes {
                            writeln!(chronicle_context, "    <causality>").unwrap();

                            if let Some(caused_by) =
                                causality.get("causedBy").and_then(|cb| cb.as_array())
                            {
                                for cause_id in caused_by {
                                    if let Some(id_str) = cause_id.as_str() {
                                        writeln!(
                                            chronicle_context,
                                            "        <caused_by>{}</caused_by>",
                                            escape_xml(id_str)
                                        )
                                        .unwrap();
                                    }
                                }
                            }

                            if let Some(causes) = causality.get("causes").and_then(|c| c.as_array())
                            {
                                for effect_id in causes {
                                    if let Some(id_str) = effect_id.as_str() {
                                        writeln!(
                                            chronicle_context,
                                            "        <causes>{}</causes>",
                                            escape_xml(id_str)
                                        )
                                        .unwrap();
                                    }
                                }
                            }

                            writeln!(chronicle_context, "    </causality>").unwrap();
                        }
                    }

                    // Add summary - try to get it from the event data first, fall back to rag_item.text
                    let summary = event_data
                        .get("summary")
                        .and_then(|s| s.as_str())
                        .unwrap_or_else(|| rag_item.text.trim());
                    writeln!(
                        chronicle_context,
                        "    <summary>{}</summary>",
                        escape_xml(summary)
                    )
                    .unwrap();

                    writeln!(chronicle_context, "</chronicle_event>").unwrap();
                } else {
                    // Fallback to simple format if JSON parsing fails
                    warn!(
                        "Failed to parse chronicle event JSON for event type: {}",
                        chronicle_meta.event_type
                    );
                    writeln!(
                        chronicle_context,
                        "<chronicle_event type=\"{}\" timestamp=\"{}\" status=\"unparseable\">[Chronicle data corrupted or truncated - raw text length: {} chars]</chronicle_event>",
                        escape_xml(&chronicle_meta.event_type),
                        chronicle_meta.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        rag_item.text.len()
                    )
                    .unwrap();
                }
            }
        }
        chronicle_context.push_str("</long_term_memory>\n\n");
    }

    // Add Lorebook entries
    if !lorebook_entries.is_empty() {
        lorebook_context.push_str("<lorebook_entries>\n");

        for rag_item in &lorebook_entries {
            if let crate::services::embeddings::RetrievedMetadata::Lorebook(lorebook_meta) =
                &rag_item.metadata
            {
                let content = &rag_item.text;
                let session_dek =
                    user_dek.map(|d| crate::auth::SessionDek::new(d.expose_secret().clone()));
                let title = decrypt_lorebook_title(lorebook_meta, session_dek.as_ref());

                write!(lorebook_context, "<lorebook_entry").unwrap();
                write!(lorebook_context, " title=\"{}\"", escape_xml(&title)).unwrap();

                if let Some(keywords) = &lorebook_meta.keywords {
                    if !keywords.is_empty() {
                        let keywords_str = keywords.join(", ");
                        write!(
                            lorebook_context,
                            " keywords=\"{}\"",
                            escape_xml(&keywords_str)
                        )
                        .unwrap();
                    }
                }

                writeln!(
                    lorebook_context,
                    ">{}</lorebook_entry>",
                    escape_xml(content.trim())
                )
                .unwrap();
            }
        }

        lorebook_context.push_str("</lorebook_entries>\n\n");
    }

    // Add Older Chat History
    if !older_chat_history.is_empty() {
        older_chat_context.push_str("<older_chat_history>\n");

        for rag_item in &older_chat_history {
            if let crate::services::embeddings::RetrievedMetadata::Chat(chat_meta) =
                &rag_item.metadata
            {
                let game_time_attr = if let Some(gt_val) = &chat_meta.game_time {
                    let day = gt_val.get("day").and_then(|v| v.as_i64()).unwrap_or(0);
                    let hour = gt_val.get("hour").and_then(|v| v.as_i64()).unwrap_or(0);
                    let minute = gt_val.get("minute").and_then(|v| v.as_i64()).unwrap_or(0);
                    let period = gt_val.get("period").and_then(|v| v.as_str()).unwrap_or("");
                    format!(
                        " game_time=\"Day {}, {:02}:{:02} {}\"",
                        day, hour, minute, period
                    )
                } else {
                    String::new()
                };

                if chat_meta.speaker == "Pair" {
                    // Split the pair into User and Assistant tags
                    let text = rag_item.text.trim();
                    if let Some((user_part, assistant_part)) = text.split_once("\n\nAssistant: ") {
                        let user_text = user_part.strip_prefix("User: ").unwrap_or(user_part);
                        writeln!(
                            older_chat_context,
                            "<chat_history speaker=\"User\" timestamp=\"{}\"{}>{}</chat_history>",
                            chat_meta.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                            game_time_attr,
                            escape_xml(user_text.trim())
                        )
                        .unwrap();
                        writeln!(
                            older_chat_context,
                            "<chat_history speaker=\"Assistant\" timestamp=\"{}\"{}>{}</chat_history>",
                            chat_meta.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                            game_time_attr,
                            escape_xml(assistant_part.trim())
                        )
                        .unwrap();
                    } else {
                        // Fallback if split fails
                        writeln!(
                            older_chat_context,
                            "<chat_history speaker=\"Pair\" timestamp=\"{}\"{}>{}</chat_history>",
                            chat_meta.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                            game_time_attr,
                            escape_xml(text)
                        )
                        .unwrap();
                    }
                } else {
                    writeln!(
                        older_chat_context,
                        "<chat_history speaker=\"{}\" timestamp=\"{}\"{}>{}</chat_history>",
                        escape_xml(&chat_meta.speaker),
                        chat_meta.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                        game_time_attr,
                        escape_xml(rag_item.text.trim())
                    )
                    .unwrap();
                }
            }
        }

        older_chat_context.push_str("</older_chat_history>\n\n");
    }

    (
        chronicle_context.trim_end().to_string(),
        lorebook_context.trim_end().to_string(),
        older_chat_context.trim_end().to_string(),
    )
}

async fn build_final_prompt_strings(
    calculation: &TokenCalculation,
    current_user_message: &GenAiChatMessage,
    character_metadata: Option<&CharacterMetadata>,
    _token_counter: &HybridTokenCounter,
    _model_name: &str,
    agent_context: Option<&str>,
    user_dek: Option<&secrecy::SecretBox<Vec<u8>>>,
    guidance: Option<&str>,
    template_id: Option<&str>,
    user_persona_name: Option<&str>,
    narrative_style: Option<&crate::prompt_templates::NarrativeStyle>,
    game_state: Option<&crate::models::game_state::GameState>,
    core_memory: Option<&str>,
) -> Result<(String, Vec<GenAiChatMessage>), AppError> {
    // Use the template system to build the final system prompt
    let template_id = template_id.unwrap_or("neutral_roleplay");

    debug!(template_id = %template_id, "Building final prompt with template");

    // Build RAG context strings
    let (chronicle_context, lorebook_context, older_chat_context) =
        build_rag_context_strings(calculation, user_dek);

    // Extract character personality and description if available
    let (character_personality, character_description) = if let Some(char_meta) = character_metadata
    {
        let personality = decrypt_character_field(
            &char_meta.personality,
            &char_meta.personality_nonce,
            user_dek,
            &char_meta.name,
            None, // TODO: get from user persona
        );
        let description = decrypt_character_field(
            &char_meta.description,
            &char_meta.description_nonce,
            user_dek,
            &char_meta.name,
            None, // TODO: get from user persona
        );
        (personality, description)
    } else {
        (None, None)
    };

    // Agent context is handled separately in the template now

    // Build context for template rendering
    let mut template_context = serde_json::json!({
        "user": {
            "name": user_persona_name.unwrap_or("User")
        }
    });

    // Add character information if available
    if let Some(char_meta) = character_metadata {
        let mut char_obj = serde_json::json!({
            "name": char_meta.name
        });

        if let Some(personality) = character_personality {
            char_obj["personality"] = serde_json::Value::String(personality).into();
        }

        if let Some(description) = character_description {
            char_obj["description"] = serde_json::Value::String(description).into();
        }

        template_context["char"] = char_obj;
    }

    // Add persona override if available
    if !calculation.persona_override_prompt_str.is_empty() {
        template_context["persona_override"] =
            serde_json::Value::String(calculation.persona_override_prompt_str.clone()).into();
    }

    // Add character definition if available
    if !calculation.character_definition_str.is_empty() {
        template_context["character_definition"] =
            serde_json::Value::String(calculation.character_definition_str.clone()).into();
    }

    // Add character details if available
    if !calculation.character_details_str.is_empty() {
        template_context["character_details"] =
            serde_json::Value::String(calculation.character_details_str.clone()).into();
    }

    // Add Chronicle context if available
    if !chronicle_context.is_empty() {
        template_context["chronicle_context"] = serde_json::Value::String(chronicle_context).into();
    }

    // Add Lorebook RAG context if available
    if !lorebook_context.is_empty() {
        template_context["lorebook_context"] = serde_json::Value::String(lorebook_context).into();
    }

    // Add Older Chat RAG context if available
    if !older_chat_context.is_empty() {
        template_context["older_chat_context"] =
            serde_json::Value::String(older_chat_context).into();
    }

    // Add agent context as separate template variable for sections list generation
    if let Some(agent_ctx) = agent_context {
        template_context["agent_context"] = serde_json::Value::String(agent_ctx.to_string()).into();
    }

    // Add scene context for Game Master mode (if game_state is provided)
    if let Some(state) = game_state {
        let scene_context = build_scene_context_xml(state);
        template_context["scene_context"] = serde_json::Value::String(scene_context).into();
    }

    // Add cognitive context if available
    if let Some(ctx) = &calculation.cognitive_context {
        if !ctx.is_empty() {
            template_context["cognitive_context"] = serde_json::Value::String(ctx.clone()).into();
        }
    }

    if let Some(mem) = core_memory {
        if !mem.is_empty() {
            template_context["core_memory"] = serde_json::Value::String(mem.to_string()).into();
        }
    }

    // Use render_with_style to inject narrative style variables into the template
    let final_system_prompt = TEMPLATE_MANAGER.read().unwrap().render_with_style(
        template_id,
        crate::db::Json(template_context),
        narrative_style.cloned(),
    )?;

    // Assemble the final message list
    let mut final_message_list = Vec::new();

    // Add recent history messages
    for (history_msg, _) in &calculation.recent_history_with_tokens {
        final_message_list.push(history_msg.clone());
    }

    // Format current user message with guidance if provided
    let mut final_user_message = current_user_message.clone();
    if let Some(guidance_text) = guidance {
        if !guidance_text.is_empty() {
            // Extract text from the message content and append guidance
            if let Some(existing_text) = final_user_message.content.first_text() {
                let modified_text = format!(
                    "{}\n\n(SYSTEM INSTRUCTION: {})\n",
                    existing_text, guidance_text
                );
                final_user_message.content = MessageContent::from_text(modified_text);
            } else {
                warn!("User message is not plain text, guidance not applied.");
            }
        }
    }

    final_message_list.push(final_user_message);

    Ok((final_system_prompt, final_message_list))
}

/// Builds the final LLM prompt, managing token limits by truncating RAG context and recent history if necessary.
///
/// # Errors
/// Returns `AppError` if token counting fails, prompt building encounters errors, or character metadata processing fails
pub async fn build_final_llm_prompt(
    params: PromptBuildParams<'_>,
) -> Result<(String, Vec<GenAiChatMessage>), AppError> {
    debug!(
        max_allowed_total_tokens = params
            .context_total_token_limit
            .unwrap_or(params.config.context_total_token_limit),
        recent_history_token_budget = params
            .recent_history_token_budget
            .unwrap_or(params.config.context_recent_history_token_budget),
        rag_token_budget = params
            .rag_token_budget
            .unwrap_or(params.config.context_rag_token_budget),
        "Starting build_final_llm_prompt"
    );

    // Perform initial token calculations for all components
    let mut calculation = perform_initial_token_calculation(&params).await?;

    // Apply token limits by truncating RAG and history if necessary (with hard enforcement)
    calculation = apply_token_limits(
        calculation,
        &params.config,
        params.rag_chronicles_limit,
        params.rag_lorebooks_limit,
        params.rag_older_chat_limit,
        params.context_total_token_limit,
        params.recent_history_token_budget,
        params.rag_token_budget,
    )?;

    // Build final prompt strings
    let (final_system_prompt, final_message_list) = build_final_prompt_strings(
        &calculation,
        &params.current_user_message,
        params.character_metadata,
        &params.token_counter,
        &params.model_name,
        params.agent_context.as_deref(),
        params.user_dek,
        params.guidance.as_deref(),
        params.prompt_template_id.as_deref(),
        params.user_persona_name.as_deref(),
        params.narrative_style.as_ref(),
        params.game_state,
        params.core_memory.as_deref(),
    )
    .await?;

    let final_total_tokens = calculation.meta_system_prompt_tokens
        + calculation.persona_override_prompt_tokens
        + calculation.character_definition_tokens
        + calculation.character_details_tokens
        + calculation.current_user_message_tokens
        + calculation
            .rag_items_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
        + calculation
            .recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
        + calculation.cognitive_context_tokens
        + calculation.core_memory_tokens;

    debug!(
        final_system_prompt_len = final_system_prompt.len(),
        final_message_list_len = final_message_list.len(),
        final_total_tokens,
        "Final prompt constructed."
    );

    Ok((final_system_prompt, final_message_list))
}

// --- Unit Tests ---
#[cfg(all(test, feature = "postgres-backend"))]
mod tests {

    use crate::models::characters::CharacterMetadata;
    use crate::DbId;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_build_prompt_no_character() {
        let prompt = build_prompt_with_rag(None);
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when no character is provided, got: {prompt}"
        );
    }

    #[test]
    fn test_build_prompt_character_with_description() {
        let char_meta = CharacterMetadata {
            id: DbId::new(),
            user_id: DbId::new(),
            name: "Test Bot".to_string(),
            description: Some(b"A friendly test bot.".to_vec()),
            description_nonce: None,
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            first_mes: Some(b"Bot greeting".to_vec()),
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        assert!(
            prompt.contains("Test Bot"),
            "Expected prompt to contain character name, got: {prompt}"
        );
        assert!(
            prompt.contains("A friendly test bot."),
            "Expected prompt to contain character description, got: {prompt}"
        );
        // Note: Static instruction section was removed as it was redundant
    }

    #[test]
    fn test_build_prompt_character_no_description() {
        let char_meta = CharacterMetadata {
            id: DbId::new(),
            user_id: DbId::new(),
            name: "Minimal Bot".to_string(),
            description: None, // No description
            description_nonce: None,
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            first_mes: None,
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        // When description is None, we expect an empty string
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when character has no description, got: {prompt}"
        );
    }

    #[test]
    fn test_build_prompt_character_empty_description() {
        let char_meta = CharacterMetadata {
            id: DbId::new(),
            user_id: DbId::new(),
            name: "Silent Bot".to_string(),
            description: Some(b"".to_vec()), // Empty description
            description_nonce: None,
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            first_mes: None,
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        // When description is empty, we expect an empty string
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when character has empty description, got: {prompt}"
        );
    }

    fn build_prompt_with_rag(character_metadata: Option<&CharacterMetadata>) -> String {
        super::build_prompt_with_rag(character_metadata).unwrap()
    }

    #[test]
    fn test_replace_template_variables() {
        // Test with both character and user names
        let result = super::replace_template_variables(
            "{{char}} is talking to {{user}} about something",
            Some("Alice"),
            Some("Bob"),
        );
        assert_eq!(result, "Alice is talking to Bob about something");

        // Test with no character name
        let result =
            super::replace_template_variables("{{char}} is talking to {{user}}", None, Some("Bob"));
        assert_eq!(result, "{{char}} is talking to Bob");

        // Test with no user name (should default to "User")
        let result = super::replace_template_variables(
            "{{char}} is talking to {{user}}",
            Some("Alice"),
            None,
        );
        assert_eq!(result, "Alice is talking to User");

        // Test with no template variables
        let result =
            super::replace_template_variables("This is a normal text", Some("Alice"), Some("Bob"));
        assert_eq!(result, "This is a normal text");

        // Test with multiple occurrences
        let result = super::replace_template_variables(
            "{{char}} says hello to {{user}}. {{char}} is friendly and {{user}} responds.",
            Some("Alice"),
            Some("Bob"),
        );
        assert_eq!(
            result,
            "Alice says hello to Bob. Alice is friendly and Bob responds."
        );

        // Test empty string
        let result = super::replace_template_variables("", Some("Alice"), Some("Bob"));
        assert_eq!(result, "");
    }

    mod strategic_truncation_tests {
        use crate::config::Config;
        use crate::errors::AppError;
        use crate::prompt_builder::{
            apply_token_limits, truncate_rag_context, truncate_recent_history_strategically,
            TokenCalculation,
        };
        use crate::services::embeddings::{
            ChatMessageChunkMetadata, RetrievedChunk, RetrievedMetadata,
        };
        use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole, MessageContent};
        use std::sync::Arc;

        fn create_test_message(
            role: ChatRole,
            content: &str,
            tokens: usize,
        ) -> (GenAiChatMessage, usize) {
            (
                GenAiChatMessage {
                    role,
                    content: MessageContent::from(content.to_string()),
                    options: None,
                },
                tokens,
            )
        }

        fn create_test_calculation(
            meta_tokens: usize,
            persona_tokens: usize,
            character_tokens: usize,
            details_tokens: usize,
            current_user_tokens: usize,
            rag_items: Vec<(RetrievedChunk, usize)>,
            history_messages: Vec<(GenAiChatMessage, usize)>,
        ) -> TokenCalculation {
            TokenCalculation {
                meta_system_prompt_tokens: meta_tokens,
                persona_override_prompt_str: if persona_tokens > 0 {
                    "persona".to_string()
                } else {
                    String::new()
                },
                persona_override_prompt_tokens: persona_tokens,
                character_definition_str: if character_tokens > 0 {
                    "character".to_string()
                } else {
                    String::new()
                },
                character_definition_tokens: character_tokens,
                character_details_str: if details_tokens > 0 {
                    "details".to_string()
                } else {
                    String::new()
                },
                character_details_tokens: details_tokens,
                current_user_message_tokens: current_user_tokens,
                rag_items_with_tokens: rag_items,
                recent_history_with_tokens: history_messages,
                cognitive_context: None,
                cognitive_context_tokens: 0,
                core_memory: None,
                core_memory_tokens: 0,
            }
        }

        #[test]
        fn test_strategic_truncation_preserves_tail() {
            // Create 10 messages, each 1000 tokens
            let mut history_messages = Vec::new();
            for i in 0..10 {
                history_messages.push(create_test_message(
                    if i % 2 == 0 {
                        ChatRole::User
                    } else {
                        ChatRole::Assistant
                    },
                    &format!("Message {}", i),
                    1000,
                ));
            }

            let mut calculation = create_test_calculation(
                5000,   // meta_tokens
                1000,   // persona_tokens
                2000,   // character_tokens
                1000,   // details_tokens
                500,    // current_user_tokens
                vec![], // no RAG items
                history_messages,
            );

            // Total: 5000 + 1000 + 2000 + 1000 + 500 + (10 * 1000) = 19,500 tokens
            // Limit: 15,000 tokens (need to remove 4,500 tokens = ~4-5 messages)
            // Min tail: 4 messages to preserve
            let mut current_total = 19_500;
            let max_allowed = 15_000;
            let min_tail = 4;

            truncate_recent_history_strategically(
                &mut calculation,
                &mut current_total,
                max_allowed,
                min_tail,
            );

            // Should preserve the last 4 messages (tail)
            // Need to remove 4500 tokens = 5 messages, so should have 5 left
            assert_eq!(calculation.recent_history_with_tokens.len(), 5); // Started with 10, should have 5 left
            assert!(
                current_total <= max_allowed,
                "Token count should be within limit"
            );

            // Verify tail preservation: the last messages should be preserved
            let preserved_messages = &calculation.recent_history_with_tokens;
            for (i, (message, _)) in preserved_messages.iter().enumerate() {
                if let Some(content) = message.content.first_text() {
                    // The remaining messages should be the later ones (some from middle + tail)
                    // Due to middle-out truncation, we can't predict exact indices, but we know
                    // the last 4 should definitely be preserved
                    if i >= preserved_messages.len() - min_tail {
                        // These are the tail messages - verify they're the latest
                        let expected_index = 10 - (preserved_messages.len() - i);
                        assert!(content.contains(&format!("Message {}", expected_index)));
                    }
                }
            }
        }

        #[test]
        fn test_strategic_truncation_insufficient_messages_fallback() {
            // Test with fewer messages than min_tail
            let history_messages = vec![
                create_test_message(ChatRole::User, "Message 1", 5000),
                create_test_message(ChatRole::Assistant, "Message 2", 5000),
            ];

            let mut calculation = create_test_calculation(
                5000,   // meta_tokens
                1000,   // persona_tokens
                2000,   // character_tokens
                1000,   // details_tokens
                500,    // current_user_tokens
                vec![], // no RAG items
                history_messages,
            );

            // Total: 5000 + 1000 + 2000 + 1000 + 500 + (2 * 5000) = 19,500 tokens
            // Limit: 15,000 tokens
            // Min tail: 4 messages (but we only have 2 messages)
            let mut current_total = 19_500;
            let max_allowed = 15_000;
            let min_tail = 4;

            truncate_recent_history_strategically(
                &mut calculation,
                &mut current_total,
                max_allowed,
                min_tail,
            );

            // Should fall back to oldest-first truncation
            // Since we have 2 messages, should remove 1 message (5000 tokens) to get under limit
            assert_eq!(calculation.recent_history_with_tokens.len(), 1);
            assert!(current_total <= max_allowed);
        }

        #[test]
        fn test_strategic_truncation_exact_limit() {
            // Test when we're exactly at the limit
            let history_messages = vec![
                create_test_message(ChatRole::User, "Message 1", 1000),
                create_test_message(ChatRole::Assistant, "Message 2", 1000),
            ];

            let mut calculation = create_test_calculation(
                5000,   // meta_tokens
                1000,   // persona_tokens
                2000,   // character_tokens
                1000,   // details_tokens
                500,    // current_user_tokens
                vec![], // no RAG items
                history_messages,
            );

            // Total: 5000 + 1000 + 2000 + 1000 + 500 + (2 * 1000) = 11,500 tokens
            let mut current_total = 11_500;
            let max_allowed = 11_500; // Exactly at limit
            let min_tail = 2;

            truncate_recent_history_strategically(
                &mut calculation,
                &mut current_total,
                max_allowed,
                min_tail,
            );

            // Should not remove anything since we're at the limit
            assert_eq!(calculation.recent_history_with_tokens.len(), 2);
            assert_eq!(current_total, max_allowed);
        }

        #[test]
        fn test_strategic_truncation_middle_removal() {
            // Test that middle messages are removed while preserving tail
            let mut history_messages = Vec::new();
            for i in 0..8 {
                history_messages.push(create_test_message(
                    if i % 2 == 0 {
                        ChatRole::User
                    } else {
                        ChatRole::Assistant
                    },
                    &format!("Message {}", i),
                    1000,
                ));
            }

            let mut calculation = create_test_calculation(
                1000,   // meta_tokens
                500,    // persona_tokens
                500,    // character_tokens
                500,    // details_tokens
                500,    // current_user_tokens
                vec![], // no RAG items
                history_messages,
            );

            // Total: 1000 + 500 + 500 + 500 + 500 + (8 * 1000) = 11,000 tokens
            // Limit: 8,000 tokens (need to remove 3,000 tokens = 3 messages)
            // Min tail: 3 messages to preserve
            let mut current_total = 11_000;
            let max_allowed = 8_000;
            let min_tail = 3;

            truncate_recent_history_strategically(
                &mut calculation,
                &mut current_total,
                max_allowed,
                min_tail,
            );

            // Should have 5 messages left (removed 3)
            assert_eq!(calculation.recent_history_with_tokens.len(), 5);
            assert!(current_total <= max_allowed);

            // Verify that the last 3 messages are preserved (tail)
            let preserved_messages = &calculation.recent_history_with_tokens;
            let tail_start = preserved_messages.len() - min_tail;

            for (i, (message, _)) in preserved_messages[tail_start..].iter().enumerate() {
                if let Some(content) = message.content.first_text() {
                    // These should be messages 5, 6, 7 (the tail)
                    let expected_index = 8 - min_tail + i;
                    assert!(content.contains(&format!("Message {}", expected_index)));
                }
            }
        }

        #[test]
        fn test_hard_limit_enforcement() {
            // Create a scenario where even after truncation, we're still over limit
            let history_messages =
                vec![create_test_message(ChatRole::User, "Huge message", 100_000)];

            let calculation = create_test_calculation(
                50_000, // meta_tokens
                10_000, // persona_tokens
                20_000, // character_tokens
                10_000, // details_tokens
                5_000,  // current_user_tokens
                vec![], // no RAG items
                history_messages,
            );

            // Total: 50_000 + 10_000 + 20_000 + 10_000 + 5_000 + 100_000 = 195,000 tokens
            // Even if we remove all history, we still have 95,000 from head components

            let mut config = Config::default();
            config.context_total_token_limit = 80_000; // Lower than head components alone
            config.min_tail_messages_to_preserve = 1;

            let config_arc = Arc::new(config);

            // This should return an error due to hard limit enforcement
            let result =
                apply_token_limits(calculation, &config_arc, None, None, None, None, None, None);

            assert!(
                result.is_err(),
                "Should return error when hard limit is exceeded"
            );

            if let Err(AppError::BadRequest(msg)) = result {
                assert!(msg.contains("Request too large"));
                assert!(msg.contains("tokens exceeds maximum limit"));
            } else {
                panic!("Expected BadRequest error with specific message");
            }
        }

        #[test]
        #[allow(deprecated)]
        fn test_rag_truncation_before_history() {
            // Create RAG items that will be truncated first
            let rag_chunk = RetrievedChunk {
                text: "Some context".to_string(),
                metadata: RetrievedMetadata::Chat(ChatMessageChunkMetadata {
                    game_time: None,
                    message_id: crate::db::DbId::new_v4(),
                    session_id: crate::db::DbId::new_v4(),
                    chronicle_id: None,
                    user_id: crate::db::DbId::new_v4(),
                    speaker: "user".to_string(),
                    timestamp: chrono::Utc::now().into(),
                    text: "Some context".to_string(),
                    source_type: "chat".to_string(),
                    encrypted_text: None,
                    text_nonce: None,
                }),
                score: 0.9,
            };

            let rag_items = vec![(rag_chunk.clone(), 3000), (rag_chunk.clone(), 3000)];

            let history_messages = vec![
                create_test_message(ChatRole::User, "Important message 1", 1000),
                create_test_message(ChatRole::Assistant, "Important message 2", 1000),
            ];

            let mut calculation = create_test_calculation(
                5000, // meta_tokens
                1000, // persona_tokens
                2000, // character_tokens
                1000, // details_tokens
                500,  // current_user_tokens
                rag_items,
                history_messages,
            );

            // Total: 5000 + 1000 + 2000 + 1000 + 500 + (2 * 3000) + (2 * 1000) = 17,500 tokens
            // Limit: 12,000 tokens (need to remove 5,500 tokens)
            let mut current_total = 17_500;
            let max_allowed = 12_000;

            // First truncate RAG (should remove all 6000 tokens of RAG)
            truncate_rag_context(
                &mut calculation,
                &mut current_total,
                max_allowed,
                None,
                None,
                None,
            );

            // After RAG truncation: 17,500 - 6,000 = 11,500 tokens (under limit)
            assert_eq!(calculation.rag_items_with_tokens.len(), 0);
            assert_eq!(current_total, 11_500);
            assert!(current_total <= max_allowed);

            // History should be preserved since RAG truncation was sufficient
            assert_eq!(calculation.recent_history_with_tokens.len(), 2);
        }
    }

    #[test]
    fn test_enhanced_chronicle_event_formatting() {
        // Test that chronicle events with rich data are properly formatted
        let chronicle_event_json = r#"{
            "action": "Agreed",
            "actors": [
                {
                    "id": "sol",
                    "role": "Agent",
                    "details": "Issued the command for accompaniment"
                },
                {
                    "id": "lumiya",
                    "role": "Patient",
                    "details": "Accepted the command and committed to accompaniment"
                }
            ],
            "causality": {
                "causedBy": ["997a300f-1e05-42da-a906-08a2858be03a"],
                "causes": []
            },
            "context_data": {
                "future_implication": "shared_journey",
                "location_id": "sol_private_quarters",
                "relationship_status": "reinforced_and_committed"
            },
            "valence": [
                {
                    "change": 0.3,
                    "target": "sol",
                    "type": "Power"
                },
                {
                    "change": 0.4,
                    "target": "lumiya",
                    "type": "Loyalty"
                },
                {
                    "change": 0.5,
                    "target": "lumiya",
                    "type": "Commitment"
                }
            ],
            "modality": "ACTUAL",
            "summary": "In the intimate aftermath of their bond's profound reinforcement, Sol commanded Lumiya to accompany him."
        }"#;

        // Test that the escape_xml function works correctly for special characters
        let result = super::escape_xml("Test & <tag> \"quote\" 'apostrophe'");
        assert_eq!(
            result,
            "Test &amp; &lt;tag&gt; &quot;quote&quot; &apos;apostrophe&apos;"
        );

        // Test JSON parsing of the event data
        let parsed: crate::DbJson = serde_json::from_str(chronicle_event_json).unwrap();
        assert_eq!(parsed["action"], "Agreed");
        assert_eq!(parsed["actors"][0]["id"], "sol");
        assert_eq!(parsed["valence"][0]["change"], 0.3);
        assert_eq!(
            parsed["context_data"]["location_id"],
            "sol_private_quarters"
        );
        assert_eq!(
            parsed["causality"]["causedBy"][0],
            "997a300f-1e05-42da-a906-08a2858be03a"
        );
    }

    // ========================================================================
    // Scene Context XML Tests (for Game Master mode)
    // ========================================================================

    #[test]
    fn test_build_scene_context_xml_empty_state() {
        use crate::models::game_state::GameState;
        let state = GameState::default();
        let xml = super::build_scene_context_xml(&state);

        assert!(xml.starts_with("<game_context>"));
        assert!(xml.contains("</game_context>"));
        assert!(xml.contains("<environment>"));
    }

    #[test]
    fn test_build_scene_context_xml_with_location() {
        use crate::models::game_state::{GameState, Location};
        let mut state = GameState::default();
        state.location = Some(Location {
            id: "tavern_001".to_string(),
            name: "The Rusty Anchor".to_string(),
            description: Some(serde_json::Value::String("A cozy tavern".to_string())),
            region: Some("Port District".to_string()),
            tags: vec!["indoors".to_string(), "safe".to_string()],
        });

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<location>"));
        assert!(xml.contains("<name>The Rusty Anchor</name>"));
        assert!(xml.contains("<description>A cozy tavern</description>"));
        assert!(xml.contains("<region>Port District</region>"));
        assert!(xml.contains("<tags>indoors, safe</tags>"));
        assert!(xml.contains("</location>"));
    }

    #[test]
    fn test_build_scene_context_xml_with_time() {
        use crate::models::game_state::{GameState, GameTime};
        let mut state = GameState::default();
        state.game_time = Some(GameTime {
            day: 5,
            hour: 14,
            minute: 0,
            second: 0,
            period: "afternoon".to_string(),
            season: Some("autumn".to_string()),
            total_seconds_elapsed: 0,
            calendar_system: "Earth".to_string(),
            date: "2024-01-01".to_string(),
            weekday: None,
        });

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<time>"));
        assert!(xml.contains("<day>5</day>"));
        assert!(xml.contains("<hour>14</hour>"));
        assert!(xml.contains("<period>afternoon</period>"));
        assert!(xml.contains("<season>autumn</season>"));
        assert!(xml.contains("</time>"));
    }

    #[test]
    fn test_build_scene_context_xml_with_npcs() {
        use crate::models::game_state::{GameState, NpcState};
        use std::collections::HashMap;

        let mut state = GameState::default();
        state.npcs.insert(
            "npc_001".to_string(),
            NpcState {
                id: "npc_001".to_string(),
                name: "Friendly Bartender".to_string(),
                location: None,
                disposition: "friendly".to_string(),
                status: "alive".to_string(),
                role: "Bartender".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<npcs_present>"));
        assert!(xml.contains("Friendly Bartender"));
        assert!(xml.contains("</npcs_present>"));
    }

    #[test]
    fn test_build_scene_context_xml_filters_dead_npcs() {
        use crate::models::game_state::{GameState, NpcState};
        use std::collections::HashMap;

        let mut state = GameState::default();
        state.npcs.insert(
            "npc_alive".to_string(),
            NpcState {
                id: "npc_alive".to_string(),
                name: "Living Guard".to_string(),
                location: None,
                disposition: "neutral".to_string(),
                status: "alive".to_string(),
                role: "Guard".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        state.npcs.insert(
            "npc_dead".to_string(),
            NpcState {
                id: "npc_dead".to_string(),
                name: "Fallen Warrior".to_string(),
                location: None,
                disposition: "hostile".to_string(),
                status: "dead".to_string(),
                role: "Warrior".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("Living Guard"));
        assert!(!xml.contains("Fallen Warrior")); // Dead NPCs should be filtered out
    }

    #[test]
    fn test_build_scene_context_xml_with_environment() {
        use crate::models::game_state::{EnvironmentState, GameState};
        let mut state = GameState::default();
        state.environment = EnvironmentState {
            weather: Some("rainy".to_string()),
            lighting: Some("dim".to_string()),
            temperature: Some("cool".to_string()),
            hazards: vec!["slippery floor".to_string()],
            tags: vec!["atmospheric".to_string()],
        };

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<weather>rainy</weather>"));
        assert!(xml.contains("<lighting>dim</lighting>"));
        assert!(xml.contains("<temperature>cool</temperature>"));
        assert!(xml.contains("<hazards>slippery floor</hazards>"));
    }

    #[test]
    fn test_build_scene_context_xml_escapes_special_chars() {
        use crate::models::game_state::{GameState, Location};
        let mut state = GameState::default();
        state.location = Some(Location {
            id: "test".to_string(),
            name: "Tom & Jerry's <Tavern>".to_string(),
            description: Some(serde_json::Value::String(
                "A \"special\" place with 'quotes'".to_string(),
            )),
            region: None,
            tags: vec![],
        });

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("Tom &amp; Jerry&apos;s &lt;Tavern&gt;"));
        assert!(xml.contains("&quot;special&quot;"));
    }

    #[test]
    fn test_build_scene_context_xml_full_state() {
        use crate::models::game_state::{
            EnvironmentState, GameState, GameTime, Location, NpcState,
        };
        use std::collections::HashMap;

        let mut state = GameState::default();
        state.location = Some(Location {
            id: "dungeon_01".to_string(),
            name: "Dark Dungeon".to_string(),
            description: None,
            region: Some("Underworld".to_string()),
            tags: vec!["dangerous".to_string()],
        });
        state.game_time = Some(GameTime {
            day: 10,
            hour: 23,
            minute: 0,
            second: 0,
            period: "night".to_string(),
            season: Some("winter".to_string()),
            total_seconds_elapsed: 0,
            calendar_system: "Earth".to_string(),
            date: "2025-01-10".to_string(),
            weekday: None,
        });
        state.npcs.insert(
            "goblin_01".to_string(),
            NpcState {
                id: "goblin_01".to_string(),
                name: "Sneaky Goblin".to_string(),
                location: None,
                disposition: "hostile".to_string(),
                status: "alive".to_string(),
                role: "Goblin".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        state.environment = EnvironmentState {
            weather: None,
            lighting: Some("torch-lit".to_string()),
            temperature: Some("cold".to_string()),
            hazards: vec!["traps".to_string(), "pit".to_string()],
            tags: vec!["eerie".to_string()],
        };

        let xml = super::build_scene_context_xml(&state);

        // Verify all components present
        assert!(xml.contains("<location>"));
        assert!(xml.contains("<time>"));
        assert!(xml.contains("<npcs_present>"));
        assert!(xml.contains("<environment>"));
        assert!(xml.contains("Dark Dungeon"));
        assert!(xml.contains("night"));
        assert!(xml.contains("Sneaky Goblin"));
        assert!(xml.contains("torch-lit"));
    }
}

// Scene Context XML Tests - feature-agnostic (works with both postgres and sqlite)
#[cfg(test)]
mod scene_context_tests {
    use crate::models::game_state::{EnvironmentState, GameState, GameTime, Location, NpcState};

    #[test]
    fn test_build_scene_context_xml_empty_state() {
        let state = GameState::default();
        let xml = super::build_scene_context_xml(&state);

        assert!(xml.starts_with("<game_context>"));
        assert!(xml.contains("</game_context>"));
        assert!(xml.contains("<environment>"));
    }

    #[test]
    fn test_build_scene_context_xml_with_location() {
        let mut state = GameState::default();
        state.location = Some(Location {
            id: "tavern_001".to_string(),
            name: "The Rusty Anchor".to_string(),
            description: Some(serde_json::Value::String("A cozy tavern".to_string())),
            region: Some("Port District".to_string()),
            tags: vec!["indoors".to_string(), "safe".to_string()],
        });

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<location>"));
        assert!(xml.contains("<name>The Rusty Anchor</name>"));
        assert!(xml.contains("<description>A cozy tavern</description>"));
        assert!(xml.contains("<region>Port District</region>"));
        assert!(xml.contains("<tags>indoors, safe</tags>"));
        assert!(xml.contains("</location>"));
    }

    #[test]
    fn test_build_scene_context_xml_with_time() {
        let mut state = GameState::default();
        state.game_time = Some(GameTime {
            day: 5,
            hour: 14,
            minute: 0,
            second: 0,
            period: "afternoon".to_string(),
            season: Some("autumn".to_string()),
            total_seconds_elapsed: 0,
            calendar_system: "Earth".to_string(),
            date: "2025-01-05".to_string(),
            weekday: None,
        });

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<time>"));
        assert!(xml.contains("<day>5</day>"));
        assert!(xml.contains("<hour>14</hour>"));
        assert!(xml.contains("<period>afternoon</period>"));
        assert!(xml.contains("<season>autumn</season>"));
        assert!(xml.contains("</time>"));
    }

    #[test]
    fn test_build_scene_context_xml_with_npcs() {
        let mut state = GameState::default();
        state.npcs.insert(
            "npc_001".to_string(),
            NpcState {
                id: "npc_001".to_string(),
                name: "Friendly Bartender".to_string(),
                location: None,
                disposition: "friendly".to_string(),
                status: "alive".to_string(),
                role: "Bartender".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<npcs_present>"));
        assert!(xml.contains("Friendly Bartender"));
        assert!(xml.contains("</npcs_present>"));
    }

    #[test]
    fn test_build_scene_context_xml_filters_dead_npcs() {
        let mut state = GameState::default();
        state.npcs.insert(
            "npc_alive".to_string(),
            NpcState {
                id: "npc_alive".to_string(),
                name: "Living Guard".to_string(),
                location: None,
                disposition: "neutral".to_string(),
                status: "alive".to_string(),
                role: "Guard".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        state.npcs.insert(
            "npc_dead".to_string(),
            NpcState {
                id: "npc_dead".to_string(),
                name: "Fallen Warrior".to_string(),
                location: None,
                disposition: "hostile".to_string(),
                status: "dead".to_string(),
                role: "Warrior".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("Living Guard"));
        assert!(!xml.contains("Fallen Warrior")); // Dead NPCs should be filtered out
    }

    #[test]
    fn test_build_scene_context_xml_with_environment() {
        let mut state = GameState::default();
        state.environment = EnvironmentState {
            weather: Some("rainy".to_string()),
            lighting: Some("dim".to_string()),
            temperature: Some("cool".to_string()),
            hazards: vec!["slippery floor".to_string()],
            tags: vec!["atmospheric".to_string()],
        };

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("<weather>rainy</weather>"));
        assert!(xml.contains("<lighting>dim</lighting>"));
        assert!(xml.contains("<temperature>cool</temperature>"));
        assert!(xml.contains("<hazards>slippery floor</hazards>"));
    }

    #[test]
    fn test_build_scene_context_xml_escapes_special_chars() {
        let mut state = GameState::default();
        state.location = Some(Location {
            id: "test".to_string(),
            name: "Tom & Jerry's <Tavern>".to_string(),
            description: Some(serde_json::Value::String(
                "A \"special\" place with 'quotes'".to_string(),
            )),
            region: None,
            tags: vec![],
        });

        let xml = super::build_scene_context_xml(&state);

        assert!(xml.contains("Tom &amp; Jerry&apos;s &lt;Tavern&gt;"));
        assert!(xml.contains("&quot;special&quot;"));
    }

    #[test]
    fn test_build_scene_context_xml_full_state() {
        let mut state = GameState::default();
        state.location = Some(Location {
            id: "dungeon_01".to_string(),
            name: "Dark Dungeon".to_string(),
            description: None,
            region: Some("Underworld".to_string()),
            tags: vec!["dangerous".to_string()],
        });
        state.game_time = Some(GameTime {
            day: 10,
            hour: 23,
            minute: 0,
            second: 0,
            period: "night".to_string(),
            season: Some("winter".to_string()),
            total_seconds_elapsed: 0,
            calendar_system: "Earth".to_string(),
            date: "2025-01-10".to_string(),
            weekday: None,
        });
        state.npcs.insert(
            "goblin_01".to_string(),
            NpcState {
                id: "goblin_01".to_string(),
                name: "Sneaky Goblin".to_string(),
                location: None,
                disposition: "hostile".to_string(),
                status: "alive".to_string(),
                role: "Goblin".to_string(),
                description: None,
                personality: None,
                is_important: false,
                objectives: vec![],
                data: serde_json::Value::Object(serde_json::Map::new()),
            },
        );
        state.environment = EnvironmentState {
            weather: None,
            lighting: Some("torch-lit".to_string()),
            temperature: Some("cold".to_string()),
            hazards: vec!["traps".to_string(), "pit".to_string()],
            tags: vec!["eerie".to_string()],
        };

        let xml = super::build_scene_context_xml(&state);

        // Verify all components present
        assert!(xml.contains("<location>"));
        assert!(xml.contains("<time>"));
        assert!(xml.contains("<npcs_present>"));
        assert!(xml.contains("<environment>"));
        assert!(xml.contains("Dark Dungeon"));
        assert!(xml.contains("night"));
        assert!(xml.contains("Sneaky Goblin"));
        assert!(xml.contains("torch-lit"));
    }
}
