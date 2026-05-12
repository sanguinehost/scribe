use crate::{IntelligenceClient, IntelligenceCompletionRequest, IntelligenceChatResponse, IntelligenceStreamEvent, IntelligenceError};
use async_trait::async_trait;
use rig::providers::gemini;
use rig::client::{ProviderClient, CompletionClient};
use rig::completion::CompletionModel;
use rig::one_or_many::OneOrMany;
use rig::message::Message;
use std::pin::Pin;
use futures::Stream;

pub struct RigIntelligenceClient {
    api_key: Option<String>,
    default_model: String,
}

impl RigIntelligenceClient {
    pub fn new(api_key: Option<String>, default_model: String) -> Self {
        Self { api_key, default_model }
    }

    fn map_history(history: Vec<serde_json::Value>) -> Result<Vec<Message>, IntelligenceError> {
        history.into_iter()
            .map(|v| serde_json::from_value(v).map_err(|e| IntelligenceError::Internal(format!("Failed to parse history message: {}", e))))
            .collect()
    }
}

#[async_trait]
impl IntelligenceClient for RigIntelligenceClient {
    async fn completion(&self, req: IntelligenceCompletionRequest) -> Result<IntelligenceChatResponse, IntelligenceError> {
        // Implementation based on rig_client.rs logic
        match req.provider.as_str() {
            "gemini" => {
                let client = if let Some(key) = &self.api_key {
                    gemini::Client::new(key).map_err(|e| IntelligenceError::ProviderError(e.to_string()))?
                } else {
                    gemini::Client::from_env().map_err(|e| IntelligenceError::ProviderError(e.to_string()))?
                };

                let model_name = if req.model_name.is_empty() {
                    &self.default_model
                } else {
                    &req.model_name
                };

                let model = client.completion_model(model_name);
                let mut full_history = Self::map_history(req.history)?;
                
                if !req.prompt.is_empty() {
                    full_history.push(Message::User {
                        content: OneOrMany::one(rig::message::UserContent::text(req.prompt)),
                    });
                }

                let chat_history = OneOrMany::many(full_history)
                    .map_err(|_| IntelligenceError::Internal("History cannot be empty".to_string()))?;

                let mut additional_params = serde_json::Map::new();
                if let Some(budget) = req.reasoning_budget {
                    let mut thinking_config = serde_json::Map::new();
                    thinking_config.insert("includeThoughts".to_string(), serde_json::json!(true));
                    let effective_budget = if budget == -1 { 32768 } else { budget };
                    thinking_config.insert("thinkingBudget".to_string(), serde_json::json!(effective_budget));
                    if let Some(level) = &req.thinking_level {
                        if level != "dynamic" && !level.is_empty() {
                            thinking_config.insert("thinkingLevel".to_string(), serde_json::json!(level));
                        }
                    }
                    additional_params.insert("generationConfig".to_string(), serde_json::json!({ "thinkingConfig": thinking_config }));
                }

                let rig_req = rig::completion::CompletionRequest {
                    model: Some(model_name.to_string()),
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() { None } else { Some(serde_json::Value::Object(additional_params)) },
                    tool_choice: None,
                    output_schema: None,
                };

                let response = model.completion(rig_req).await
                    .map_err(|e| IntelligenceError::ProviderError(e.to_string()))?;

                let content = response.choice.iter().find_map(|c| match c {
                    rig::completion::AssistantContent::Text(t) => Some(t.text.clone()),
                    _ => None,
                }).ok_or_else(|| IntelligenceError::Internal("No text response".to_string()))?;

                Ok(IntelligenceChatResponse {
                    content,
                    prompt_tokens: Some(response.usage.input_tokens),
                    completion_tokens: Some(response.usage.output_tokens),
                    total_tokens: Some(response.usage.input_tokens + response.usage.output_tokens),
                    reasoning_content: None, // Logic for extraction can be added here
                })
            }
            _ => Err(IntelligenceError::ProviderError(format!("Unsupported provider: {}", req.provider))),
        }
    }

    async fn completion_stream(&self, _req: IntelligenceCompletionRequest) -> Result<Pin<Box<dyn Stream<Item = Result<IntelligenceStreamEvent, IntelligenceError>> + Send>>, IntelligenceError> {
        // Implementation for streaming...
        Err(IntelligenceError::Internal("Stream not yet implemented in migrated client".to_string()))
    }
}
