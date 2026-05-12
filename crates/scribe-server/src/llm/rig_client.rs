use super::AiClient;
use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::client::ProviderClient;
use rig::completion::CompletionModel;
use rig::one_or_many::OneOrMany;
use rig::providers::gemini;

#[derive(Debug, Clone, Default)]
pub struct RigCompletionRequest {
    pub model_name: String,
    pub provider: String, // "gemini", "ollama", etc.
    pub prompt: String,
    pub preamble: Option<String>,
    pub history: Vec<rig::message::Message>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub max_tokens: Option<i32>,
    pub reasoning_budget: Option<i32>,
    pub thinking_level: Option<String>,
    pub capture_reasoning_content: bool,
    pub safety_settings: Option<Vec<serde_json::Value>>, // Use Value for flexibility across providers
}

#[derive(Debug, Clone)]
pub enum RigStreamEvent {
    Content(String),
    Reasoning(String),
    ToolCall {
        id: String,
        name: String,
        arguments: serde_json::Value,
    },
    TokenUsage {
        input_tokens: u64,
        output_tokens: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RigChatResponse {
    pub content: String,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub reasoning_content: Option<String>,
}

use crate::services::ai::mistralrs_service::MistralRsService;
use std::sync::Arc;

/// Wrapper around Rig's completion models to provide a unified interface
/// for Scribe's chat service.
#[derive(Clone)]
pub struct RigClient {
    api_key: Option<String>,
    mistralrs: Option<Arc<MistralRsService>>,
    default_provider: String,
    model: Option<String>,
}

impl RigClient {
    pub fn new(api_key: Option<String>, model: Option<String>) -> Self {
        let api_key = api_key.map(|k| k.trim().to_string());

        Self {
            api_key,
            mistralrs: None,
            default_provider: "gemini".to_string(),
            model,
        }
    }

    pub fn with_mistralrs(mut self, mistralrs: Arc<MistralRsService>) -> Self {
        self.mistralrs = Some(mistralrs);
        self
    }

    pub fn with_provider(mut self, provider: String) -> Self {
        self.default_provider = provider;
        self
    }

    pub async fn completion(
        &self,
        req: RigCompletionRequest,
    ) -> Result<RigChatResponse, anyhow::Error> {
        match req.provider.as_str() {
            "gemini" => {
                let client = if let Some(key) = &self.api_key {
                    gemini::Client::new(key)?
                } else {
                    gemini::Client::from_env()?
                };

                let model_name = if req.model_name.is_empty() {
                    self.model.as_deref().unwrap_or("gemini-1.5-pro")
                } else {
                    &req.model_name
                };

                let model = client.completion_model(model_name);

                // Combine history and optional prompt
                let mut full_history = req.history;
                if !req.prompt.is_empty() {
                    let prompt_msg = rig::message::Message::User {
                        content: OneOrMany::one(rig::message::UserContent::text(req.prompt)),
                    };
                    full_history.push(prompt_msg);
                }

                let chat_history = OneOrMany::many(full_history)
                    .map_err(|_| anyhow::anyhow!("History cannot be empty"))?;

                tracing::debug!("RigClient: completion request - model: {}, reasoning_budget: {:?}, thinking_level: {:?}", req.model_name, req.reasoning_budget, req.thinking_level);
                let mut generation_config = serde_json::Map::new();

                // Unified Thinking Config for Gemini 2.x and 3.x
                // rig-core 0.29.0 REQUIRES thinkingBudget (u32), so we must always provide it.
                // Gemini 3.x accepts both thinkingBudget and thinkingLevel.
                if let Some(budget) = req.reasoning_budget {
                    let mut thinking_config = serde_json::Map::new();
                    thinking_config.insert("includeThoughts".to_string(), serde_json::json!(true));

                    // Always set budget to satisfy rig-core. Map -1 (dynamic) to a default if needed.
                    let effective_budget = if budget == -1 { 32768 } else { budget };
                    thinking_config.insert(
                        "thinkingBudget".to_string(),
                        serde_json::json!(effective_budget),
                    );

                    // Add thinkingLevel if present (Gemini 3)
                    if let Some(level) = &req.thinking_level {
                        if level != "dynamic" && !level.is_empty() {
                            thinking_config
                                .insert("thinkingLevel".to_string(), serde_json::json!(level));
                        }
                    }

                    generation_config.insert(
                        "thinkingConfig".to_string(),
                        serde_json::json!(thinking_config),
                    );
                }

                if let Some(top_p) = req.top_p {
                    generation_config.insert("topP".to_string(), serde_json::json!(top_p));
                }

                tracing::debug!("RigClient: Final generationConfig: {:?}", generation_config);

                let mut additional_params = serde_json::Map::new();
                if !generation_config.is_empty() {
                    additional_params.insert(
                        "generationConfig".to_string(),
                        serde_json::json!(generation_config),
                    );
                }
                if let Some(safety) = req.safety_settings {
                    additional_params
                        .insert("safetySettings".to_string(), serde_json::json!(safety));
                }

                let completion_req = rig::completion::CompletionRequest {
                    model: Some(model_name.to_string()),
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(additional_params))
                    },
                    tool_choice: None,
                    output_schema: None,
                };

                let response = match model.completion(completion_req).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(
                            event_type = "llm_generation_failure",
                            provider = "gemini",
                            error = %e,
                            "LLM completion failed"
                        );
                        return Err(e.into());
                    }
                };

                // Extract the first choice content
                let content = response
                    .choice
                    .iter()
                    .find_map(|c| match c {
                        rig::completion::AssistantContent::Text(t) => Some(t.text.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow::anyhow!("No text response received"))?;

                let prompt_tokens = Some(response.usage.input_tokens);
                let completion_tokens = Some(response.usage.output_tokens);
                let total_tokens = Some(response.usage.input_tokens + response.usage.output_tokens);

                let mut rig_response = RigChatResponse {
                    content,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    reasoning_content: None,
                };

                // Extract reasoning if requested
                if req.capture_reasoning_content {
                    rig_response.reasoning_content = response.choice.iter().find_map(|c| match c {
                        rig::completion::AssistantContent::Reasoning(r) => Some(
                            r.content
                                .iter()
                                .map(|c| match c {
                                    rig::message::ReasoningContent::Text { text, .. } => {
                                        text.clone()
                                    }
                                    rig::message::ReasoningContent::Redacted { .. } => {
                                        "[REDACTED]".to_string()
                                    }
                                    _ => String::new(),
                                })
                                .collect::<Vec<_>>()
                                .join(""),
                        ),
                        _ => None,
                    });
                }

                tracing::info!(
                    event_type = "llm_generation_success",
                    provider = "gemini",
                    prompt_tokens = prompt_tokens,
                    completion_tokens = completion_tokens,
                    "LLM completion successful"
                );

                Ok(rig_response)
            }
            "mistralrs" | "local" => {
                let service = self
                    .mistralrs
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("MistralRs service not initialized"))?;

                let adapter = crate::llm::mistralrs_adapter::MistralRsRigAdapter::new(
                    service.clone(),
                    req.model_name.clone(),
                );

                // Combine history and optional prompt
                let mut full_history = req.history;
                if !req.prompt.is_empty() {
                    let prompt_msg = rig::message::Message::User {
                        content: OneOrMany::one(rig::message::UserContent::text(req.prompt)),
                    };
                    full_history.push(prompt_msg);
                }

                let chat_history = OneOrMany::many(full_history)
                    .map_err(|_| anyhow::anyhow!("History cannot be empty"))?;

                let mut generation_config = serde_json::Map::new();
                if let Some(budget) = req.reasoning_budget {
                    let mut thinking_config = serde_json::Map::new();
                    thinking_config.insert("includeThoughts".to_string(), serde_json::json!(true));
                    if budget != -1 {
                        thinking_config
                            .insert("thinkingBudget".to_string(), serde_json::json!(budget));
                    }
                    generation_config.insert(
                        "thinkingConfig".to_string(),
                        serde_json::json!(thinking_config),
                    );
                }
                if let Some(top_p) = req.top_p {
                    generation_config.insert("topP".to_string(), serde_json::json!(top_p));
                }

                let mut additional_params = serde_json::Map::new();
                if !generation_config.is_empty() {
                    additional_params.insert(
                        "generationConfig".to_string(),
                        serde_json::json!(generation_config),
                    );
                }
                if let Some(safety) = req.safety_settings {
                    additional_params
                        .insert("safetySettings".to_string(), serde_json::json!(safety));
                }

                let completion_req = rig::completion::CompletionRequest {
                    model: Some(req.model_name.clone()),
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(additional_params))
                    },
                    tool_choice: None,
                    output_schema: None,
                };

                let response = match adapter.completion(completion_req).await {
                    Ok(r) => r,
                    Err(e) => {
                        let prov = req.provider.as_str();
                        tracing::error!(
                            event_type = "llm_generation_failure",
                            provider = %prov,
                            error = %e,
                            "LLM completion failed"
                        );
                        return Err(e.into());
                    }
                };

                // Extract the first choice content
                let content = response
                    .choice
                    .iter()
                    .find_map(|c| match c {
                        rig::completion::AssistantContent::Text(t) => Some(t.text.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow::anyhow!("No text response received"))?;

                let prompt_tokens = response.usage.input_tokens;
                let completion_tokens = response.usage.output_tokens;
                let prov = req.provider.as_str();

                tracing::info!(
                    event_type = "llm_generation_success",
                    provider = %prov,
                    prompt_tokens = prompt_tokens,
                    completion_tokens = completion_tokens,
                    "LLM completion successful"
                );

                Ok(RigChatResponse {
                    content,
                    prompt_tokens: Some(prompt_tokens),
                    completion_tokens: Some(completion_tokens),
                    total_tokens: Some(prompt_tokens + completion_tokens),
                    reasoning_content: None,
                })
            }
            _ => Err(anyhow::anyhow!("Unsupported provider: {}", req.provider)),
        }
    }

    pub async fn completion_stream(
        &self,
        req: RigCompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<RigStreamEvent, anyhow::Error>> + Send>,
        >,
        anyhow::Error,
    > {
        match req.provider.as_str() {
            "gemini" => {
                // Use Rig's native streaming - it properly handles ReasoningDelta and Reasoning chunks

                let client = if let Some(key) = &self.api_key {
                    gemini::Client::new(key)?
                } else {
                    gemini::Client::from_env()?
                };

                let model_name = if req.model_name.is_empty() {
                    self.model.as_deref().unwrap_or("gemini-1.5-pro")
                } else {
                    &req.model_name
                };

                let model = client.completion_model(model_name);

                // Combine history and optional prompt
                // (generation.rs uses prompt: "" with messages in history, so we skip appending empty prompts)
                let mut full_history = req.history;
                if !req.prompt.is_empty() {
                    let prompt_msg = rig::message::Message::User {
                        content: OneOrMany::one(rig::message::UserContent::text(req.prompt)),
                    };
                    full_history.push(prompt_msg);
                }

                let chat_history = OneOrMany::many(full_history)
                    .map_err(|_| anyhow::anyhow!("History cannot be empty"))?;

                tracing::info!("RigClient: stream request - model: {}, reasoning_budget: {:?}, thinking_level: {:?}", req.model_name, req.reasoning_budget, req.thinking_level);

                let mut generation_config = serde_json::Map::new();

                // Unified Thinking Config for Gemini 2.x and 3.x matching completion()
                if let Some(budget) = req.reasoning_budget {
                    let mut thinking_config = serde_json::Map::new();
                    thinking_config.insert("includeThoughts".to_string(), serde_json::json!(true));

                    // Always set budget to satisfy rig-core. Map -1 (dynamic) to a default if needed.
                    let effective_budget = if budget == -1 { 32768 } else { budget };
                    thinking_config.insert(
                        "thinkingBudget".to_string(),
                        serde_json::json!(effective_budget),
                    );

                    // Add thinkingLevel if present (Gemini 3)
                    if let Some(level) = &req.thinking_level {
                        if level != "dynamic" && !level.is_empty() {
                            thinking_config
                                .insert("thinkingLevel".to_string(), serde_json::json!(level));
                        }
                    }

                    tracing::info!("RigClient: thinkingConfig = {:?}", thinking_config);
                    generation_config.insert(
                        "thinkingConfig".to_string(),
                        serde_json::json!(thinking_config),
                    );
                }

                if let Some(top_p) = req.top_p {
                    generation_config.insert("topP".to_string(), serde_json::json!(top_p));
                }

                tracing::debug!("RigClient: Final generationConfig: {:?}", generation_config);

                let mut additional_params = serde_json::Map::new();
                if !generation_config.is_empty() {
                    additional_params.insert(
                        "generationConfig".to_string(),
                        serde_json::json!(generation_config),
                    );
                }
                if let Some(safety) = req.safety_settings {
                    additional_params
                        .insert("safetySettings".to_string(), serde_json::json!(safety));
                }

                let completion_req = rig::completion::CompletionRequest {
                    model: Some(model_name.to_string()),
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(additional_params))
                    },
                    tool_choice: None,
                    output_schema: None,
                };

                let stream = match model.stream(completion_req).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            event_type = "llm_generation_failure",
                            provider = "gemini",
                            error = %e,
                            "LLM stream initiation failed"
                        );
                        return Err(e.into());
                    }
                };

                let output_stream = async_stream::try_stream! {
                    use futures::StreamExt;
                    use rig::completion::GetTokenUsage;
                    use std::time::Instant;
                    let inner_stream = stream;
                    futures::pin_mut!(inner_stream);

                    let start_time = Instant::now();
                    let mut first_token_received = false;

                    while let Some(result) = inner_stream.next().await {
                        match result {
                            Ok(content) => {
                                match content {
                                    rig::streaming::StreamedAssistantContent::Text(t) => {
                                        if !first_token_received {
                                            first_token_received = true;
                                            let ttft = start_time.elapsed().as_millis() as u64;
                                            tracing::info!(
                                                event_type = "llm_ttft",
                                                provider = "gemini",
                                                duration_ms = ttft,
                                                "First token received"
                                            );
                                        }
                                        tracing::info!("RigClient: Received Text chunk (len: {})", t.text.len());
                                        yield RigStreamEvent::Content(t.text);
                                    }
                                    rig::streaming::StreamedAssistantContent::ReasoningDelta { reasoning, .. } => {
                                        tracing::info!(len = reasoning.len(), "RigClient: Received ReasoningDelta");
                                        yield RigStreamEvent::Reasoning(reasoning);
                                    }
                                    rig::streaming::StreamedAssistantContent::Reasoning(r) => {
                                        let reasoning_text = r.content.iter().map(|c| match c {
                                            rig::message::ReasoningContent::Text { text, .. } => text.clone(),
                                            rig::message::ReasoningContent::Redacted { .. } => "[REDACTED]".to_string(),
                                            _ => String::new(),
                                        }).collect::<Vec<_>>().join("");
                                        tracing::info!(len = reasoning_text.len(), "RigClient: Received full Reasoning chunk");
                                        yield RigStreamEvent::Reasoning(reasoning_text);
                                    }
                                    rig::streaming::StreamedAssistantContent::ToolCall { tool_call, .. } => {
                                        tracing::info!("RigClient: Received ToolCall: {}", tool_call.function.name);
                                        yield RigStreamEvent::ToolCall {
                                            id: tool_call.id,
                                            name: tool_call.function.name,
                                            arguments: tool_call.function.arguments,
                                        };
                                    }
                                    rig::streaming::StreamedAssistantContent::Final(res) => {
                                        if let Some(usage) = res.token_usage() {
                                            tracing::info!("RigClient: Received Final (TokenUsage: {:?})", usage);
                                            yield RigStreamEvent::TokenUsage {
                                                input_tokens: usage.input_tokens,
                                                output_tokens: usage.output_tokens,
                                            };
                                        }
                                    }
                                    _other => {
                                        tracing::warn!("RigClient: Received unhandled/OTHER chunk variant: {:?}", std::any::type_name_of_val(&_other));
                                    }
                                }
                            }
                            Err(e) => Err(anyhow::anyhow!("Stream error: {}", e))?,
                        }
                    }
                };

                Ok(Box::pin(output_stream))
            }
            "mistralrs" | "local" => {
                let service = self
                    .mistralrs
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("MistralRs service not initialized"))?;

                let mut messages = Vec::new();
                if let Some(preamble) = req.preamble {
                    messages.push(("system".to_string(), preamble));
                }
                for msg in req.history {
                    match msg {
                        rig::message::Message::User { content } => {
                            let text = content
                                .into_iter()
                                .map(|c| match c {
                                    rig::message::UserContent::Text(t) => t.text,
                                    _ => "".to_string(),
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            messages.push(("user".to_string(), text));
                        }
                        rig::message::Message::Assistant { content, .. } => {
                            let text = content
                                .into_iter()
                                .map(|c| match c {
                                    rig::message::AssistantContent::Text(t) => t.text,
                                    _ => "".to_string(),
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            messages.push(("assistant".to_string(), text));
                        }
                        rig::message::Message::System { content } => {
                            messages.push(("system".to_string(), content));
                        }
                    }
                }
                messages.push(("user".to_string(), req.prompt));

                let stream = match service.stream_chat(messages).await {
                    Ok(s) => s,
                    Err(e) => {
                        let prov = req.provider.as_str();
                        tracing::error!(
                            event_type = "llm_generation_failure",
                            provider = %prov,
                            error = %e,
                            "LLM stream initiation failed"
                        );
                        return Err(e.into());
                    }
                };

                let output_stream = async_stream::try_stream! {
                    use futures::StreamExt;
                    use std::time::Instant;
                    let inner_stream = stream;
                    futures::pin_mut!(inner_stream);

                    let start_time = Instant::now();
                    let mut first_token_received = false;
                    let prov = req.provider.as_str();

                    while let Some(result) = inner_stream.next().await {
                        match result {
                            Ok(content) => {
                                if !first_token_received {
                                    first_token_received = true;
                                    let ttft = start_time.elapsed().as_millis() as u64;
                                    tracing::info!(
                                        event_type = "llm_ttft",
                                        provider = prov,
                                        duration_ms = ttft,
                                        "First token received"
                                    );
                                }
                                yield RigStreamEvent::Content(content);
                            }
                            Err(e) => Err(anyhow::anyhow!("Stream error: {}", e))?,
                        }
                    }
                };

                Ok(Box::pin(output_stream))
            }
            _ => Err(anyhow::anyhow!("Unsupported provider: {}", req.provider)),
        }
    }
}

#[async_trait]
impl AiClient for RigClient {
    async fn completion(
        &self,
        req: RigCompletionRequest,
    ) -> Result<RigChatResponse, anyhow::Error> {
        self.completion(req).await
    }

    async fn completion_stream(
        &self,
        req: RigCompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<RigStreamEvent, anyhow::Error>> + Send>,
        >,
        anyhow::Error,
    > {
        self.completion_stream(req).await
    }
}

#[cfg(test)]
mod tests {
    
}
