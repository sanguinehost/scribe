use super::AiClient;
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client as HttpClient;
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

#[derive(serde::Deserialize)]
struct GeminiStreamResponse {
    candidates: Option<Vec<GeminiCandidate>>,
    #[serde(rename = "usageMetadata")]
    usage_metadata: Option<GeminiUsage>,
}

#[derive(serde::Deserialize)]
struct GeminiCandidate {
    content: Option<GeminiContent>,
    #[serde(rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct GeminiContent {
    parts: Option<Vec<GeminiPart>>,
    role: Option<String>,
}

#[derive(serde::Deserialize)]
struct GeminiPart {
    text: Option<String>,
    thought: Option<bool>,
    #[serde(rename = "functionCall")]
    function_call: Option<serde_json::Value>,
}

#[derive(serde::Deserialize, Debug)]
struct GeminiUsage {
    #[serde(rename = "promptTokenCount")]
    prompt_token_count: Option<i32>,
    #[serde(rename = "candidatesTokenCount")]
    candidates_token_count: Option<i32>,
    #[serde(rename = "totalTokenCount")]
    total_token_count: Option<i32>,
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
}

impl RigClient {
    pub fn new(api_key: Option<String>, mistralrs: Option<Arc<MistralRsService>>) -> Self {
        Self {
            api_key,
            mistralrs,
            default_provider: "gemini".to_string(),
        }
    }

    pub fn with_provider(mut self, provider: String) -> Self {
        self.default_provider = provider;
        self
    }

    async fn stream_gemini_raw(
        &self,
        req: RigCompletionRequest,
    ) -> Result<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<RigStreamEvent, anyhow::Error>> + Send>,
        >,
        anyhow::Error,
    > {
        eprintln!("DEBUG: RigClient::stream_gemini_raw CALLED");
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("API key required for Gemini"))?;
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
            req.model_name, api_key
        );

        // Construct JSON body manually
        let mut contents = Vec::new();

        // Preamble (System Instruction) - handled separately in Gemini API via systemInstruction field,
        // but rig usually puts it there. Here we construct full request.
        let mut system_instruction = None;
        if let Some(preamble) = &req.preamble {
            system_instruction = Some(serde_json::json!({
                "parts": [{ "text": preamble }]
            }));
        }

        // History + Prompt
        for msg in &req.history {
            match msg {
                rig::message::Message::User { content } => {
                    let text = content
                        .iter()
                        .map(|c| match c {
                            rig::message::UserContent::Text(t) => t.text.clone(),
                            _ => "".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    contents.push(serde_json::json!({
                         "role": "user",
                         "parts": [{ "text": text }]
                    }));
                }
                rig::message::Message::Assistant { content, .. } => {
                    let text = content
                        .iter()
                        .map(|c| match c {
                            rig::message::AssistantContent::Text(t) => t.text.clone(),
                            _ => "".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    contents.push(serde_json::json!({
                         "role": "model",
                         "parts": [{ "text": text }]
                    }));
                }
            }
        }
        // Add current prompt
        contents.push(serde_json::json!({
            "role": "user",
            "parts": [{ "text": req.prompt }]
        }));

        let mut generation_config = serde_json::Map::new();

        // Thinking Config
        // Thinking Config
        // Check if either budget or level is provided to enable thinking
        let has_budget = req.reasoning_budget.is_some() && req.reasoning_budget != Some(0);
        let has_level = req
            .thinking_level
            .as_ref()
            .map_or(false, |l| l != "none" && !l.is_empty());

        if has_budget || has_level {
            let mut thinking_config = serde_json::Map::new();
            thinking_config.insert("includeThoughts".to_string(), serde_json::json!(true));

            // Model-aware thinking configuration:
            // - gemini-2.5-* only supports thinkingBudget (not thinkingLevel)
            // - gemini-3-* supports both, but prefers thinkingLevel
            let is_gemini_3 = req.model_name.starts_with("gemini-3");
            let is_gemini_25 = req.model_name.starts_with("gemini-2.5");

            if is_gemini_3 {
                // Gemini 3: Use thinkingLevel (preferred)
                if let Some(level) = &req.thinking_level {
                    if level != "dynamic" && level != "none" && !level.is_empty() {
                        thinking_config.insert(
                            "thinkingLevel".to_string(),
                            serde_json::json!(level.to_uppercase()),
                        );
                    } else {
                        // Default to MEDIUM for dynamic or unspecified
                        thinking_config
                            .insert("thinkingLevel".to_string(), serde_json::json!("MEDIUM"));
                    }
                } else {
                    // No level specified, default to MEDIUM
                    thinking_config
                        .insert("thinkingLevel".to_string(), serde_json::json!("MEDIUM"));
                }
            } else if is_gemini_25 {
                // Gemini 2.5: Only supports thinkingBudget (max 24576)
                // Map thinking levels to budgets:
                // - low: 1024
                // - medium: 8192
                // - high: 24576
                let budget = if let Some(level) = &req.thinking_level {
                    match level.to_lowercase().as_str() {
                        "low" => 1024,
                        "medium" => 8192,
                        "high" => 24576,
                        _ => req.reasoning_budget.unwrap_or(8192).min(24576),
                    }
                } else {
                    req.reasoning_budget.unwrap_or(8192).min(24576)
                };
                let effective_budget = if budget <= 0 { 8192 } else { budget.min(24576) };
                thinking_config.insert(
                    "thinkingBudget".to_string(),
                    serde_json::json!(effective_budget),
                );
            } else {
                // Unknown model: default to thinkingBudget approach
                let budget = req.reasoning_budget.unwrap_or(8192);
                let effective_budget = if budget <= 0 { 8192 } else { budget };
                thinking_config.insert(
                    "thinkingBudget".to_string(),
                    serde_json::json!(effective_budget),
                );
            }

            generation_config.insert(
                "thinkingConfig".to_string(),
                serde_json::json!(thinking_config),
            );
        }

        if let Some(top_p) = req.top_p {
            generation_config.insert("topP".to_string(), serde_json::json!(top_p));
        }
        if let Some(max_tokens) = req.max_tokens {
            generation_config.insert("maxOutputTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temp) = req.temperature {
            generation_config.insert("temperature".to_string(), serde_json::json!(temp));
        }

        let mut safety_settings = None;
        if let Some(settings) = req.safety_settings {
            safety_settings = Some(settings);
        }

        let body = serde_json::json!({
            "contents": contents,
            "generationConfig": generation_config,
            "systemInstruction": system_instruction,
            "safetySettings": safety_settings
        });

        tracing::info!(
            "RigClient: stream_gemini_raw called. ThinkingLevel: {:?}, Budget: {:?}",
            req.thinking_level,
            req.reasoning_budget
        );
        tracing::debug!("RigClient: Custom RAW stream request body: {}", body);

        let client = HttpClient::new();
        let res = client.post(&url).json(&body).send().await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Gemini API error: {} - {}", status, text));
        }

        Ok(Box::pin(async_stream::try_stream! {
            let mut buffer = String::new();

            // Use chunk() method directly to avoid Stream trait complexities inside macro
            // res must be mutable
            let mut res = res;

            while let Some(chunk) = res.chunk().await.map_err(|e| anyhow::anyhow!("Gemini chunk error: {}", e))? {
                let chunk_str = String::from_utf8_lossy(&chunk);
                buffer.push_str(&chunk_str);

                while let Some(line_end) = buffer.find('\n') {
                    let line = buffer[..line_end].trim().to_string();
                    buffer = buffer[line_end + 1..].to_string();

                    if line.starts_with("data:") {
                        let data_str = line[5..].trim();
                        if data_str.is_empty() { continue; }

                        // Log raw response for debugging (first 3 chunks)
                        static RAW_LOG_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                        let count = RAW_LOG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if count < 3 {
                            tracing::info!("🔥 GEMINI RAW CHUNK {}: {}", count, data_str);
                        }

                        // Parse JSON
                        if let Ok(response) = serde_json::from_str::<GeminiStreamResponse>(data_str) {
                             // Handle candidates
                             if let Some(candidates) = response.candidates {
                                 for candidate in candidates {
                                     if let Some(content) = candidate.content {
                                         if let Some(parts) = content.parts {
                                             for part in parts {
                                                 if let Some(true) = part.thought {
                                                     if let Some(text) = part.text {
                                                         yield RigStreamEvent::Reasoning(text);
                                                     }
                                                 } else if let Some(text) = part.text {
                                                     yield RigStreamEvent::Content(text);
                                                 } else if let Some(func) = part.function_call {
                                                     // Basic tool call mapping
                                                     if let Some(name) = func.get("name").and_then(|n| n.as_str()) {
                                                        yield RigStreamEvent::ToolCall {
                                                            id: "unknown".to_string(),
                                                            name: name.to_string(),
                                                            arguments: func.get("args").cloned().unwrap_or(serde_json::Value::Null),
                                                        };
                                                     }
                                                 }
                                             }
                                         }
                                     }
                                 }
                             }
                             // Handle usage
                             if let Some(usage) = response.usage_metadata {
                                 yield RigStreamEvent::TokenUsage {
                                     input_tokens: usage.prompt_token_count.unwrap_or(0) as u64,
                                     output_tokens: usage.candidates_token_count.unwrap_or(0) as u64,
                                 };
                             }
                        }
                    }
                }
            }
        }))
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
                    gemini::Client::from_env()
                };

                let model = client.completion_model(&req.model_name);

                // Construct the prompt message
                let prompt_msg = rig::message::Message::User {
                    content: OneOrMany::one(rig::message::UserContent::text(req.prompt)),
                };

                // Combine history and prompt
                let mut full_history = req.history;
                full_history.push(prompt_msg);

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
                        if level != "dynamic" {
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
                };

                let response = model.completion(completion_req).await?;

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
                        rig::completion::AssistantContent::Reasoning(r) => {
                            Some(r.reasoning.join(""))
                        }
                        _ => None,
                    });
                }

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

                // Construct the prompt message
                let prompt_msg = rig::message::Message::User {
                    content: OneOrMany::one(rig::message::UserContent::text(req.prompt)),
                };

                // Combine history and prompt
                let mut full_history = req.history;
                full_history.push(prompt_msg);

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
                };

                let response = adapter.completion(completion_req).await?;

                // Extract the first choice content
                let content = response
                    .choice
                    .iter()
                    .find_map(|c| match c {
                        rig::completion::AssistantContent::Text(t) => Some(t.text.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow::anyhow!("No text response received"))?;

                Ok(RigChatResponse {
                    content,
                    prompt_tokens: Some(response.usage.input_tokens),
                    completion_tokens: Some(response.usage.output_tokens),
                    total_tokens: Some(response.usage.input_tokens + response.usage.output_tokens),
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
        eprintln!("DEBUG: RigClient::completion_stream (INHERENT) CALLED");
        match req.provider.as_str() {
            "gemini" => {
                // Use Rig's native streaming - it properly handles ReasoningDelta and Reasoning chunks

                let client = if let Some(key) = &self.api_key {
                    gemini::Client::new(key)?
                } else {
                    gemini::Client::from_env()
                };

                let model = client.completion_model(&req.model_name);

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

                // Model-aware thinkingConfig:
                // - gemini-2.5-* ONLY supports thinkingBudget (max 24576)
                // - gemini-3-* supports both, but PREFERS thinkingLevel
                let has_budget = req.reasoning_budget.is_some();
                let has_level = req.thinking_level.is_some();

                if has_budget || has_level {
                    let mut thinking_config = serde_json::Map::new();
                    thinking_config.insert("includeThoughts".to_string(), serde_json::json!(true));

                    let is_gemini_3 = req.model_name.starts_with("gemini-3");
                    let is_gemini_25 = req.model_name.starts_with("gemini-2.5");

                    if is_gemini_3 {
                        // Gemini 3: Use thinkingLevel (preferred)
                        if let Some(level) = &req.thinking_level {
                            if level != "dynamic" && level != "none" && !level.is_empty() {
                                thinking_config.insert(
                                    "thinkingLevel".to_string(),
                                    serde_json::json!(level.to_uppercase()),
                                );
                            } else {
                                thinking_config.insert(
                                    "thinkingLevel".to_string(),
                                    serde_json::json!("MEDIUM"),
                                );
                            }
                        } else {
                            thinking_config
                                .insert("thinkingLevel".to_string(), serde_json::json!("MEDIUM"));
                        }
                        // CRITICAL: Even though Gemini 3 uses level, Rig's internal streaming logic
                        // for capturing reasoning often checks for a non-zero budget.
                        thinking_config
                            .insert("thinkingBudget".to_string(), serde_json::json!(16384));
                    } else if is_gemini_25 {
                        // Gemini 2.5: Only supports thinkingBudget (max 24576)
                        let budget = if let Some(level) = &req.thinking_level {
                            match level.to_lowercase().as_str() {
                                "low" => 8192,
                                "medium" => 16384,
                                "high" => 24576,
                                _ => req.reasoning_budget.unwrap_or(16384).min(24576),
                            }
                        } else {
                            req.reasoning_budget.unwrap_or(16384).min(24576)
                        };
                        let effective_budget = if budget <= 0 {
                            16384
                        } else {
                            budget.min(24576)
                        };
                        thinking_config.insert(
                            "thinkingBudget".to_string(),
                            serde_json::json!(effective_budget),
                        );
                    } else {
                        // Unknown model: default to thinkingBudget
                        let budget = req.reasoning_budget.unwrap_or(16384);
                        let effective_budget = if budget <= 0 { 16384 } else { budget };
                        thinking_config.insert(
                            "thinkingBudget".to_string(),
                            serde_json::json!(effective_budget),
                        );
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
                };

                let stream = model.stream(completion_req).await?;

                let output_stream = async_stream::try_stream! {
                    use futures::StreamExt;
                    use rig::completion::GetTokenUsage;
                    let inner_stream = stream;
                    futures::pin_mut!(inner_stream);

                    while let Some(result) = inner_stream.next().await {
                        match result {
                            Ok(content) => {
                                match content {
                                    rig::streaming::StreamedAssistantContent::Text(t) => {
                                        tracing::info!("RigClient: Received Text chunk (len: {})", t.text.len());
                                        yield RigStreamEvent::Content(t.text);
                                    }
                                    rig::streaming::StreamedAssistantContent::ReasoningDelta { reasoning, .. } => {
                                        tracing::info!("RigClient: Received ReasoningDelta (len: {})", reasoning.len());
                                        yield RigStreamEvent::Reasoning(reasoning);
                                    }
                                    rig::streaming::StreamedAssistantContent::Reasoning(r) => {
                                        let reasoning_text = r.reasoning.join("");
                                        tracing::info!("RigClient: Received Reasoning (len: {})", reasoning_text.len());
                                        yield RigStreamEvent::Reasoning(reasoning_text);
                                    }
                                    rig::streaming::StreamedAssistantContent::ToolCall(tc) => {
                                        tracing::info!("RigClient: Received ToolCall: {}", tc.function.name);
                                        yield RigStreamEvent::ToolCall {
                                            id: tc.id,
                                            name: tc.function.name,
                                            arguments: tc.function.arguments,
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
                    }
                }
                messages.push(("user".to_string(), req.prompt));

                let stream = service.stream_chat(messages).await?;

                let output_stream = async_stream::try_stream! {
                    use futures::StreamExt;
                    let inner_stream = stream;
                    futures::pin_mut!(inner_stream);
                    while let Some(result) = inner_stream.next().await {
                        match result {
                            Ok(content) => yield RigStreamEvent::Content(content),
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
    use super::*;
}
