use super::AiClient;
use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::client::ProviderClient;
use rig::completion::CompletionModel;
use rig::one_or_many::OneOrMany;
use rig::providers::gemini;
// use futures::Stream;

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

                let mut additional_params = serde_json::Map::new();
                if let Some(budget) = req.reasoning_budget {
                    additional_params
                        .insert("reasoning_budget".to_string(), serde_json::json!(budget));
                }
                if let Some(safety) = req.safety_settings {
                    additional_params
                        .insert("safety_settings".to_string(), serde_json::json!(safety));
                }
                if let Some(top_p) = req.top_p {
                    additional_params.insert("top_p".to_string(), serde_json::json!(top_p));
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

                let mut additional_params = serde_json::Map::new();
                if let Some(budget) = req.reasoning_budget {
                    additional_params
                        .insert("reasoning_budget".to_string(), serde_json::json!(budget));
                }
                if let Some(safety) = req.safety_settings {
                    additional_params
                        .insert("safety_settings".to_string(), serde_json::json!(safety));
                }
                if let Some(top_p) = req.top_p {
                    additional_params.insert("top_p".to_string(), serde_json::json!(top_p));
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

                let mut additional_params = serde_json::Map::new();
                if let Some(budget) = req.reasoning_budget {
                    additional_params
                        .insert("reasoning_budget".to_string(), serde_json::json!(budget));
                }
                if let Some(safety) = req.safety_settings {
                    additional_params
                        .insert("safety_settings".to_string(), serde_json::json!(safety));
                }
                if let Some(top_p) = req.top_p {
                    additional_params.insert("top_p".to_string(), serde_json::json!(top_p));
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
                                        yield RigStreamEvent::Content(t.text);
                                    }
                                    rig::streaming::StreamedAssistantContent::ReasoningDelta { reasoning, .. } => {
                                        yield RigStreamEvent::Reasoning(reasoning);
                                    }
                                    rig::streaming::StreamedAssistantContent::Reasoning(r) => {
                                        yield RigStreamEvent::Reasoning(r.reasoning.join(""));
                                    }
                                    rig::streaming::StreamedAssistantContent::ToolCall(tc) => {
                                        yield RigStreamEvent::ToolCall {
                                            id: tc.id,
                                            name: tc.function.name,
                                            arguments: tc.function.arguments,
                                        };
                                    }
                                    rig::streaming::StreamedAssistantContent::Final(res) => {
                                        if let Some(usage) = res.token_usage() {
                                            yield RigStreamEvent::TokenUsage {
                                                input_tokens: usage.input_tokens,
                                                output_tokens: usage.output_tokens,
                                            };
                                        }
                                    }
                                    _ => {}
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
