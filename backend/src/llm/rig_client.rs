use super::{AiClient, ChatStream};
use crate::errors::AppError;
use async_trait::async_trait;
use genai::chat::{ChatOptions, ChatRequest, ChatResponse};
use rig::client::CompletionClient;
use rig::client::ProviderClient;
use rig::completion::CompletionModel;
use rig::one_or_many::OneOrMany;
use rig::providers::gemini;
// use futures::Stream;

#[derive(Debug, Clone)]
pub struct RigCompletionRequest {
    pub model_name: String,
    pub provider: String, // "gemini", "ollama", etc.
    pub prompt: String,
    pub preamble: Option<String>,
    pub history: Vec<rig::message::Message>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<i32>,
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
}

/// Wrapper around Rig's completion models to provide a unified interface
/// for Scribe's chat service.
#[derive(Clone)]
pub struct RigClient {
    api_key: Option<String>,
}

impl RigClient {
    pub fn new(api_key: Option<String>) -> Self {
        Self { api_key }
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

                let completion_req = rig::completion::CompletionRequest {
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: None,
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

                Ok(RigChatResponse {
                    content,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
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

                let completion_req = rig::completion::CompletionRequest {
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: None,
                    tool_choice: None,
                };

                let stream = model.stream(completion_req).await?;

                let output_stream = async_stream::try_stream! {
                    use futures::StreamExt;
                    use rig::completion::GetTokenUsage;
                    let mut inner_stream = stream;

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
            _ => Err(anyhow::anyhow!("Unsupported provider: {}", req.provider)),
        }
    }
}

#[async_trait]
impl AiClient for RigClient {
    async fn exec_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatResponse, AppError> {
        // Convert genai::ChatRequest to RigCompletionRequest
        let mut rig_messages = Vec::new();
        for m in request.messages {
            let role = match m.role {
                genai::chat::ChatRole::User => rig::message::Message::User {
                    content: OneOrMany::one(rig::message::UserContent::text(
                        m.content.texts().join("\n"),
                    )),
                },
                genai::chat::ChatRole::Assistant => rig::message::Message::Assistant {
                    id: None,
                    content: OneOrMany::one(rig::message::AssistantContent::text(
                        m.content.texts().join("\n"),
                    )),
                },
                _ => continue,
            };
            rig_messages.push(role);
        }

        let rig_req = RigCompletionRequest {
            model_name: model_name.to_string(),
            provider: "gemini".to_string(), // Default to gemini for now
            prompt: "".to_string(),
            preamble: request.system,
            history: rig_messages,
            temperature: config_override.as_ref().and_then(|o| o.temperature),
            max_tokens: config_override
                .as_ref()
                .and_then(|o| o.max_tokens)
                .map(|t| t as i32),
        };

        let rig_response = self
            .completion(rig_req)
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;

        // Convert RigChatResponse to genai::ChatResponse
        Ok(ChatResponse {
            content: genai::chat::MessageContent::from(rig_response.content),
            captured_raw_body: None,
            reasoning_content: None,
            model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, model_name),
            provider_model_iden: genai::ModelIden::new(
                genai::adapter::AdapterKind::Gemini,
                model_name,
            ),
            usage: genai::chat::Usage {
                prompt_tokens: rig_response.prompt_tokens.map(|t| t as i32),
                completion_tokens: rig_response.completion_tokens.map(|t| t as i32),
                total_tokens: rig_response.total_tokens.map(|t| t as i32),
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
        })
    }

    async fn stream_chat(
        &self,
        _model_name: &str,
        _request: ChatRequest,
        _config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        // For now, we don't implement stream_chat for RigClient via AiClient trait
        // because the stream types are different and complex to map.
        // We expect callers to use completion_stream directly if they have a RigClient.
        Err(AppError::InternalServerErrorGeneric(
            "stream_chat not implemented for RigClient".to_string(),
        ))
    }

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
