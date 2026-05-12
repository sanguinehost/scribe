// backend/src/services/ai/mistralrs_service.rs
#[cfg(feature = "local-llm")]
use crate::errors::AppError;
#[cfg(feature = "local-llm")]
use futures_util::StreamExt;
#[cfg(feature = "local-llm")]
use mistralrs::{GgufModelBuilder, Model, Response, TextMessageRole, TextMessages};
#[cfg(feature = "local-llm")]
use mistralrs_core::{ChatCompletionChunkResponse, ChunkChoice, Delta};
#[cfg(feature = "local-llm")]
use std::sync::Arc;
#[cfg(feature = "local-llm")]
use tracing::info;

#[cfg(feature = "local-llm")]
pub struct MistralRsService {
    model: Arc<Model>,
}

#[cfg(feature = "local-llm")]
impl MistralRsService {
    pub async fn new(model_id: String, model_file: String) -> Result<Self, AppError> {
        info!(
            "Initializing MistralRsService with model: {} ({})",
            model_id, model_file
        );

        let model = GgufModelBuilder::new(model_id, vec![model_file])
            .with_logging()
            .build()
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to load MistralRs model: {}",
                    e
                ))
            })?;

        Ok(Self {
            model: Arc::new(model),
        })
    }

    pub async fn chat(&self, messages: Vec<(String, String)>) -> Result<String, AppError> {
        let mut mistral_messages = TextMessages::new();
        for (role, content) in messages {
            let mistral_role = match role.as_str() {
                "system" => TextMessageRole::System,
                "user" => TextMessageRole::User,
                "assistant" => TextMessageRole::Assistant,
                _ => TextMessageRole::User,
            };
            mistral_messages = mistral_messages.add_message(mistral_role, content);
        }

        let response = self
            .model
            .send_chat_request(mistral_messages)
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "MistralRs chat request failed: {}",
                    e
                ))
            })?;

        response
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .ok_or_else(|| {
                AppError::InternalServerErrorGeneric(
                    "MistralRs returned empty response".to_string(),
                )
            })
    }

    pub async fn stream_chat(
        &self,
        messages: Vec<(String, String)>,
    ) -> Result<impl futures_util::Stream<Item = Result<String, AppError>>, AppError> {
        let mut mistral_messages = TextMessages::new();
        for (role, content) in messages {
            let mistral_role = match role.as_str() {
                "system" => TextMessageRole::System,
                "user" => TextMessageRole::User,
                "assistant" => TextMessageRole::Assistant,
                _ => TextMessageRole::User,
            };
            mistral_messages = mistral_messages.add_message(mistral_role, content);
        }

        let stream = self
            .model
            .stream_chat_request(mistral_messages)
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "MistralRs stream chat request failed: {}",
                    e
                ))
            })?;

        let output_stream = async_stream::try_stream! {
            let mut inner_stream = stream;
            while let Some(chunk) = inner_stream.next().await {
                if let Response::Chunk(ChatCompletionChunkResponse { choices, .. }) = chunk {
                    if let Some(ChunkChoice {
                        delta: Delta { content: Some(content), .. },
                        ..
                    }) = choices.first() {
                        yield content.clone();
                    }
                }
            }
        };

        Ok(output_stream)
    }
}

// Dummy implementation for when local-llm is disabled
#[cfg(not(feature = "local-llm"))]
pub struct MistralRsService;

#[cfg(not(feature = "local-llm"))]
impl MistralRsService {
    pub async fn chat(
        &self,
        _messages: Vec<(String, String)>,
    ) -> Result<String, crate::errors::AppError> {
        Err(crate::errors::AppError::InternalServerErrorGeneric(
            "MistralRs local-llm feature not enabled".to_string(),
        ))
    }

    pub async fn stream_chat(
        &self,
        _messages: Vec<(String, String)>,
    ) -> Result<
        impl futures_util::Stream<Item = Result<String, crate::errors::AppError>>,
        crate::errors::AppError,
    > {
        let stream = futures_util::stream::once(async {
            Err(crate::errors::AppError::InternalServerErrorGeneric(
                "MistralRs local-llm feature not enabled".to_string(),
            ))
        });
        Ok(stream)
    }
}
