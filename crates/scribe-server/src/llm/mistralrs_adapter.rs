// backend/src/llm/mistralrs_adapter.rs
use crate::services::ai::mistralrs_service::MistralRsService;
use futures::StreamExt;
use rig::completion::{
    CompletionError, CompletionModel, CompletionRequest, CompletionResponse, Usage,
};
use rig::message::{AssistantContent, Message};
use rig::streaming::{RawStreamingChoice, StreamingCompletionResponse};
use rig::OneOrMany;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct MistralRsRigAdapter {
    service: Arc<MistralRsService>,
}

impl MistralRsRigAdapter {
    pub fn new(service: Arc<MistralRsService>, _model_name: String) -> Self {
        Self { service }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MistralRsResponse(pub String);

impl rig::completion::GetTokenUsage for MistralRsResponse {
    fn token_usage(&self) -> Option<Usage> {
        None
    }
}

impl CompletionModel for MistralRsRigAdapter {
    type Response = MistralRsResponse;
    type StreamingResponse = MistralRsResponse;
    type Client = Arc<MistralRsService>;

    fn make(client: &Self::Client, _model: impl Into<String>) -> Self {
        Self {
            service: client.clone(),
        }
    }

    async fn completion(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse<Self::Response>, CompletionError> {
        let mut messages = Vec::new();

        // Add preamble as system message if present
        if let Some(preamble) = request.preamble {
            messages.push(("system".to_string(), preamble));
        }

        // Add chat history
        for msg in request.chat_history.iter() {
            match msg {
                Message::User { content, .. } => {
                    let text = content
                        .iter()
                        .map(|c| match c {
                            rig::message::UserContent::Text(t) => t.text.clone(),
                            _ => "".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    messages.push(("user".to_string(), text));
                }
                Message::Assistant { content, .. } => {
                    let text = content
                        .iter()
                        .map(|c| match c {
                            rig::message::AssistantContent::Text(t) => t.text.clone(),
                            _ => "".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    messages.push(("assistant".to_string(), text));
                }
                Message::System { content } => {
                    messages.push(("system".to_string(), content.clone()));
                }
            }
        }

        let response_text = self
            .service
            .chat(messages)
            .await
            .map_err(|e| CompletionError::ProviderError(e.to_string()))?;

        Ok(CompletionResponse {
            choice: OneOrMany::one(AssistantContent::text(response_text.clone())),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
            raw_response: MistralRsResponse(response_text),
            message_id: None,
        })
    }

    async fn stream(
        &self,
        request: CompletionRequest,
    ) -> Result<StreamingCompletionResponse<Self::StreamingResponse>, CompletionError> {
        let mut messages = Vec::new();

        if let Some(preamble) = request.preamble {
            messages.push(("system".to_string(), preamble));
        }

        for msg in request.chat_history.iter() {
            match msg {
                Message::User { content, .. } => {
                    let text = content
                        .iter()
                        .map(|c| match c {
                            rig::message::UserContent::Text(t) => t.text.clone(),
                            _ => "".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    messages.push(("user".to_string(), text));
                }
                Message::Assistant { content, .. } => {
                    let text = content
                        .iter()
                        .map(|c| match c {
                            rig::message::AssistantContent::Text(t) => t.text.clone(),
                            _ => "".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    messages.push(("assistant".to_string(), text));
                }
                Message::System { content } => {
                    messages.push(("system".to_string(), content.clone()));
                }
            }
        }

        let stream = self
            .service
            .stream_chat(messages)
            .await
            .map_err(|e| CompletionError::ProviderError(e.to_string()))?;

        let rig_stream = stream.map(|res| match res {
            Ok(chunk) => Ok(RawStreamingChoice::Message(chunk)),
            Err(e) => Err(CompletionError::ProviderError(e.to_string())),
        });

        Ok(StreamingCompletionResponse::stream(Box::pin(rig_stream)))
    }
}

use rig::embeddings::Embedding;

impl rig::embeddings::EmbeddingModel for MistralRsRigAdapter {
    const MAX_DOCUMENTS: usize = 1;
    type Client = ();

    fn make(_client: &Self::Client, _model: impl Into<String>, _ndims: Option<usize>) -> Self {
        unimplemented!("MistralRsRigAdapter must be created via constructor")
    }

    fn ndims(&self) -> usize {
        0 // Unknown for now
    }

    #[allow(refining_impl_trait)]
    fn embed_texts(
        &self,
        _documents: impl IntoIterator<Item = String> + Send,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<Embedding>, rig::embeddings::EmbeddingError>,
                > + Send,
        >,
    > {
        Box::pin(async {
            Err(rig::embeddings::EmbeddingError::ProviderError(
                "Embeddings not yet supported for MistralRs".to_string(),
            ))
        })
    }
}
