// cli/src/client/interface.rs

use crate::error::CliError;
use async_trait::async_trait;
use futures_util::Stream;
use scribe_backend::models::{
    auth::LoginPayload,
    users::User,
    characters::CharacterDataForClient as BackendCharacterDataForClient, // Alias to avoid confusion if needed
    chats::{Chat, ChatMessage, ApiChatMessage, ChatSettingsResponse, UpdateChatSettingsRequest, GenerateChatRequest},
};
use std::pin::Pin;
use uuid::Uuid;

// Re-exporting local types from super::types for use in the trait definition
use super::types::{
    HealthStatus,
    ClientCharacterDataForClient, // This is the primary character type the client deals with
    StreamEvent,
    RegisterPayload, // CLI specific payload
    AdminUserListResponse,
    AdminUserDetailResponse,
    // UpdateUserRoleRequest is used as a payload, not a return type here
};


/// Trait for abstracting HTTP client interactions to allow mocking in tests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    // Authentication
    async fn login(&self, credentials: &LoginPayload) -> Result<User, CliError>;
    async fn register(&self, credentials: &RegisterPayload) -> Result<User, CliError>;
    async fn logout(&self) -> Result<(), CliError>;
    async fn me(&self) -> Result<User, CliError>;
    fn get_last_recovery_key(&self) -> Option<String>;
    
    // Characters
    async fn list_characters(&self) -> Result<Vec<ClientCharacterDataForClient>, CliError>;
    async fn create_chat_session(&self, character_id: Uuid) -> Result<Chat, CliError>;
    async fn upload_character(
        &self,
        name: &str,
        file_path: &str,
    ) -> Result<ClientCharacterDataForClient, CliError>;
    async fn get_character(&self, character_id: Uuid) -> Result<ClientCharacterDataForClient, CliError>;
    
    // Chat
    async fn list_chat_sessions(&self) -> Result<Vec<Chat>, CliError>;
    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError>;
    async fn send_message(
        &self,
        chat_id: Uuid,
        content: &str,
        model_name: Option<&str>,
    ) -> Result<ChatMessage, CliError>;

    // Streaming Chat
    async fn stream_chat_response(
        &self,
        chat_id: Uuid,
        history: Vec<ApiChatMessage>,
        request_thinking: bool,
        model_name: Option<&str>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError>;

    // Chat Settings
    async fn update_chat_settings(&self, session_id: Uuid, payload: &UpdateChatSettingsRequest) -> Result<ChatSettingsResponse, CliError>;
 
    // Server Health
    async fn health_check(&self) -> Result<HealthStatus, CliError>;
    
    // ADMIN APIs
    async fn admin_list_users(&self) -> Result<Vec<AdminUserListResponse>, CliError>;
    async fn admin_get_user(&self, user_id: Uuid) -> Result<AdminUserDetailResponse, CliError>;
    async fn admin_get_user_by_username(&self, username: &str) -> Result<AdminUserDetailResponse, CliError>;
    async fn admin_update_user_role(&self, user_id: Uuid, role: &str) -> Result<AdminUserDetailResponse, CliError>;
    async fn admin_lock_user(&self, user_id: Uuid) -> Result<(), CliError>;
    async fn admin_unlock_user(&self, user_id: Uuid) -> Result<(), CliError>;
    
    // Legacy - Keep for compatibility but mark unused
    #[allow(dead_code)]
    async fn generate_response(
        &self,
        chat_id: Uuid,
        message_content: &str,
        model_name: Option<String>,
    ) -> Result<ChatMessage, CliError>;
}