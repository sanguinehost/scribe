// cli/src/client/interface.rs

use crate::error::CliError;
use async_trait::async_trait;
use futures_util::Stream;
use scribe_backend::models::{
    auth::LoginPayload,
    // characters::CharacterDataForClient as BackendCharacterDataForClient, // Unused
    chats::{
        ApiChatMessage, Chat, ChatForClient, ChatMessage, ChatSettingsResponse,
        UpdateChatSettingsRequest,
    }, // Removed GenerateChatRequest
    lorebook_dtos::{
        AssociateLorebookToChatPayload, ChatSessionBasicInfo,
        ChatSessionLorebookAssociationResponse, CreateLorebookEntryPayload, CreateLorebookPayload,
        LorebookEntryResponse, LorebookEntrySummaryResponse, LorebookResponse,
        UpdateLorebookEntryPayload, UpdateLorebookPayload,
    },
    user_settings::UserSettingsResponse, // Added UserSettingsResponse
    users::User,
};
use std::pin::Pin;
use uuid::Uuid;

// Re-exporting local types from super::types for use in the trait definition
use crate::client::types::{
    AdminUserDetailResponse,
    // UpdateUserRoleRequest is used as a payload, not a return type here
    AdminUserListResponse,
    // New DTOs for character and chat management
    CharacterCreateDto,
    CharacterUpdateDto,
    ChatSessionDetails,
    ClientCharacterDataForClient, // This is the primary character type the client deals with
    ClientChatMessageResponse,
    // Changed from super::types to crate::client::types
    // User persona types are now directly available under crate::client::types
    CreateUserPersonaDto,
    HealthStatus,
    // CharacterOverrideRequest, // This is a request payload, not directly returned by trait methods
    OverrideSuccessResponse,
    RegisterPayload, // CLI specific payload
    StreamEvent,
    UpdateUserPersonaDto,
    UserPersonaDataForClient,
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
    async fn create_chat_session(
        &self,
        character_id: Uuid,
        active_custom_persona_id: Option<Uuid>,
        lorebook_ids: Option<Vec<Uuid>>,
    ) -> Result<Chat, CliError>;
    async fn upload_character(
        &self,
        name: &str,
        file_path: &str,
    ) -> Result<ClientCharacterDataForClient, CliError>;
    async fn get_character(
        &self,
        character_id: Uuid,
    ) -> Result<ClientCharacterDataForClient, CliError>;
    async fn create_character(
        &self,
        character_data: CharacterCreateDto,
    ) -> Result<ClientCharacterDataForClient, CliError>;
    async fn update_character(
        &self,
        id: Uuid,
        character_update_data: CharacterUpdateDto,
    ) -> Result<ClientCharacterDataForClient, CliError>;

    // User Personas
    async fn create_user_persona(
        &self,
        persona_data: CreateUserPersonaDto,
    ) -> Result<UserPersonaDataForClient, CliError>;
    async fn list_user_personas(&self) -> Result<Vec<UserPersonaDataForClient>, CliError>;
    async fn get_user_persona(
        &self,
        persona_id: Uuid,
    ) -> Result<UserPersonaDataForClient, CliError>;
    async fn update_user_persona(
        &self,
        persona_id: Uuid,
        persona_data: UpdateUserPersonaDto,
    ) -> Result<UserPersonaDataForClient, CliError>;
    async fn delete_user_persona(&self, persona_id: Uuid) -> Result<(), CliError>;
    async fn set_default_persona(&self, persona_id: Uuid) -> Result<User, CliError>;
    async fn clear_default_persona(&self) -> Result<(), CliError>;

    // Lorebooks
    async fn create_lorebook(
        &self,
        payload: &CreateLorebookPayload,
    ) -> Result<LorebookResponse, CliError>;
    async fn list_lorebooks(&self) -> Result<Vec<LorebookResponse>, CliError>;
    async fn get_lorebook(&self, lorebook_id: Uuid) -> Result<LorebookResponse, CliError>;
    async fn update_lorebook(
        &self,
        lorebook_id: Uuid,
        payload: &UpdateLorebookPayload,
    ) -> Result<LorebookResponse, CliError>;
    async fn delete_lorebook(&self, lorebook_id: Uuid) -> Result<(), CliError>;

    // Lorebook Entries
    async fn create_lorebook_entry(
        &self,
        lorebook_id: Uuid,
        payload: &CreateLorebookEntryPayload,
    ) -> Result<LorebookEntryResponse, CliError>;
    async fn list_lorebook_entries(
        &self,
        lorebook_id: Uuid,
    ) -> Result<Vec<LorebookEntrySummaryResponse>, CliError>;
    async fn get_lorebook_entry(
        &self,
        lorebook_id: Uuid,
        entry_id: Uuid,
    ) -> Result<LorebookEntryResponse, CliError>;
    async fn update_lorebook_entry(
        &self,
        lorebook_id: Uuid,
        entry_id: Uuid,
        payload: &UpdateLorebookEntryPayload,
    ) -> Result<LorebookEntryResponse, CliError>;
    async fn delete_lorebook_entry(
        &self,
        lorebook_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), CliError>;

    // Chat Session Lorebook Associations
    async fn associate_lorebook_to_chat(
        &self,
        chat_session_id: Uuid,
        payload: &AssociateLorebookToChatPayload,
    ) -> Result<ChatSessionLorebookAssociationResponse, CliError>;
    async fn list_chat_lorebook_associations(
        &self,
        chat_session_id: Uuid,
    ) -> Result<Vec<ChatSessionLorebookAssociationResponse>, CliError>;
    async fn disassociate_lorebook_from_chat(
        &self,
        chat_session_id: Uuid,
        lorebook_id: Uuid,
    ) -> Result<(), CliError>;
    async fn list_associated_chat_sessions_for_lorebook(
        &self,
        lorebook_id: Uuid,
    ) -> Result<Vec<ChatSessionBasicInfo>, CliError>;

    // Chat
    async fn list_chat_sessions(&self) -> Result<Vec<ChatForClient>, CliError>;
    async fn get_chat_session(&self, session_id: Uuid) -> Result<ChatSessionDetails, CliError>;
    async fn set_chat_character_override(
        &self,
        session_id: Uuid,
        field_name: String,
        value: String,
    ) -> Result<OverrideSuccessResponse, CliError>;
    async fn get_effective_character_for_chat(
        &self,
        character_id: Uuid,
        session_id: Uuid,
    ) -> Result<ClientCharacterDataForClient, CliError>; // Assuming it returns the full character data with overrides applied
    async fn get_chat_messages(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ClientChatMessageResponse>, CliError>;
    async fn send_message(
        &self,
        chat_id: Uuid,
        content: &str,
        model_name: Option<&str>,
    ) -> Result<ChatMessage, CliError>;
    async fn delete_chat(&self, chat_id: Uuid) -> Result<(), CliError>;

    // Streaming Chat
    async fn stream_chat_response(
        &self,
        chat_id: Uuid,
        history: Vec<ApiChatMessage>,
        request_thinking: bool,
        model_name: Option<&str>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError>;

    // Chat Settings
    async fn update_chat_settings(
        &self,
        session_id: Uuid,
        payload: &UpdateChatSettingsRequest,
    ) -> Result<ChatSettingsResponse, CliError>;
    async fn get_chat_settings(&self, session_id: Uuid) -> Result<ChatSettingsResponse, CliError>; // Added

    // User Settings
    async fn get_user_chat_settings(&self) -> Result<Option<UserSettingsResponse>, CliError>;

    // Server Health
    async fn health_check(&self) -> Result<HealthStatus, CliError>;

    // ADMIN APIs
    async fn admin_list_users(&self) -> Result<Vec<AdminUserListResponse>, CliError>;
    async fn admin_get_user(&self, user_id: Uuid) -> Result<AdminUserDetailResponse, CliError>;
    async fn admin_get_user_by_username(
        &self,
        username: &str,
    ) -> Result<AdminUserDetailResponse, CliError>;
    async fn admin_update_user_role(
        &self,
        user_id: Uuid,
        role: &str,
    ) -> Result<AdminUserDetailResponse, CliError>;
    async fn admin_lock_user(&self, user_id: Uuid) -> Result<(), CliError>;
    async fn admin_unlock_user(&self, user_id: Uuid) -> Result<(), CliError>;

    // Legacy - Keep for compatibility but mark unused

    async fn generate_response(
        &self,
        chat_id: Uuid,
        message_content: &str,
        model_name: Option<String>,
    ) -> Result<ChatMessage, CliError>;
}
