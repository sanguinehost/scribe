use crate::client::HttpClient;
use crate::client::types::{
    AdminUserDetailResponse, AdminUserListResponse, ClientCharacterDataForClient,
    ClientChatMessageResponse, HealthStatus, RegisterPayload, StreamEvent,
    // New DTOs for character and chat management
    CharacterCreateDto,
    CharacterUpdateDto,
    ChatSessionDetails,
    OverrideSuccessResponse,
};
use crate::error::CliError;
use crate::io::IoHandler;
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use chrono::Utc;
use futures_util::Stream;
use scribe_backend::models::auth::LoginPayload;
use scribe_backend::models::chats::{
    ApiChatMessage, Chat, ChatMessage, ChatSettingsResponse, MessageRole, UpdateChatSettingsRequest,
};
use scribe_backend::models::users::User;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

// Define a simple, cloneable error for mocking purposes
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MockCliError {
    AuthFailed(String),
    RegistrationFailed(String),
    ApiError(String), // Simplified API error
    NotFound,
    Internal(String),
    // Add other variants as needed for specific test cases
}

impl From<MockCliError> for CliError {
    fn from(mock_err: MockCliError) -> Self {
        match mock_err {
            MockCliError::AuthFailed(msg) => CliError::AuthFailed(msg),
            MockCliError::RegistrationFailed(msg) => CliError::RegistrationFailed(msg),
            MockCliError::ApiError(msg) => CliError::ApiError {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR, // Use a default status
                message: msg,
            },
            MockCliError::NotFound => CliError::NotFound,
            MockCliError::Internal(msg) => CliError::Internal(msg),
        }
    }
}

#[derive(Default)]
pub struct MockIoHandler {
    inputs: RefCell<VecDeque<String>>,
    outputs: RefCell<Vec<String>>,
}

#[allow(dead_code)]
impl MockIoHandler {
    pub fn new(inputs: Vec<&str>) -> Self {
        MockIoHandler {
            inputs: RefCell::new(inputs.into_iter().map(String::from).collect()),
            outputs: RefCell::new(Vec::new()),
        }
    }

    pub fn expect_output(&self, expected: &str) {
        assert!(
            self.outputs
                .borrow()
                .iter()
                .any(|line| line.contains(expected)),
            "Expected output containing '{}', but got: {:?}",
            expected,
            self.outputs.borrow()
        );
    }

    pub fn expect_no_output_containing(&self, unexpected: &str) {
        assert!(
            !self
                .outputs
                .borrow()
                .iter()
                .any(|line| line.contains(unexpected)),
            "Did not expect output containing '{}', but got: {:?}",
            unexpected,
            self.outputs.borrow()
        );
    }
}

impl IoHandler for MockIoHandler {
    fn read_line(&mut self, prompt: &str) -> Result<String, CliError> {
        self.outputs.borrow_mut().push(prompt.to_string());
        self.inputs.borrow_mut().pop_front().ok_or_else(|| {
            CliError::InputError("MockIoHandler: No more inputs provided".to_string())
        })
    }

    fn write_line(&mut self, line: &str) -> Result<(), CliError> {
        self.outputs.borrow_mut().push(line.to_string());
        Ok(())
    }

    fn write_raw(&mut self, text: &str) -> Result<(), CliError> {
        // For the mock, just store the raw text like write_line
        self.outputs.borrow_mut().push(text.to_string());
        Ok(())
    }

    // Add dummy flush implementation for tests
    fn flush(&mut self) -> Result<(), CliError> {
        // No-op for mock handler, just return Ok
        Ok(())
    }
}

#[derive(Default)]
pub struct MockHttpClient {
    pub login_result: Option<Arc<Result<User, MockCliError>>>,
    pub register_result: Option<Arc<Result<User, MockCliError>>>,
    pub health_check_result: Option<Arc<Result<HealthStatus, MockCliError>>>,
    pub upload_character_result: Option<Arc<Result<ClientCharacterDataForClient, MockCliError>>>,
    pub list_characters_result:
        Option<Arc<Result<Vec<ClientCharacterDataForClient>, MockCliError>>>,
    pub get_character_result: Option<Arc<Result<ClientCharacterDataForClient, MockCliError>>>,
    pub list_chat_sessions_result: Option<Arc<Result<Vec<Chat>, MockCliError>>>,
    pub get_chat_messages_result: Option<Arc<Result<Vec<ClientChatMessageResponse>, MockCliError>>>,
    pub create_chat_session_result: Option<Arc<Result<Chat, MockCliError>>>,
    pub generate_response_result: Option<Arc<Result<ChatMessage, MockCliError>>>,
    pub logout_result: Option<Arc<Result<(), MockCliError>>>,
    pub me_result: Option<Arc<Result<User, MockCliError>>>,
    pub update_chat_settings_result: Option<Arc<Result<ChatSettingsResponse, MockCliError>>>,
    pub delete_chat_result: Option<Arc<Result<(), MockCliError>>>,
    pub admin_list_users_result: Option<Arc<Result<Vec<AdminUserListResponse>, MockCliError>>>,
    pub admin_get_user_result: Option<Arc<Result<AdminUserDetailResponse, MockCliError>>>,
    pub admin_get_user_by_username_result:
        Option<Arc<Result<AdminUserDetailResponse, MockCliError>>>,
    pub admin_update_user_role_result: Option<Arc<Result<AdminUserDetailResponse, MockCliError>>>,
    pub admin_lock_user_result: Option<Arc<Result<(), MockCliError>>>,
    pub admin_unlock_user_result: Option<Arc<Result<(), MockCliError>>>,
    pub last_recovery_key: Option<String>,

    // New fields for character and chat override methods
    pub create_character_result: Option<Arc<Result<ClientCharacterDataForClient, MockCliError>>>,
    pub update_character_result: Option<Arc<Result<ClientCharacterDataForClient, MockCliError>>>,
    pub get_chat_session_result: Option<Arc<Result<ChatSessionDetails, MockCliError>>>,
    pub set_chat_character_override_result:
        Option<Arc<Result<OverrideSuccessResponse, MockCliError>>>,
    pub get_effective_character_for_chat_result:
        Option<Arc<Result<ClientCharacterDataForClient, MockCliError>>>,

    // Track called endpoints for validation - use Arc<Mutex> for thread safety
    pub called_endpoints: Arc<std::sync::Mutex<Vec<String>>>,

    // Expected endpoint patterns for validation
    #[allow(dead_code)]
    pub expected_endpoints: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

#[allow(dead_code)]
impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            called_endpoints: Arc::new(std::sync::Mutex::new(Vec::new())),
            expected_endpoints: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            ..Default::default()
        }
    }

    // Records a called endpoint
    pub fn record_endpoint_call(&self, endpoint: &str) {
        if let Ok(mut endpoints) = self.called_endpoints.lock() {
            endpoints.push(endpoint.to_string());
        }
    }

    // Set expected endpoint for a function
    pub fn expect_endpoint(&self, function_name: &str, endpoint_pattern: &str) {
        if let Ok(mut patterns) = self.expected_endpoints.lock() {
            patterns.insert(function_name.to_string(), endpoint_pattern.to_string());
        }
    }

    // Verify that a function was called with the expected endpoint pattern
    pub fn verify_endpoint_call(&self, function_name: &str) -> Result<(), String> {
        let expected_patterns = match self.expected_endpoints.lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Failed to acquire lock on expected_endpoints".to_string()),
        };

        let called_endpoints = match self.called_endpoints.lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Failed to acquire lock on called_endpoints".to_string()),
        };

        if let Some(expected_pattern) = expected_patterns.get(function_name) {
            // Find if any called endpoint matches the expected pattern
            for endpoint in called_endpoints.iter() {
                if endpoint.contains(expected_pattern) {
                    return Ok(());
                }
            }

            // No match found
            return Err(format!(
                "Function '{}' was not called with an endpoint containing '{}'. Called endpoints: {:?}",
                function_name, expected_pattern, *called_endpoints
            ));
        }

        // No expectation set for this function
        Ok(())
    }

    // Verify all endpoint expectations
    pub fn verify_all_endpoints(&self) -> Result<(), String> {
        let expected_patterns = match self.expected_endpoints.lock() {
            Ok(guard) => guard,
            Err(_) => return Err("Failed to acquire lock on expected_endpoints".to_string()),
        };

        let function_names: Vec<String> = expected_patterns.keys().cloned().collect();

        for function_name in function_names {
            if let Err(e) = self.verify_endpoint_call(&function_name) {
                return Err(e);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn login(&self, _credentials: &LoginPayload) -> Result<User, CliError> {
        let mock_result = Arc::unwrap_or_clone(self.login_result.clone().unwrap_or_else(|| {
            Arc::new(Err(MockCliError::Internal(
                "MockHttpClient: login result not set".into(),
            )))
        }));
        mock_result.map_err(Into::into)
    }

    async fn register(&self, _credentials: &RegisterPayload) -> Result<User, CliError> {
        let mock_result = Arc::unwrap_or_clone(self.register_result.clone().unwrap_or_else(|| {
            Arc::new(Err(MockCliError::Internal(
                "MockHttpClient: register result not set".into(),
            )))
        }));
        mock_result.map_err(Into::into)
    }

    async fn list_characters(&self) -> Result<Vec<ClientCharacterDataForClient>, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.list_characters_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: list_characters result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn create_chat_session(&self, _character_id: Uuid, _active_custom_persona_id: Option<Uuid>, _lorebook_ids: Option<Vec<Uuid>>) -> Result<Chat, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.create_chat_session_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: create_chat_session result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn upload_character(
        &self,
        _name: &str,
        _file_path: &str,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.upload_character_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: upload_character result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn health_check(&self) -> Result<HealthStatus, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.health_check_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: health_check result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn logout(&self) -> Result<(), CliError> {
        let mock_result = Arc::unwrap_or_clone(self.logout_result.clone().unwrap_or_else(|| {
            Arc::new(Err(MockCliError::Internal(
                "MockHttpClient: logout result not set".into(),
            )))
        }));
        mock_result.map_err(Into::into)
    }

    async fn me(&self) -> Result<User, CliError> {
        let mock_result = Arc::unwrap_or_clone(self.me_result.clone().unwrap_or_else(|| {
            Arc::new(Err(MockCliError::Internal(
                "MockHttpClient: me result not set".into(),
            )))
        }));
        mock_result.map_err(Into::into)
    }

    async fn get_character(
        &self,
        _character_id: Uuid,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.get_character_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: get_character result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn list_chat_sessions(&self) -> Result<Vec<Chat>, CliError> {
        self.record_endpoint_call("list_chat_sessions");
        match &self.list_chat_sessions_result {
            Some(res) => res.as_ref().clone().map_err(CliError::from),
            None => Err(CliError::Internal(
                "list_chat_sessions_result not set".to_string(),
            )),
        }
    }

    async fn get_chat_messages(
        &self,
        _session_id: Uuid,
    ) -> Result<Vec<ClientChatMessageResponse>, CliError> {
        self.record_endpoint_call(&format!("get_chat_messages/{}", _session_id));
        match &self.get_chat_messages_result {
            Some(res) => res.as_ref().clone().map_err(CliError::from),
            None => Err(CliError::Internal(
                "get_chat_messages_result not set".to_string(),
            )),
        }
    }

    // Add missing implementation for generate_response (matching the trait signature)
    async fn generate_response(
        &self,
        _chat_id: Uuid,
        _message_content: &str,
        _model_name: Option<String>,
    ) -> Result<ChatMessage, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.generate_response_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: generate_response result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    // Add missing implementation for send_message
    async fn send_message(
        &self,
        _chat_id: Uuid,
        _content: &str,
        _model_name: Option<&str>,
    ) -> Result<ChatMessage, CliError> {
        // Use the configurable result field, similar to generate_response
        let mock_result =
            Arc::unwrap_or_clone(self.generate_response_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: generate_response_result (for send_message) not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    // Add mock implementation for stream_chat_response
    async fn stream_chat_response(
        &self,
        _chat_id: Uuid,
        _history: Vec<ApiChatMessage>,
        _request_thinking: bool,
        _model_name: Option<&str>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError> {
        // Default mock implementation: return an error or an empty stream.
        // For most handler tests, we don't need to simulate a full stream.
        // If a specific test needs a stream, it can configure a dedicated mock field.
        Err(CliError::Internal(
            "MockHttpClient: stream_chat_response not implemented/configured".into(),
        ))
        // Or return an empty stream:
        // Ok(Box::pin(futures_util::stream::empty())) // Use futures_util::stream::empty
    }

    async fn update_chat_settings(
        &self,
        _session_id: Uuid,
        _payload: &UpdateChatSettingsRequest,
    ) -> Result<ChatSettingsResponse, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.update_chat_settings_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: update_chat_settings result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn admin_list_users(&self) -> Result<Vec<AdminUserListResponse>, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.admin_list_users_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: admin_list_users result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn admin_get_user(&self, _user_id: Uuid) -> Result<AdminUserDetailResponse, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.admin_get_user_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: admin_get_user result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn admin_get_user_by_username(
        &self,
        _username: &str,
    ) -> Result<AdminUserDetailResponse, CliError> {
        let mock_result = Arc::unwrap_or_clone(
            self.admin_get_user_by_username_result
                .clone()
                .unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: admin_get_user_by_username result not set".into(),
                    )))
                }),
        );
        mock_result.map_err(Into::into)
    }

    async fn admin_update_user_role(
        &self,
        _user_id: Uuid,
        _role: &str,
    ) -> Result<AdminUserDetailResponse, CliError> {
        let mock_result = Arc::unwrap_or_clone(
            self.admin_update_user_role_result
                .clone()
                .unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: admin_update_user_role result not set".into(),
                    )))
                }),
        );
        mock_result.map_err(Into::into)
    }

    async fn admin_lock_user(&self, _user_id: Uuid) -> Result<(), CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.admin_lock_user_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: admin_lock_user result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn admin_unlock_user(&self, _user_id: Uuid) -> Result<(), CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.admin_unlock_user_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: admin_unlock_user result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn delete_chat(&self, chat_id: Uuid) -> Result<(), CliError> {
        // Record the endpoint call with the expected format
        self.record_endpoint_call(&format!("/api/chats/remove/{}", chat_id));

        let mock_result =
            Arc::unwrap_or_clone(self.delete_chat_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: delete_chat result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    fn get_last_recovery_key(&self) -> Option<String> {
        self.last_recovery_key.clone()
    }

    async fn create_character(
        &self,
        _character_data: crate::client::types::CharacterCreateDto,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.create_character_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: create_character result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn update_character(
        &self,
        _id: Uuid,
        _character_update_data: crate::client::types::CharacterUpdateDto,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.update_character_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: update_character result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn get_chat_session(&self, _session_id: Uuid) -> Result<crate::client::types::ChatSessionDetails, CliError> {
        let mock_result =
            Arc::unwrap_or_clone(self.get_chat_session_result.clone().unwrap_or_else(|| {
                Arc::new(Err(MockCliError::Internal(
                    "MockHttpClient: get_chat_session result not set".into(),
                )))
            }));
        mock_result.map_err(Into::into)
    }

    async fn set_chat_character_override(
        &self,
        _session_id: Uuid,
        _field_name: String,
        _value: String,
    ) -> Result<crate::client::types::OverrideSuccessResponse, CliError> {
        let mock_result = Arc::unwrap_or_clone(
            self.set_chat_character_override_result
                .clone()
                .unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: set_chat_character_override result not set".into(),
                    )))
                }),
        );
        mock_result.map_err(Into::into)
    }

    async fn get_effective_character_for_chat(
        &self,
        _character_id: Uuid,
        _session_id: Uuid,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let mock_result = Arc::unwrap_or_clone(
            self.get_effective_character_for_chat_result
                .clone()
                .unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: get_effective_character_for_chat result not set".into(),
                    )))
                }),
        );
        mock_result.map_err(Into::into)
    }
}

// --- Helper Functions for Creating Mocks ---

/// Creates a mock user for testing
#[allow(dead_code)]
pub fn mock_user(username: &str) -> User {
    User {
        id: Uuid::new_v4(),
        username: username.to_string(),
        email: "user@example.com".to_string(),
        password_hash: "hashed_password".to_string(), // Mocked
        kek_salt: "mock_kek_salt".to_string(),
        encrypted_dek: vec![],
        dek_nonce: vec![0u8; 12], // Placeholder 12-byte nonce
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        dek: None, // Option<SerializableSecretDek>
        created_at: Utc::now(),
        updated_at: Utc::now(),
        role: scribe_backend::models::users::UserRole::User, // Default to User role
        account_status: Some("active".to_string()),          // Default to active account
        recovery_phrase: None,                               // Recovery phrase not stored in DB
    }
}

/// Creates a mock character for testing
#[allow(dead_code)]
pub fn mock_character_data_for_client(
    id: Uuid,
    name: &str,
    description: Option<&str>,
) -> ClientCharacterDataForClient {
    ClientCharacterDataForClient {
        id,
        user_id: Uuid::new_v4(),
        name: name.to_string(),
        description: description.map(String::from),
        spec: "spec_v3".to_string(),
        spec_version: "1.0".to_string(),
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        creator_notes: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        creator_notes_multilingual: None,
        source: None,
        group_only_greetings: None,
        creation_date: Some(Utc::now()),
        modification_date: Some(Utc::now()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        persona: None,
        world_scenario: None,
        avatar: None,
        chat: None,
        greeting: None,
        definition: None,
        default_voice: None,
        extensions: None,
        data_id: None,
        category: None,
        definition_visibility: None,
        depth: None,
        example_dialogue: None,
        favorite: Some(false),
        first_message_visibility: None,
        height: None,
        last_activity: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_visibility: None,
        model_temperature: None,
        num_interactions: None,
        permanence: None,
        persona_visibility: None,
        revision: None,
        sharing_visibility: None,
        status: None,
        system_prompt_visibility: None,
        system_tags: None,
        token_budget: None,
        usage_hints: None,
        user_persona: None,
        user_persona_visibility: None,
        visibility: Some("private".to_string()),
        weight: None,
        world_scenario_visibility: None,
    }
}

/// Creates a mock chat session for testing
#[allow(dead_code)]
pub fn mock_chat_session(id: Uuid, character_id: Uuid) -> Chat {
    Chat {
        id,
        user_id: Uuid::new_v4(),
        character_id,
        title: Some("Mock Chat".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        system_prompt: Some("You are a helpful mock assistant".to_string()),
        temperature: Some(BigDecimal::from_str("0.7").unwrap()),
        max_output_tokens: Some(1024),
        frequency_penalty: Some(BigDecimal::from_str("0").unwrap()),
        presence_penalty: Some(BigDecimal::from_str("0").unwrap()),
        top_k: Some(40),
        top_p: Some(BigDecimal::from_str("0.95").unwrap()),
        repetition_penalty: Some(BigDecimal::from_str("1.03").unwrap()),
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        history_management_strategy: "window".to_string(),
        history_management_limit: 20,
        visibility: Some("private".to_string()),
        model_name: "default-model".to_string(),
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
    }
}

/// Creates a mock chat message for testing
#[allow(dead_code)]
pub fn mock_chat_message(
    id: Uuid,
    session_id: Uuid,
    role: MessageRole,
    content: &str,
) -> ChatMessage {
    ChatMessage {
        id,
        session_id,
        user_id: Uuid::nil(), // Use Uuid::nil() for test context
        message_type: role,
        content: content.to_string().into_bytes(),
        content_nonce: None,
        created_at: Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
    }
}
