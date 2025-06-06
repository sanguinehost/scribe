// frontend/src/lib/types.ts

// Placeholder for User type - Define based on expected fields from backend
export interface User {
    id: string;
    username: string;
    email: string;
    // Add other user-related fields as needed
}

// Message type based on backend MessageResponse
export interface Message {
    id: string;
    session_id: string;
    message_type: MessageRole;
    role: string;
    parts: any; // serde_json::Value from backend
    attachments: any; // serde_json::Value from backend
    created_at: Date;
    raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
}

// Placeholder for Vote type - Define based on expected fields from backend
export interface Vote {
    id: string;
    message_id: string;
    user_id: string;
    type_: 'up' | 'down';
    created_at: Date;
}

// Placeholder for Suggestion type - Define based on expected fields from backend
export interface Suggestion {
    id: string;
    document_id: string;
    document_created_at: string;
    original_text: string;
    suggested_text: string;
    description?: string;
    created_at: Date;
    updated_at: Date;
}

// Placeholder for Session type - Define based on expected fields from backend
export interface Session {
    id: string;
    user_id: string;
    expires_at: string;
}

// Placeholder for AuthUser type - Define based on expected fields from backend
export interface AuthUser {
    id: string;
    username: string;
    email: string;
    // Add other auth-related fields as needed
}

// Backend AuthResponse type
export interface BackendAuthResponse {
    user_id: string;
    username: string;
    email: string;
    role: string;
    recovery_key: string | null;
    default_persona_id: string | null;
}

// Placeholder for ScribeChatSession type - Define based on expected fields from backend
export interface ScribeChatSession {
    id: string;
    title: string;
    character_id: string;
    character_name?: string | null; // Added character_name
    user_id: string;
    created_at: string;
    updated_at: string;
    system_prompt?: string | null;
    personality?: string | null;
    scenario?: string | null;
    visibility?: VisibilityType | null;
    active_custom_persona_id?: string | null;
    model_name?: string | null;
    temperature?: number | null;
    max_output_tokens?: number | null;
    frequency_penalty?: number | null;
    presence_penalty?: number | null;
    top_k?: number | null;
    top_p?: number | null;
    seed?: number | null;
    gemini_thinking_budget?: number | null;
    gemini_enable_code_execution?: boolean | null;
    context_total_token_limit?: number | null;
    context_recent_history_budget?: number | null;
    context_rag_budget?: number | null;
}

// Placeholder for LoginSuccessData type - Define based on expected fields from backend
export interface LoginSuccessData {
    user: User;
    session: Session;
}

export type VisibilityType = 'public' | 'private';

// Message role type for Scribe messages
export type MessageRole = 'User' | 'Assistant' | 'System';

// Placeholder for Lorebook type - Define based on expected fields from backend
export interface Lorebook {
    id: string;
    user_id: string;
    name: string;
    description?: string | null;
    created_at: string;
    updated_at: string;
}

// Placeholder for LorebookEntry type - Define based on expected fields from backend
export interface LorebookEntry {
    id: string;
    lorebook_id: string;
    user_id: string;
    name: string;
    content: string;
    keywords: string[];
    created_at: string;
    updated_at: string;
}

// Placeholder for CreateLorebookPayload type - Define based on expected fields for creating a lorebook
export interface CreateLorebookPayload {
    name: string;
    description?: string | null;
}

// Placeholder for UpdateLorebookPayload type - Define based on expected fields for updating a lorebook
export interface UpdateLorebookPayload {
    name?: string;
    description?: string | null;
}

// Placeholder for CreateLorebookEntryPayload type - Define based on expected fields for creating a lorebook entry
export interface CreateLorebookEntryPayload {
    name: string;
    content: string;
    keywords: string[];
}

// Placeholder for UpdateLorebookEntryPayload type - Define based on expected fields for updating a lorebook entry
export interface UpdateLorebookEntryPayload {
    name?: string;
    content?: string;
    keywords?: string[];
}

// Placeholder for LorebookUploadPayload type - Define based on expected fields for lorebook upload
export interface LorebookUploadPayload {
    name: string;
    description?: string;
    entries: {
        name: string;
        content: string;
        keywords: string[];
    }[];
}

// Definition for ScribeMinimalLorebook
export interface ScribeMinimalLorebook {
    name: string;
    description?: string;
    entries: {
        title: string;
        content: string;
        keywords: string[];
    }[];
}

// Placeholder for ChatSessionLorebookAssociation type
export interface ChatSessionLorebookAssociation {
    chat_session_id: string;
    lorebook_id: string;
    user_id: string;
    lorebook_name: string;
    created_at: string;
}

// Enhanced version with source information
export type LorebookAssociationSource = 'Chat' | 'Character';

export interface EnhancedChatSessionLorebookAssociation {
    chat_session_id: string;
    lorebook_id: string;
    user_id: string;
    lorebook_name: string;
    source: LorebookAssociationSource;
    is_overridden: boolean;
    override_action?: string; // "disable" or "enable" if overridden
    created_at: string;
}

// Union type for API responses
export type ChatLorebookAssociationsResponse = 
    | ChatSessionLorebookAssociation[] 
    | EnhancedChatSessionLorebookAssociation[];

// Character lorebook override type
export interface CharacterLorebookOverrideResponse {
    id: string;
    chat_session_id: string;
    lorebook_id: string;
    user_id: string;
    action: string;
    created_at: string;
    updated_at: string;
}

// Character type based on backend CharacterDataForClient
export interface Character {
    id: string;
    user_id: string;
    spec: string;
    spec_version: string;
    name: string;
    description?: string | null;
    personality?: string | null;
    scenario?: string | null;
    first_mes?: string | null;
    mes_example?: string | null;
    creator_notes?: string | null;
    system_prompt?: string | null;
    post_history_instructions?: string | null;
    tags?: (string | null)[] | null;
    creator?: string | null;
    character_version?: string | null;
    alternate_greetings?: string[] | null;
    nickname?: string | null;
    creator_notes_multilingual?: any | null;
    source?: (string | null)[] | null;
    group_only_greetings?: (string | null)[] | null;
    creation_date?: string | null;
    modification_date?: string | null;
    created_at: string;
    updated_at: string;
    persona?: string | null;
    world_scenario?: string | null;
    avatar?: string | null;
    avatar_url?: string | null; // For backward compatibility
    chat?: string | null;
    greeting?: string | null;
    definition?: string | null;
    default_voice?: string | null;
    extensions?: any | null;
    data_id?: number | null;
    category?: string | null;
    definition_visibility?: string | null;
    depth?: number | null;
    example_dialogue?: string | null;
    favorite?: boolean | null;
    first_message_visibility?: string | null;
    height?: string | null;
    last_activity?: string | null;
    migrated_from?: string | null;
    model_prompt?: string | null;
    model_prompt_visibility?: string | null;
    model_temperature?: string | null;
    num_interactions?: number | null;
    permanence?: string | null;
    persona_visibility?: string | null;
    revision?: number | null;
    sharing_visibility?: string | null;
    status?: string | null;
    system_prompt_visibility?: string | null;
    system_tags?: (string | null)[] | null;
    token_budget?: number | null;
    usage_hints?: any | null;
    user_persona?: string | null;
    user_persona_visibility?: string | null;
    visibility?: string | null;
    weight?: string | null;
    world_scenario_visibility?: string | null;
}

// Scribe-specific character type alias for consistency
export type ScribeCharacter = Character;

// User Persona types
export interface UserPersona {
    id: string;
    user_id: string;
    name: string;
    description: string;
    spec?: string | null;
    spec_version?: string | null;
    personality?: string | null;
    scenario?: string | null;
    first_mes?: string | null;
    mes_example?: string | null;
    system_prompt?: string | null;
    post_history_instructions?: string | null;
    tags?: string[] | null;
    avatar?: string | null;
    created_at: string;
    updated_at: string;
}

export interface CreateUserPersonaRequest {
    name: string;
    description: string;
    spec?: string | null;
    spec_version?: string | null;
    personality?: string | null;
    scenario?: string | null;
    first_mes?: string | null;
    mes_example?: string | null;
    system_prompt?: string | null;
    post_history_instructions?: string | null;
    tags?: string[] | null;
    avatar?: string | null;
}

export interface UpdateUserPersonaRequest {
    name?: string;
    description?: string;
    spec?: string | null;
    spec_version?: string | null;
    personality?: string | null;
    scenario?: string | null;
    first_mes?: string | null;
    mes_example?: string | null;
    system_prompt?: string | null;
    post_history_instructions?: string | null;
    tags?: string[] | null;
    avatar?: string | null;
}


// Type definitions for message parts
export interface TextPart {
    text: string;
}

export interface ImagePart {
    image_url: string;
    alt?: string;
}

export type MessagePart = TextPart | ImagePart;

export interface MessageAttachment {
    type: string;
    data: unknown;
}

// Type definitions for API requests
export type CreateChatRequest = {
    title: string;
    character_id: string;
    system_prompt?: string | null;
    personality?: string | null;
    scenario?: string | null;
};

export type CreateMessageRequest = {
    role: string;
    content: string;
    parts?: MessagePart[];
    attachments?: MessageAttachment[];
};

export type VoteRequest = {
    type_: 'up' | 'down';
};

export type UpdateChatVisibilityRequest = {
    visibility: 'public' | 'private';
};

export type CreateDocumentRequest = {
    title: string;
    content?: string;
    kind: string;
};

export type CreateSuggestionRequest = {
    document_id: string;
    document_created_at: string;
    original_text: string;
    suggested_text: string;
    description?: string;
};

// Type definitions for API responses
export type ChatResponse = {
    id: string;
    title: string;
    created_at: Date;
    user_id: string;
    visibility?: string;
};

export type MessageResponse = {
    id: string;
    chat_id: string;
    role: string;
    parts: MessagePart[];
    attachments: MessageAttachment[];
    created_at: Date;
    raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
};

// Scribe-specific chat message interface for frontend components
export interface ScribeChatMessage {
    id: string;
    content: string;
    message_type: MessageRole;
    session_id?: string; // Chat session ID
    created_at?: string; // Creation timestamp
    user_id?: string; // User ID who created the message
    loading?: boolean;
    raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
}

export type DocumentResponse = {
    id: string;
    created_at: Date;
    title: string;
    content?: string;
    kind: string;
    user_id: string;
};

export type SessionResponse = {
    session: {
        id: string;
        user_id: string;
        expires_at: string | Date;
    };
    user: User;
};

export interface SuggestedActionItem {
    action: string;
}

export type SuggestedActionsResponse = {
    suggestions: SuggestedActionItem[];
};


// Types for Chat Session Settings
export interface UpdateChatSessionSettingsRequest {
    title?: string | null;
    system_prompt?: string | null;
    temperature?: number | null;
    max_output_tokens?: number | null;
    frequency_penalty?: number | null;
    presence_penalty?: number | null;
    top_k?: number | null;
    top_p?: number | null;
    seed?: number | null;
    history_management_strategy?: string | null;
    history_management_limit?: number | null;
    visibility?: VisibilityType | null;
    active_custom_persona_id?: string | null;
    model_name?: string | null;
    gemini_thinking_budget?: number | null;
    gemini_enable_code_execution?: boolean | null;
    context_total_token_limit?: number | null;
    context_recent_history_budget?: number | null;
    context_rag_budget?: number | null;
}

export interface ChatSessionSettingsResponse {
    model_name?: string | null;
    temperature?: number | null;
    max_output_tokens?: number | null;
    frequency_penalty?: number | null;
    presence_penalty?: number | null;
    top_k?: number | null;
    top_p?: number | null;
    seed?: number | null;
    gemini_thinking_budget?: number | null;
    gemini_enable_code_execution?: boolean | null;
    context_total_token_limit?: number | null;
    context_recent_history_budget?: number | null;
    context_rag_budget?: number | null;
    system_prompt?: string | null;
}