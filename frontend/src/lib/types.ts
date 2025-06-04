// frontend/src/lib/types.ts

// Placeholder for User type - Define based on expected fields from backend
export interface User {
    id: string;
    username: string;
    email: string;
    // Add other user-related fields as needed
}

// Placeholder for Message type - Define based on expected fields from backend
export interface Message {
    id: string;
    chat_id: string;
    role: string;
    parts: MessagePart[];
    attachments: MessageAttachment[];
    created_at: Date;
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

// Placeholder for ScribeChatSession type - Define based on expected fields from backend
export interface ScribeChatSession {
    id: string;
    title: string;
    character_id: string;
    user_id: string;
    created_at: string;
    updated_at: string;
    system_prompt?: string | null;
    personality?: string | null;
    scenario?: string | null;
    visibility?: VisibilityType | null;
    active_custom_persona_id?: string | null;
    model_name?: string | null;
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
    chat_id: string;
    lorebook_id: string;
    created_at: string;
}

// Placeholder for Character type - Define based on expected fields from GET /api/characters/{id}
export interface Character {
    id: string;
    name: string;
    description?: string;
    system_prompt?: string | null;
    personality?: string | null;
    scenario?: string | null;
    avatar_url?: string | null;
    greeting?: string | null;
}

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
};

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