// frontend/src/lib/types.ts

// Placeholder for User type - Define based on expected fields from backend
export interface User {
	user_id: string; // UUID, primary field from backend AuthResponse
	username: string;
	email: string;
	role: string;
	recovery_key: string | null;
	default_persona_id: string | null; // UUID
	avatar?: string | null; // Add avatar field
	// Backwards compatibility - should map to user_id
	id: string;
}

// Message type based on backend MessageResponse
export interface Message {
	id: string;
	session_id: string;
	message_type: MessageRole;
	role: string;
	parts: MessagePart[]; // serde_json::Value from backend
	attachments: MessageAttachment[]; // serde_json::Value from backend
	created_at: Date;
	raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
	prompt_tokens?: number | null; // Token count for user messages
	completion_tokens?: number | null; // Token count for AI responses
	model_name?: string; // Model used for this specific message (optional for backward compatibility)
}

// Paginated messages response for infinite scroll
export interface PaginatedMessagesResponse {
	messages: Message[];
	nextCursor: string | null; // ISO 8601 timestamp or null if no more messages
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
	character_id: string | null; // CHANGED: Now nullable for non-character modes
	character_name?: string | null; // Added character_name
	chat_mode: ChatMode; // NEW: Required chat mode field
	player_chronicle_id?: string | null; // Chronicle association (backend field name: player_chronicle_id)
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

// LoginSuccessData type matching the backend LoginSuccessResponse
export interface LoginSuccessData {
	user: User;
	session_id: string;
	expires_at: string; // ISO 8601 datetime string
}

export type VisibilityType = 'public' | 'private';

// Message role type for Scribe messages
export type MessageRole = 'User' | 'Assistant' | 'System';

// Chat Mode type - matches backend ChatMode enum
export type ChatMode = 'Character' | 'ScribeAssistant' | 'Rpg';

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
export interface CharacterDataForClient {
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
	creator_notes_multilingual?: unknown | null;
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
	extensions?: unknown | null;
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
	usage_hints?: unknown | null;
	user_persona?: string | null;
	user_persona_visibility?: string | null;
	visibility?: string | null;
	weight?: string | null;
	world_scenario_visibility?: string | null;
	// SillyTavern v3 fields
	fav?: boolean | null;
	world?: string | null;
	lorebook_id?: string | null; // Deprecated - for backward compatibility
	lorebook_ids: string[]; // Multiple lorebooks support - always present, may be empty
	creator_comment?: string | null;
	depth_prompt?: string | null;
	depth_prompt_depth?: number | null;
	depth_prompt_role?: string | null;
	talkativeness?: string | null;
}

// Scribe-specific character type alias for consistency
export type ScribeCharacter = CharacterDataForClient;
export type Character = CharacterDataForClient;

// User Persona types
export interface UserPersona {
	id: string;
	user_id: string;
	name: string;
	description: string | null;
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
	description?: string | null;
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
	chat_mode: ChatMode; // NEW: Required chat mode field
	character_id?: string | null; // CHANGED: Optional for non-character modes
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
	id: string; // Stable frontend ID for UI consistency
	backend_id?: string; // Actual backend ID (updates after save)
	content: string;
	message_type: MessageRole;
	session_id?: string; // Chat session ID
	created_at?: string; // Creation timestamp
	user_id?: string; // User ID who created the message
	loading?: boolean;
	error?: string | null; // Error message if generation failed
	retryable?: boolean; // Whether this message can be retried
	raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
	prompt_tokens?: number | null; // Token count for user messages
	completion_tokens?: number | null; // Token count for AI responses
	model_name?: string; // Model used for this specific message
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

export interface SuggestedActionsTokenUsage {
	input_tokens: number;
	output_tokens: number;
	total_tokens: number;
}

export type SuggestedActionsResponse = {
	suggestions: SuggestedActionItem[];
	token_usage?: SuggestedActionsTokenUsage;
};

// Types for Chat Session Settings
export interface UpdateChatSessionSettingsRequest {
	title?: string | null;
	chronicle_id?: string | null; // Associate chat with chronicle (backend API uses chronicle_id)
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
	// Required fields matching backend ChatSettingsResponse
	model_name: string;
	history_management_strategy: string;
	history_management_limit: number;
	// Optional fields
	temperature?: number | null;
	max_output_tokens?: number | null;
	frequency_penalty?: number | null;
	presence_penalty?: number | null;
	top_k?: number | null;
	top_p?: number | null;
	seed?: number | null;
	stop_sequences?: (string | null)[] | null;
	gemini_thinking_budget?: number | null;
	gemini_enable_code_execution?: boolean | null;
	chronicle_id?: string | null; // Chronicle association (backend API returns chronicle_id)
	// Context fields that don't exist in backend but are expected by frontend components
	context_total_token_limit?: number | null;
	context_recent_history_budget?: number | null;
	context_rag_budget?: number | null;
}

// Types for Global User Settings
export interface UpdateUserSettingsRequest {
	// Generation Settings
	default_model_name?: string | null;
	default_temperature?: number | null;
	default_max_output_tokens?: number | null;
	default_frequency_penalty?: number | null;
	default_presence_penalty?: number | null;
	default_top_p?: number | null;
	default_top_k?: number | null;
	default_seed?: number | null;

	// Gemini-Specific Settings
	default_gemini_thinking_budget?: number | null;
	default_gemini_enable_code_execution?: boolean | null;

	// Context Management Settings
	default_context_total_token_limit?: number | null;
	default_context_recent_history_budget?: number | null;
	default_context_rag_budget?: number | null;

	// Application Preferences
	auto_save_chats?: boolean | null;
	theme?: string | null;
	notifications_enabled?: boolean | null;
	typing_speed?: number | null;
}

export interface UserSettingsResponse {
	// Generation Settings
	default_model_name?: string | null;
	default_temperature?: number | null;
	default_max_output_tokens?: number | null;
	default_frequency_penalty?: number | null;
	default_presence_penalty?: number | null;
	default_top_p?: number | null;
	default_top_k?: number | null;
	default_seed?: number | null;

	// Gemini-Specific Settings
	default_gemini_thinking_budget?: number | null;
	default_gemini_enable_code_execution?: boolean | null;

	// Context Management Settings
	default_context_total_token_limit?: number | null;
	default_context_recent_history_budget?: number | null;
	default_context_rag_budget?: number | null;

	// Application Preferences
	auto_save_chats?: boolean | null;
	theme?: string | null;
	notifications_enabled?: boolean | null;
	typing_speed?: number | null;

	// Timestamps
	created_at: string;
	updated_at: string;
}

// Text expansion types
export interface ExpandTextRequest {
	original_text: string;
}

export interface ExpandTextResponse {
	expanded_text: string;
}

// Impersonate request (for generating full user response)
export interface ImpersonateRequest {
	// Empty for now, uses chat context
}

export interface ImpersonateResponse {
	generated_response: string;
}

// ============================================================================
// AI Generation Types
// ============================================================================

export type GenerationMode = 'create' | 'enhance' | 'rewrite' | 'expand';

export interface CharacterContext {
	name?: string;
	description?: string;
	personality?: string;
	scenario?: string;
	first_mes?: string;
	tags?: string[];
	mes_example?: string;
	system_prompt?: string;
	depth_prompt?: string;
	alternate_greetings?: string[];
	lorebook_entries?: LorebookEntry[];
	associated_persona?: string;
	selectedLorebooks?: string[]; // Array of lorebook IDs to query for context (frontend-only)
}

// Backend LorebookEntry for character context
export interface LorebookEntry {
	id: string;
	keys: string[];
	content: string;
	priority?: number;
	enabled: boolean;
}

// Character field generation
export interface GenerateCharacterFieldRequest {
	field_name: string; // "description", "personality", "scenario", etc.
	field_context?: string; // Existing content to enhance
	character_context?: CharacterContext; // Existing character data for context
	generation_prompt?: string; // User's specific instructions
	generation_mode: GenerationMode;
}

export interface GenerateCharacterFieldResponse {
	content: string;
	style_used: string;
	metadata: {
		tokens_used: number;
		generation_time_ms: number;
		style_detected?: string | null;
		model_used: string;
		timestamp: string;
		debug_info?: {
			system_prompt: string;
			user_message: string;
			lorebook_context_included: boolean;
			lorebook_entries_count?: number | null;
			query_text_used?: string | null;
		} | null;
	};
}

// Complete character generation
export interface GenerateCompleteCharacterRequest {
	character_prompt: string; // High-level description or concept
	generation_style?: string; // Style preferences
	include_fields?: string[]; // Which fields to generate
}

export interface GenerateCompleteCharacterResponse {
	character: {
		name?: string;
		description?: string;
		personality?: string;
		scenario?: string;
		first_mes?: string;
		mes_example?: string;
		tags?: string[];
	};
	suggestions?: {
		alternative_names?: string[];
		alternative_concepts?: string[];
	};
}

// Character enhancement
export interface EnhanceCharacterRequest {
	character_data: CharacterContext;
	enhancement_prompt: string; // What to improve or focus on
	target_fields?: string[]; // Specific fields to enhance
}

export interface EnhanceCharacterResponse {
	enhanced_character: CharacterContext;
	changes_summary: string; // Description of what was changed
}

// Lorebook generation
export interface GenerateLorebookEntryRequest {
	entry_prompt: string;
	existing_entries_context?: string; // Context from existing lorebook
	character_context?: CharacterContext; // Related character context
	entry_type?: string; // "character", "location", "item", "event", etc.
}

export interface GenerateLorebookEntryResponse {
	entry: {
		name: string;
		content: string;
		keys: string[];
		priority?: number;
	};
	suggestions?: {
		related_entries?: string[];
		additional_keys?: string[];
	};
}

export interface GenerateLorebookEntriesRequest {
	entries_prompt: string; // Overall theme or world concept
	entry_count?: number; // How many entries to generate
	existing_lorebook_context?: string;
	character_context?: CharacterContext;
}

export interface GenerateLorebookEntriesResponse {
	entries: Array<{
		name: string;
		content: string;
		keys: string[];
		priority?: number;
	}>;
	world_summary?: string; // Overall description of the generated content
}

// Scribe Assistant (Chat mode for content creation)
export interface ScribeAssistantRequest {
	message: string; // User's message/request
	context?: {
		character_data?: CharacterContext;
		lorebook_data?: string;
		session_history?: Array<{
			role: 'user' | 'assistant';
			content: string;
		}>;
	};
	mode?: 'character_creation' | 'character_editing' | 'lorebook_creation' | 'general';
}

export interface ScribeAssistantResponse {
	response: string; // Assistant's response
	actions?: Array<{
		type: 'generate_field' | 'create_character' | 'create_lorebook_entry';
		payload: any; // Specific action data
		description: string;
	}>;
	suggestions?: string[]; // Follow-up suggestions
}

// Chronicle types
export interface PlayerChronicle {
	id: string;
	user_id: string;
	name: string;
	description: string | null;
	created_at: string;
	updated_at: string;
}

export interface PlayerChronicleWithCounts extends PlayerChronicle {
	event_count: number;
	chat_session_count: number;
}

export interface CreateChronicleRequest {
	name: string;
	description?: string | null;
}

export interface UpdateChronicleRequest {
	name?: string | null;
	description?: string | null;
}

export interface ChronicleEvent {
	id: string;
	chronicle_id: string;
	event_type: string;
	summary: string;
	source: EventSource;
	event_data: any | null;
	created_at: string;
	updated_at: string;
}

export type EventSource = 'USER_ADDED' | 'AI_EXTRACTED' | 'GAME_API' | 'SYSTEM';

export interface CreateEventRequest {
	event_type: string;
	summary: string;
	source: EventSource;
	event_data?: any | null;
}

export interface EventFilter {
	event_type?: string | null;
	source?: EventSource | null;
	order_by?: EventOrderBy | null;
	limit?: number | null;
	offset?: number | null;
}

export type EventOrderBy = 'created_at_asc' | 'created_at_desc' | 'updated_at_asc' | 'updated_at_desc';

// Token counting types
export interface TokenCountRequest {
	text: string;
	model?: string;
	use_api_counting?: boolean;
}

export interface TokenCountResponse {
	total: number;
	text: number;
	images: number;
	video: number;
	audio: number;
	is_estimate: boolean;
	model_used: string;
	counting_method: string;
}
