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
	content: string; // Message content
	parts: MessagePart[]; // serde_json::Value from backend
	attachments: MessageAttachment[]; // serde_json::Value from backend
	created_at: Date;
	raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
	prompt_tokens?: number | null; // Token count for user messages
	completion_tokens?: number | null; // Token count for AI responses
	model_name?: string; // Model used for this specific message (optional for backward compatibility)
	status?: string; // Message status: streaming, completed, failed, partial, pending
	error_message?: string | null; // Error message if generation failed
	superseded_at?: string | null; // ISO 8601 timestamp when message was superseded
	contentVersion?: number; // Reactivity signal - increments when content changes during streaming
	// Variant metadata
	variant_count: number; // Number of variants for this message
	current_variant_index: number; // Currently selected variant index
	is_variant: boolean; // Whether this is a variant of another message
	parent_message_id?: string | null; // UUID of parent message if this is a variant
	variants?: MessageVariantResponse[] | null; // Array of variants for this message
}

// Message variant response type
export interface MessageVariantResponse {
	index: number; // Variant index (0 for original)
	content: string; // Variant content
	created_at: string; // ISO 8601 timestamp
	prompt_tokens?: number | null;
	completion_tokens?: number | null;
	model_name?: string | null;
}

// Request types for variant operations
export interface CreateMessageVariantRequest {
	content: string;
}

export interface SelectVariantRequest {
	variant_index: number;
}

// Model capabilities interface
export interface ModelCapabilities {
	context_window_size: number;
	max_output_tokens: number;
	provider: string;
	is_local: boolean;
	is_available: boolean;
	metadata: Record<string, string>;
}

// Recommended context settings from backend
export interface RecommendedContextSettings {
	total_token_limit: number;
	recent_history_budget: number;
	rag_budget: number;
}

// Enhanced model info with capabilities
export interface ModelInfo {
	id: string;
	name: string;
	description: string;
	isLocal: boolean;
	capabilities?: ModelCapabilities;
	recommended_settings?: RecommendedContextSettings;
	// Local model management properties (optional for cloud models)
	filename?: string;
	size_gb?: number;
	vram_required?: number;
	compatible?: boolean;
	downloaded?: boolean;
	active?: boolean;
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

// AuthUser type - matches backend AuthResponse structure
export interface AuthUser {
	user_id: string; // UUID, primary field from backend AuthResponse
	id: string; // Backwards compatibility - should map to user_id
	username: string;
	email: string;
	role: string;
	recovery_key: string | null;
	default_persona_id: string | null;
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
	chronicle_id?: string | null; // Backwards compatibility alias for player_chronicle_id
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
	total_prompt_tokens?: number;
	total_completion_tokens?: number;
	total_credits_used?: number | string; // BigDecimal from backend may serialize as string
	total_actual_cost?: number; // Raw cost in dollars (from backend)
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

// Lorebook type - Define based on expected fields from backend
export interface Lorebook {
	id: string;
	user_id: string;
	name: string;
	description?: string | null;
	source_format?: string | null; // Format of the lorebook (e.g., "json", "yaml")
	is_public?: boolean | null; // Visibility of the lorebook
	created_at: string;
	updated_at: string;
}

// LorebookEntry type matching backend LorebookEntryResponse
export interface LorebookEntry {
	id: string;
	lorebook_id: string;
	user_id: string;
	entry_title: string; // Backend uses entry_title, not name
	keys_text: string | null; // Backend field name
	content: string;
	comment: string | null;
	is_enabled: boolean; // Backend uses is_enabled
	is_constant: boolean;
	insertion_order: number;
	created_at: string;
	updated_at: string;
	// Backwards compatibility aliases
	name?: string; // For compatibility, maps to entry_title
	keywords?: string[]; // For compatibility, parsed from keys_text
	enabled?: boolean; // For compatibility, maps to is_enabled
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

// CreateLorebookEntryPayload type - matches backend expectations
export interface CreateLorebookEntryPayload {
	entry_title: string; // Backend field name
	content: string;
	keys_text: string; // Backend field name
	comment?: string;
	is_enabled?: boolean;
	is_constant?: boolean;
	insertion_order?: number;
	// Backwards compatibility
	name?: string; // Maps to entry_title (for compatibility)
	keywords?: string[]; // Maps to keys_text (for compatibility)
}

// UpdateLorebookEntryPayload type - matches backend expectations
export interface UpdateLorebookEntryPayload {
	entry_title?: string; // Backend field name
	content?: string;
	keys_text?: string; // Backend field name
	comment?: string;
	is_enabled?: boolean; // Backend field name
	is_constant?: boolean;
	insertion_order?: number;
	// Backwards compatibility
	name?: string; // Maps to entry_title
	keywords?: string[]; // Converts to keys_text
	enabled?: boolean; // Maps to is_enabled
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

/**
 * Request to create a new chat session.
 *
 * NOTE: This type is used differently depending on deployment mode:
 *
 * Desktop/SQLite (feature-flagged via isDesktopMode()):
 *   - Only sends: character_id, title, active_custom_persona_id, lorebook_ids
 *   - Other fields (chat_mode, system_prompt, personality, scenario) are NOT sent
 *
 * Cloud/PostgreSQL (default):
 *   - Sends all fields as-is
 *
 * See frontend/src/lib/api/index.ts createChat() for the feature-flagged implementation.
 */
export type CreateChatRequest = {
	title: string;
	chat_mode: ChatMode; // Only sent to Cloud/PostgreSQL
	character_id?: string | null;
	system_prompt?: string | null; // Only sent to Cloud/PostgreSQL
	personality?: string | null; // Only sent to Cloud/PostgreSQL
	scenario?: string | null; // Only sent to Cloud/PostgreSQL
	active_custom_persona_id?: string | null; // Sent to both backends
	lorebook_ids?: string[] | null; // Sent to both backends
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
	status?: string; // Message status: streaming, completed, failed, partial, pending
	superseded_at?: string | null; // ISO 8601 timestamp when message was superseded
	// Cost tracking fields (from backend)
	actual_cost?: number | null; // Raw Google API cost in dollars (always calculated)
	modified_cost?: number | null; // Cost with markup applied (when payment feature enabled)
	credit_cost?: number | null; // Credits consumed (when credits actually used)
	actual_charge?: number | null; // Actual dollar amount charged to user
	// Variant metadata
	variant_count?: number; // Number of variants for this message
	current_variant_index?: number; // Currently selected variant index
	is_variant?: boolean; // Whether this is a variant of another message
	parent_message_id?: string | null; // UUID of parent message if this is a variant
	variants?: MessageVariantResponse[] | null; // Array of variants for this message
	// UI state
	isRegenerating?: boolean; // Currently regenerating this message (shows loading indicator)
	shouldAnimate?: boolean; // True only for new streaming messages, false for historical messages
	contentVersion?: number; // Reactivity signal - increments when content changes during streaming (required for Svelte 5 fine-grained tracking)
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
	} | null;
	user: User | null;
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
	// NOTE: Must match backend UpdateChatSettingsRequest exactly (no extra fields!)
	// Extra fields cause 422 errors due to serde's default deny_unknown_fields
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
	active_custom_persona_id?: string | null;
	model_name?: string | null;
	model_provider?: string | null;
	gemini_thinking_budget?: number | null;
	gemini_enable_code_execution?: boolean | null;
	agent_mode?: string | null;
	prompt_template_id?: string | null;
}

export interface ChatSessionSettingsResponse {
	// Required fields matching backend ChatSettingsResponse
	model_name: string;
	model_provider?: string | null;
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
	agent_mode?: string | null;
	prompt_template_id?: string | null;
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

	// Local LLM Preferences
	local_llm_enabled?: boolean | null;
	preferred_local_model?: string | null;
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

	// Local LLM Preferences
	local_llm_enabled?: boolean | null;
	preferred_local_model?: string | null;

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
export type ImpersonateRequest = object; // Uses chat context

export interface ImpersonateResponse {
	generated_response: string;
}

// ============================================================================
// AI Generation Types
// ============================================================================

export type GenerationMode = 'create' | 'enhance' | 'rewrite' | 'expand';

/**
 * Description styles for character field generation
 * Based on proven style templates
 */
export type DescriptionStyle =
	| 'auto' // Let AI choose based on input (recommended)
	| 'traits' // Brief, comma-separated traits (e.g., "Tall. Silver hair. Former soldier.")
	| 'narrative' // Story-like flowing prose
	| 'profile' // Structured data fields (Name: Age: Height: etc.)
	| 'group' // Multiple character definitions with Characters() format
	| 'worldbuilding' // Rich lore and universe context
	| 'system'; // Behavioral instructions for AI roleplay

/**
 * Comprehensive metadata for AI generation operations
 * Provides transparency and debugging information
 */
export interface GenerationMetadata {
	model: string; // Model used for generation
	tokens_used: number; // Total tokens consumed
	cost?: number; // Estimated cost in credits/dollars
	generation_time_ms: number; // Time taken to generate
	finish_reason?: string; // Why generation stopped (stop, length, etc.)
	style_detected?: DescriptionStyle; // Auto-detected style if using 'auto'
	system_prompt?: string; // System prompt used (for debugging)
	user_prompt?: string; // User prompt sent (for debugging)
	lorebook_context_included?: boolean; // Whether lorebook context was used
	lorebook_entries_count?: number; // Number of lorebook entries included
	query_text_used?: string; // Query text used to search lorebook
	timestamp?: string; // ISO 8601 timestamp
	// Debug info nested object (for component compatibility)
	debug_info?: {
		lorebook_context_included?: boolean;
		lorebook_entries_count?: number;
		query_text_used?: string;
		model_used?: string;
		system_prompt?: string;
		user_message?: string;
		user_prompt?: string;
	};
}

/**
 * Streaming chunk for real-time generation display
 * Allows character-by-character streaming
 */
export interface GenerationChunk {
	content: string; // Content chunk (may be partial)
	done: boolean; // Whether generation is complete
	metadata?: GenerationMetadata; // Full metadata (only present when done=true)
}

/**
 * Style analysis response from backend
 * Uses structured outputs for reliable style detection
 */
export interface StyleAnalysisResponse {
	detected_style: DescriptionStyle; // The detected style
	confidence: number; // Confidence level (0.0 to 1.0)
	style_indicators: string[]; // Features that indicated this style
	recommendations: string[]; // Suggestions for improving the content
}

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
	lorebook_entries?: CharacterLorebookEntry[];
	associated_persona?: string;
	selectedLorebooks?: string[]; // Array of lorebook IDs to query for context (frontend-only)
}

// Character generation LorebookEntry type (different from main LorebookEntry)
export interface CharacterLorebookEntry {
	id: string;
	keys: string[];
	content: string;
	priority?: number;
	enabled: boolean;
}

// Character field generation
export interface GenerateCharacterFieldRequest {
	fieldName: string; // "description", "personality", "scenario", etc.
	fieldValue?: string; // Existing content to enhance/expand/rewrite (renamed from field_context)
	characterContext?: CharacterContext; // Existing character data for context
	mode: GenerationMode; // create, enhance, expand, rewrite (renamed from generation_mode)
	// Enhanced parameters from independent editor
	style?: DescriptionStyle; // Preferred description style
	maxTokens?: number; // Token limit for generation (500-5000)
	userPrompt?: string; // User's specific instructions/guidance
}

export interface GenerateCharacterFieldResponse {
	content: string; // Generated content
	metadata: GenerationMetadata; // Comprehensive generation metadata
	// Backwards compatibility fields
	style_used?: string; // Deprecated: use metadata.style_detected instead
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

// ============================================================================
// AI-Powered Lorebook Types (for /api/lorebooks/{id}/ai/* endpoints)
// ============================================================================

/**
 * Payload for AI-powered lorebook entry generation
 * Used by POST /api/lorebooks/{id}/ai/generate
 */
export interface GenerateAILorebookEntriesPayload {
	/** Theme or context for generating entries (e.g., "medieval fantasy tavern", "sci-fi space station") */
	theme: string;
	/** Number of entries to generate (1-20) */
	count: number;
	/** Optional additional context to guide generation */
	context?: string;
}

/**
 * Preview information for a generated lorebook entry
 */
export interface GeneratedEntryPreview {
	id: string;
	entry_title: string;
	keys_text?: string;
}

/**
 * Response from AI-powered lorebook entry generation
 */
export interface GenerateAILorebookEntriesResponse {
	success: boolean;
	entries_generated: number;
	/** Preview of generated entries (titles and IDs) */
	entries: GeneratedEntryPreview[];
	message: string;
}

/**
 * Structured analysis of a lorebook
 */
export interface LorebookAnalysis {
	/** Missing information or themes that would strengthen the lorebook */
	gaps: string[];
	/** Contradictions or inconsistencies found between entries */
	consistency_issues: string[];
	/** Specific suggestions for enhancing existing entries */
	improvement_suggestions: string[];
	/** New entry themes that would add value to the lorebook */
	recommended_themes: string[];
}

/**
 * Response from AI-powered lorebook analysis
 * Used by POST /api/lorebooks/{id}/ai/analyze
 */
export interface AnalyzeAILorebookResponse {
	success: boolean;
	entries_analyzed: number;
	analysis: LorebookAnalysis;
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
		payload: unknown; // Specific action data
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
	user_id: string;
	event_type: string;
	summary: string;
	source: EventSource;
	keywords?: string[] | null; // New simplified field
	timestamp_iso8601: string; // Story timeline timestamp
	chat_session_id?: string | null; // Link to originating chat
	created_at: string;
	updated_at: string;
}

export type EventSource = 'USER_ADDED' | 'AI_EXTRACTED' | 'GAME_API' | 'SYSTEM';

export interface CreateEventRequest {
	event_type: string;
	summary: string;
	source: EventSource;
	keywords?: string[] | null;
	timestamp_iso8601?: string | null;
	chat_session_id?: string | null;
}

export interface EventFilter {
	event_type?: string | null;
	source?: EventSource | null;
	keywords?: string[] | null;
	after_timestamp?: string | null;
	before_timestamp?: string | null;
	chat_session_id?: string | null;
	order_by?: EventOrderBy | null;
	limit?: number | null;
	offset?: number | null;
}

export type EventOrderBy =
	| 'created_at_asc'
	| 'created_at_desc'
	| 'updated_at_asc'
	| 'updated_at_desc'
	| 'timestamp_asc'
	| 'timestamp_desc';

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

// Agent context analysis types
export interface AgentAnalysisResponse {
	id: string;
	chat_session_id: string;
	analysis_type: string;
	agent_reasoning: string | null;
	planned_searches: unknown | null;
	execution_log: unknown | null;
	retrieved_context: string | null;
	analysis_summary: string | null;
	total_tokens_used: number | null;
	execution_time_ms: number | null;
	model_used: string | null;
	created_at: string | null;
	updated_at: string | null;
	message_id: string | null;
}

// Chat deletion analysis types
export interface ChronicleAnalysis {
	id: string;
	name: string;
	total_events: number;
	events_from_this_chat: number;
	other_chats_using_chronicle: number;
	can_delete_chronicle: boolean;
}

export interface ChatDeletionAnalysisResponse {
	has_chronicle: boolean;
	chronicle?: ChronicleAnalysis;
}

export type ChronicleAction = 'delete_chronicle' | 'disassociate' | 'delete_events';

export interface DeleteChatRequest {
	chronicle_action?: ChronicleAction;
}

// LLM Management Types for Local Model Support

export interface LlmInfoResponse {
	local_llm_enabled: boolean; // Feature is available
	server_running: boolean; // Server is actually running
	hardware: Event; // Hardware capabilities as JSON
	models: LocalModelInfo[];
	download_progress?: DownloadProgressInfo | null;
}

export interface LocalModelInfo {
	id: string;
	name: string;
	filename: string;
	size_gb: number;
	vram_required: number;
	compatible: boolean;
	downloaded: boolean;
	active: boolean;
	description: string;
}

export interface DownloadProgressInfo {
	model_id: string;
	total_bytes: number;
	downloaded_bytes: number;
	percentage: number;
	speed_bytes_per_sec?: number | null;
}

export interface DownloadModelRequest {
	model_id: string;
}

export interface DownloadModelResponse {
	success: boolean;
	message: string;
	download_id?: string | null;
}

export interface ModelRecommendation {
	model_name: string;
	priority_score: number;
	performance_estimate: 'Low' | 'Medium' | 'High';
	reasons: string[];
	estimated_download_time?: number | null; // Duration in seconds
	disk_space_required: number;
}

export interface GroupedModelInfo {
	base_model_id: string;
	base_model_name: string;
	description: string;
	parameter_count: string;
	context_window: number;
	huggingface_repo: string;
	variants: ModelVariantInfo[];
}

export interface ModelVariantInfo {
	id: string;
	quantization: string;
	filename: string;
	size_gb: number;
	vram_required: number;
	compatible: boolean;
	downloaded: boolean;
	active: boolean;
	recommended: boolean;
	quality_level: string; // Very Compact, Compact, Balanced, Good Quality, etc.
}

export interface ModelActionResponse {
	success: boolean;
	message: string;
	active_model?: string;
}

export interface HardwareCapabilities {
	total_ram_gb: number;
	available_ram_gb: number;
	cpu_cores: number;
	cpu_arch: string;
	gpu_info: GpuInfo[];
	has_cuda: boolean;
	has_metal: boolean;
	os: string;
}

export interface GpuInfo {
	name: string;
	vram_gb?: number | null;
	cuda_capable: boolean;
	device_id: number;
}

// Prompt Template Types

export interface TemplateCompatibility {
	requires_character: boolean;
	supports_rag: boolean;
	supports_personas: boolean;
}

export interface PromptTemplateInfo {
	id: string;
	version: string;
	name: string;
	description: string;
	compatibility: TemplateCompatibility;
}

export interface PromptTemplateListResponse {
	templates: PromptTemplateInfo[];
}

// ============================================================================
// Payment & Subscription Types
// ============================================================================

export type SubscriptionStatus =
	| 'active'
	| 'canceled'
	| 'past_due'
	| 'trialing'
	| 'unpaid'
	| 'incomplete'
	| 'expired'
	| 'pending_cancellation';
export type PlanType = 'free' | 'basic' | 'premium' | 'pro'; // Added 'pro' for legacy compatibility

export interface Subscription {
	id: string;
	user_id: string;
	paddle_customer_id?: string;
	paddle_subscription_id?: string;
	plan_type: PlanType;
	status: SubscriptionStatus;
	current_period_start: string; // ISO date
	current_period_end: string; // ISO date
	cancel_at_period_end?: boolean;
	trial_end?: string; // ISO date
	has_ever_paid?: boolean | null; // Tracks if subscription ever converted from trial to paid
	first_payment_date?: string | null; // ISO date - when trial first converted to paid
	created_at?: string; // ISO date
	updated_at?: string; // ISO date
}

export interface BillingFeatures {
	display_price: string;
	billing_period: 'monthly' | 'yearly';
	trial_days: number;
	cancel_anytime: boolean;
	monthly_equivalent?: string;
	savings_message?: string;
}

export interface PlanFeatures {
	plan_type: PlanType;
	display_name: string;
	description: string;
	price_monthly: number;
	price_yearly?: number;
	annual_savings_percent?: number;
	paddle_price_id_monthly?: string;
	paddle_price_id_yearly?: string;
	max_context_tokens?: number; // Subscription tier context limit
	billing_features?: {
		monthly: BillingFeatures;
		yearly: BillingFeatures;
	};
	limits: {
		daily_messages: number;
		daily_limit_type: 'hard' | 'soft';
		context_tokens: number;
		chronicles_enabled: boolean;
		lorebooks_enabled: boolean;
		personas_enabled: boolean;
		max_characters: number;
		max_lorebooks: number;
	};
	credits: {
		included_monthly: number;
		welcome_bonus?: number;
		rollover_enabled?: boolean;
		rollover_max?: number;
		purchase_discount?: number;
	};
	models: {
		allowed: string[];
		default: string;
	};
	features: {
		priority_support?: boolean;
		api_access?: boolean;
		beta_features?: boolean;
		export_enabled?: boolean;
		import_enabled?: boolean;
		custom_personas?: boolean;
		priority_queue?: boolean;
		advanced_analytics?: boolean;
	};
}

export interface UsageLimitsResponse {
	tokens_used_total: number;
	period_start: string; // ISO date
	period_end: string; // ISO date
	is_unlimited: boolean;
	// Daily usage fields
	daily_message_count?: number;
	is_throttled?: boolean;
	throttle_delay?: number;
}

export interface SubscriptionResponse {
	subscription?: Subscription;
	plan_features?: PlanFeatures;
	usage_limits?: UsageLimitsResponse;
	customer_portal_url?: string;
}

export interface PlansResponse {
	plans: PlanFeatures[];
	current_plan?: PlanType;
}

export interface CreatePaymentRequest {
	plan_type: PlanType;
	success_url?: string;
	cancel_url?: string;
}

export interface CreatePaymentResponse {
	transaction_id: string;
	checkout_url: string;
	status: string;
}

export interface CancelSubscriptionRequest {
	immediate?: boolean;
}

// Extended User type with subscription info
export interface UserWithSubscription extends User {
	subscription?: Subscription;
	plan_features?: PlanFeatures;
	usage_limits?: UsageLimitsResponse;
}

// ============================================================================
// Template Preferences Types
// ============================================================================

/**
 * Narrative tense options for template generation
 */
export type NarrativeTense = 'past-tense' | 'present-tense' | 'future-tense';

/**
 * Narrative perspective options
 */
export type NarrativeNarration = 'first-person' | 'second-person' | 'third-person';

/**
 * Narrative point of view options
 */
export type NarrativePerspective = 'character-pov' | 'omniscient' | 'limited';

/**
 * Response length preferences
 */
export type ResponseLength = 'concise' | 'balanced' | 'detailed' | 'flexible';

/**
 * Template preferences response from backend
 * Matches backend TemplatePreferenceResponse
 */
export interface TemplatePreferenceResponse {
	id: string;
	user_id: string;
	character_id: string | null; // Nullable - applies to global settings when null
	template_id: string | null;
	tense: NarrativeTense;
	narration: NarrativeNarration;
	perspective: NarrativePerspective;
	length: ResponseLength;
	enable_info_box: boolean;
	enable_stats_tracker: boolean;
	enable_thinking: boolean;
	created_at: string; // ISO 8601 timestamp
	updated_at: string; // ISO 8601 timestamp
}

/**
 * Update request for template preferences
 * All fields are optional - only updates provided fields
 */
export interface UpdateTemplatePreferenceRequest {
	template_id?: string | null;
	tense?: NarrativeTense;
	narration?: NarrativeNarration;
	perspective?: NarrativePerspective;
	length?: ResponseLength;
	enable_info_box?: boolean;
	enable_stats_tracker?: boolean;
	enable_thinking?: boolean;
}

// ============================================================================
// Desktop Authentication Types
// ============================================================================

/**
 * Desktop authentication mode options
 */
export type DesktopAuthMode = 'quick_start' | 'account' | 'not_set';

/**
 * Desktop deployment mode options
 */
export type DesktopDeploymentMode = 'local' | 'remote';

/**
 * Desktop configuration response from backend
 * Returned by GET /api/auth/desktop/config
 */
export interface DesktopConfigResponse {
	setup_complete: boolean;
	auth_mode: DesktopAuthMode;
	deployment_mode: DesktopDeploymentMode;
}

/**
 * Desktop setup payload for initial wizard
 * Sent to POST /api/auth/desktop/setup
 */
export interface DesktopSetupPayload {
	auth_mode: DesktopAuthMode;
	username?: string; // Required when auth_mode is 'account'
	password?: string; // Required when auth_mode is 'account'
}

/**
 * Payload for upgrading Quick Start to Account mode
 * Sent to POST /api/auth/desktop/upgrade-account
 */
export interface DesktopUpgradeAccountPayload {
	username: string;
	password: string;
}
