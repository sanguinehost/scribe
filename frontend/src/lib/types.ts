// frontend/src/lib/types.ts

/**
 * Represents the role of a chat message sender, mirroring the backend enum.
 */
export type MessageRole = 'User' | 'Assistant' | 'System';

/**
 * Represents a chat message structure based on the Scribe backend API.
 */
export interface ScribeChatMessage {
	id: string; // UUID
	session_id: string; // UUID
	message_type: MessageRole;
	content: string;
	created_at: string; // ISO 8601 DateTime string
	user_id: string; // UUID
	// Add any other relevant fields if needed for the UI, e.g., loading state
	loading?: boolean;
}

/**
 * Defines the possible visibility states for a chat session.
 */
export type VisibilityType = 'private' | 'public';

/**
 * Represents a chat session structure based on the Scribe backend API.
 * (Adding this as it's likely needed soon)
 */
export interface ScribeChatSession {
	id: string; // UUID
	user_id: string; // UUID
	character_id: string; // UUID
	title: string | null;
	system_prompt: string | null;
	temperature: number | null; // Assuming conversion from BigDecimal
	max_output_tokens: number | null;
	created_at: string; // ISO 8601 DateTime string
	updated_at: string; // ISO 8601 DateTime string
	// Add other settings fields if needed
	frequency_penalty: number | null;
	presence_penalty: number | null;
	top_k: number | null;
	top_p: number | null;
	repetition_penalty: number | null;
	min_p: number | null;
	top_a: number | null;
	seed: number | null;
	logit_bias: Record<string, number> | null; // Assuming JSON object maps to this
	history_management_strategy: string;
	history_management_limit: number;
	visibility: VisibilityType; // Added visibility property
}

/**
 * Represents a character structure based on the Scribe backend API.
 * (Minimal definition for now, add fields as needed)
 */
export interface ScribeCharacter {
	id: string; // UUID
	name: string;
	first_mes: string | null | undefined;
	system_prompt?: string | null; // Optional system prompt
	personality?: string | null; // Optional personality description
	scenario?: string | null; // Optional scenario description
	// Add other relevant character fields here, e.g., description, avatar_url
}
// Add other shared types as needed...

// Types for our application, previously defined in db/schema.ts

export type User = {
	user_id: string;
	email: string;
	username: string;
};

export type AuthUser = User & {
	password: string;
};

export type Session = {
	id: string;
	user_id: string;
	expires_at: Date;
};

export type Chat = {
	id: string;
	createdAt: Date;
	title: string;
	userId: string;
	visibility: 'public' | 'private';
};

export type MessagePart = {
	text?: string;
	imageUrl?: string;
	type?: string;
	[key: string]: unknown;
};

export type MessageAttachment = {
	type: string;
	url?: string;
	name?: string;
	size?: number;
	[key: string]: unknown;
};

export type Message = {
	id: string;
	chatId: string;
	role: string;
	parts: MessagePart[];
	attachments: MessageAttachment[];
	createdAt: Date;
};

export type Vote = {
	chatId: string;
	messageId: string;
	isUpvoted: boolean;
};

export type Document = {
	id: string;
	createdAt: Date;
	title: string;
	content: string;
	kind: 'text' | 'code' | 'image' | 'sheet';
	userId: string;
};

export type Suggestion = {
	id: string;
	documentId: string;
	documentCreatedAt: Date;
	originalText: string;
	suggestedText: string;
	description: string | null;
	isResolved: boolean;
	userId: string;
	createdAt: Date;
};