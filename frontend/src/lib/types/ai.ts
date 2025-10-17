/**
 * AI Generation Types
 *
 * Type definitions for AI-powered character field generation.
 * Supports multiple providers via abstraction layer.
 *
 * Security: Implements OWASP LLM Top 10 mitigations
 */

/**
 * Supported AI providers
 * - openrouter: Unified API for multiple models (primary)
 * - google: Direct Google Gemini API (stretch goal)
 * - anthropic: Direct Anthropic Claude API (stretch goal)
 * - openai: Direct OpenAI API (stretch goal)
 */
export type AIProvider = 'openrouter' | 'google' | 'anthropic' | 'openai';

/**
 * Generation modes for AI content creation
 * - create: Generate from scratch
 * - enhance: Improve existing content
 * - expand: Add more detail to existing content
 * - rewrite: Rewrite in different words/style
 */
export type GenerationMode = 'create' | 'enhance' | 'expand' | 'rewrite';

/**
 * Description styles for character descriptions
 * Based on Scribe's proven style templates
 */
export type DescriptionStyle =
	| 'auto' // Let AI choose based on input
	| 'traits' // Brief, punchy traits (e.g., "Tall. Silver hair. Former soldier.")
	| 'narrative' // Story-like flowing prose
	| 'profile' // Structured data fields (Name: Age: Height: etc.)
	| 'group' // Multiple character definitions with Characters() format
	| 'worldbuilding' // Rich lore and universe context
	| 'system'; // Behavioral instructions for AI roleplay

/**
 * AI model configuration
 */
export interface AIModel {
	/** Model ID (e.g., 'google/gemini-2.0-flash-exp') */
	id: string;
	/** Display name */
	name: string;
	/** Provider name for grouping */
	provider: string;
	/** Maximum context window in tokens */
	contextWindow: number;
	/** Cost per 1000 tokens */
	costPer1kTokens: {
		input: number;
		output: number;
	};
	/** Whether model supports streaming */
	supportsStreaming: boolean;
	/** Optional: Recommended use cases */
	recommendedFor?: string[];
	/** Whether model supports image generation */
	supportsImageGeneration?: boolean;
	/** Output modalities (e.g., ['text', 'image']) */
	outputModalities?: ('text' | 'image')[];
}

/**
 * Character context for AI generation
 * Provides existing character information to guide generation
 */
export interface CharacterContext extends Record<string, unknown> {
	name?: string;
	description?: string;
	personality?: string;
	scenario?: string;
	tags?: string[];
	first_mes?: string;
	mes_example?: string;
	system_prompt?: string;
	alternate_greetings?: string[];
}

/**
 * JSON Schema for OpenRouter structured outputs
 * See: https://openrouter.ai/docs/features/structured-outputs
 */
export interface JSONSchema {
	type: 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null';
	properties?: Record<string, JSONSchema>;
	items?: JSONSchema;
	required?: string[];
	additionalProperties?: boolean;
	description?: string;
	enum?: (string | number)[];
}

/**
 * OpenRouter response format for structured outputs
 */
export interface ResponseFormat {
	type: 'json_schema';
	json_schema: {
		name: string;
		strict: boolean;
		schema: JSONSchema;
	};
}

/**
 * Request for AI field generation
 */
export interface GenerationRequest {
	/** Field name being generated (e.g., 'description', 'personality') */
	fieldName: string;
	/** Current field value (for enhance/expand/rewrite modes) */
	fieldValue?: string;
	/** Character context for better generation */
	characterContext?: CharacterContext;
	/** Generation mode */
	mode: GenerationMode;
	/** Style (for description field) */
	style?: DescriptionStyle;
	/** User's custom prompt/instructions */
	userPrompt?: string;
	/** Max tokens for generation */
	maxTokens?: number;
	/** Temperature (0-1) for randomness */
	temperature?: number;
	/** Response format for structured outputs (optional) */
	responseFormat?: ResponseFormat;
}

/**
 * Generation metadata for transparency and debugging
 */
export interface GenerationMetadata {
	/** Model used for generation */
	model: string;
	/** Tokens used in generation */
	tokensUsed: number;
	/** Estimated cost in USD */
	cost: number;
	/** Time taken for generation in milliseconds */
	generationTimeMs: number;
	/** Finish reason from API */
	finishReason?: string;
	/** Detected or applied style */
	styleDetected?: DescriptionStyle;
	/** System prompt used (for debug modal) */
	systemPrompt?: string;
	/** User prompt sent (for debug modal) */
	userPrompt?: string;
	/** Whether lorebook context was included in generation */
	lorebookContextIncluded?: boolean;
	/** Number of lorebook entries used */
	lorebookEntriesCount?: number;
	/** Query text used to search lorebook */
	queryTextUsed?: string;
}

/**
 * Response from AI generation
 */
export interface GenerationResponse {
	/** Generated content */
	content: string;
	/** Generation metadata */
	metadata: GenerationMetadata;
}

/**
 * Streaming chunk from AI generation
 */
export interface GenerationChunk {
	/** Text chunk (empty on final chunk) */
	content: string;
	/** Whether this is the final chunk */
	done: boolean;
	/** Optional metadata (sent on completion) */
	metadata?: GenerationMetadata;
}

/**
 * Request for AI image generation
 */
export interface ImageGenerationRequest {
	/** Description/prompt for the image */
	prompt: string;
	/** Asset type to generate (e.g., 'icon', 'background', 'emotion') */
	assetType?: string;
	/** Character context for generating character-specific images */
	characterContext?: CharacterContext;
	/** Max tokens for generation (affects quality/detail) */
	maxTokens?: number;
}

/**
 * Response from AI image generation
 */
export interface ImageGenerationResponse {
	/** Generated image as base64 data URL */
	imageDataUrl: string;
	/** Generation metadata */
	metadata: GenerationMetadata;
}

/**
 * Rate limiting configuration
 * Implements OWASP LLM10: Unbounded Consumption mitigation
 */
export interface RateLimitConfig {
	/** Maximum requests per minute */
	requestsPerMinute: number;
	/** Maximum tokens per day */
	maxTokensPerDay: number;
	/** Maximum tokens per single request */
	maxTokensPerRequest: number;
}

/**
 * PII detection result
 * Implements OWASP LLM02: Sensitive Information Disclosure mitigation
 */
export interface PIIDetectionResult {
	/** Whether PII was detected */
	detected: boolean;
	/** Types of PII found (e.g., ['email', 'phone']) */
	types: string[];
	/** Specific matches (masked for display) */
	matches?: Array<{
		type: string;
		value: string; // Partially masked (e.g., 'j***@example.com')
		position: number;
	}>;
}

/**
 * AI settings stored in encrypted localStorage
 */
export interface AISettings {
	/** Active provider */
	provider: AIProvider;
	/** OpenRouter API key (encrypted) */
	openrouterApiKey: string;
	/** Google API key (encrypted, optional) */
	googleApiKey?: string;
	/** Anthropic API key (encrypted, optional) */
	anthropicApiKey?: string;
	/** OpenAI API key (encrypted, optional) */
	openaiApiKey?: string;
	/** Selected model ID */
	selectedModel: string;
	/** Rate limiting config */
	rateLimit: RateLimitConfig;
	/** Privacy settings */
	privacy: {
		/** Enable PII detection */
		enablePIIDetection: boolean;
		/** Warn before sending PII */
		warnOnPII: boolean;
	};
	/** UX settings */
	ux: {
		/** Enable streaming generation */
		enableStreaming: boolean;
		/** Show cost estimates */
		showCostEstimates: boolean;
	};
	/** Usage tracking */
	usage: {
		/** Tokens used today */
		tokensUsedToday: number;
		/** Requests made this minute */
		requestsThisMinute: number;
		/** Total cost incurred */
		totalCost: number;
		/** Last reset timestamp */
		lastReset: number;
	};
}

/**
 * Error types for AI operations
 */
export class AIError extends Error {
	constructor(
		message: string,
		public code: string,
		public details?: unknown
	) {
		super(message);
		this.name = 'AIError';
	}
}

export class RateLimitError extends AIError {
	constructor(message: string) {
		super(message, 'RATE_LIMIT_EXCEEDED');
		this.name = 'RateLimitError';
	}
}

export class PIIDetectedError extends AIError {
	constructor(
		public piiTypes: string[],
		public piiMatches?: PIIDetectionResult['matches']
	) {
		super(`PII detected: ${piiTypes.join(', ')}`, 'PII_DETECTED');
		this.name = 'PIIDetectedError';
	}
}

export class InvalidAPIKeyError extends AIError {
	constructor(provider: AIProvider) {
		super(`Invalid API key for ${provider}`, 'INVALID_API_KEY');
		this.name = 'InvalidAPIKeyError';
	}
}

export class TokenLimitError extends AIError {
	constructor(limit: number, requested: number) {
		super(`Token limit exceeded: requested ${requested}, limit ${limit}`, 'TOKEN_LIMIT_EXCEEDED');
		this.name = 'TokenLimitError';
	}
}
