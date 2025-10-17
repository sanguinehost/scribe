/**
 * Provider Interface
 *
 * Abstract interface for AI providers. This abstraction allows easy swapping
 * between OpenRouter (primary) and direct SDK providers (stretch goal).
 *
 * All providers must implement this interface for consistent API.
 */

import type {
	GenerationRequest,
	GenerationResponse,
	GenerationChunk,
	AIModel,
	ResponseFormat
} from '$lib/types/ai';

/**
 * Provider interface that all AI providers must implement
 */
export interface IAIProvider {
	/**
	 * Generate content for a character field
	 * @param request Generation request with field info and context
	 * @param model Model ID to use for generation
	 * @param maxTokens Maximum tokens to generate
	 * @returns Generated content with metadata
	 */
	generate(
		request: GenerationRequest,
		model: string,
		maxTokens: number
	): Promise<GenerationResponse>;

	/**
	 * Generate content with streaming for real-time UI updates
	 * @param request Generation request with field info and context
	 * @param model Model ID to use for generation
	 * @param maxTokens Maximum tokens to generate
	 * @yields Text chunks as they arrive
	 */
	generateStream(
		request: GenerationRequest,
		model: string,
		maxTokens: number
	): AsyncGenerator<GenerationChunk>;

	/**
	 * Validate API key by making a minimal test request
	 * @param apiKey API key to validate
	 * @returns true if key is valid, false otherwise
	 */
	validateApiKey(apiKey: string): Promise<boolean>;

	/**
	 * Get list of available models for this provider
	 * @returns Array of supported models with metadata
	 */
	getAvailableModels(): AIModel[];

	/**
	 * Calculate cost estimate for a generation request
	 * @param model Model ID
	 * @param estimatedTokens Estimated token count
	 * @returns Cost estimate in USD
	 */
	estimateCost(model: string, estimatedTokens: { input: number; output: number }): number;

	/**
	 * Low-level chat completion request (used by generation engine)
	 * @param request Provider request with prompts and model
	 * @returns Raw provider response
	 */
	chatCompletion(request: ProviderRequest): Promise<ProviderResponse>;

	/**
	 * Low-level streaming chat completion request (used by generation engine)
	 * @param request Provider request with prompts and model
	 * @yields Streaming chunks
	 */
	chatCompletionStream(
		request: ProviderRequest
	): AsyncGenerator<{ chunk: string; done: boolean; usage?: ProviderResponse['usage'] }>;
}

/**
 * Internal request format sent to LLM APIs
 * Standardized format across all providers
 */
export interface ProviderRequest {
	/** System prompt with instructions */
	systemPrompt: string;
	/** User message/prompt */
	userPrompt: string;
	/** Model ID */
	model: string;
	/** Maximum tokens to generate */
	maxTokens: number;
	/** Temperature (0-2, lower = more focused) */
	temperature?: number;
	/** Whether to stream the response */
	stream?: boolean;
	/** Response format for structured outputs (OpenRouter feature) */
	responseFormat?: ResponseFormat;

	// OpenRouter Sampling Parameters
	/** Top P - nucleus sampling (0.0 - 1.0) */
	top_p?: number;
	/** Top K - limit token choices (0 = disabled) */
	top_k?: number;
	/** Frequency Penalty - reduce token repetition based on frequency (-2.0 - 2.0) */
	frequency_penalty?: number;
	/** Presence Penalty - reduce token repetition based on presence (-2.0 - 2.0) */
	presence_penalty?: number;
	/** Repetition Penalty - reduce repetition (0.0 - 2.0, 1.0 = disabled) */
	repetition_penalty?: number;
	/** Min P - minimum probability threshold (0.0 - 1.0) */
	min_p?: number;
	/** Top A - dynamic top-p based on max probability (0.0 - 1.0) */
	top_a?: number;
	/** Seed - deterministic generation seed */
	seed?: number | null;
	/** Stop - stop sequences to terminate generation */
	stop?: string[];
	/** Verbosity - control response length and detail */
	verbosity?: 'low' | 'medium' | 'high';
}

/**
 * Raw response from provider API (before processing)
 */
export interface ProviderResponse {
	/** Generated text content */
	content: string;
	/** Token usage statistics */
	usage: {
		promptTokens: number;
		completionTokens: number;
		totalTokens: number;
	};
	/** Model that generated the response */
	model: string;
	/** Provider-specific metadata */
	metadata?: Record<string, unknown>;
}
