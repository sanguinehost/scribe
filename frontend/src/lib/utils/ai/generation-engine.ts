/**
 * AI Generation Engine - Scribe Backend Integration
 *
 * Simplified adapter that connects character-editor's AI components
 * to Scribe's backend API instead of OpenRouter.
 */

import type { GenerationRequest, GenerationResponse, GenerationChunk } from '$lib/types/ai';
import { apiClient } from '$lib/api';

/**
 * Generate content (non-streaming)
 */
export async function generate(request: GenerationRequest): Promise<GenerationResponse> {
	// Call scribe's backend API
	const result = await apiClient.generateCharacterField({
		fieldName: request.fieldName,
		fieldValue: request.mode === 'create' ? undefined : request.fieldValue,
		characterContext: request.characterContext,
		mode: request.mode,
		style: request.style === 'auto' ? undefined : request.style,
		userPrompt: request.userPrompt,
		maxTokens: request.maxTokens
	});

	if (result.isErr()) {
		throw new Error(result.error.message || 'Failed to generate content');
	}

	const response = result.value;

	return {
		content: response.content,
		metadata: {
			model: response.metadata?.model || 'unknown',
			tokensUsed: response.metadata?.tokens_used || 0,
			cost: response.metadata?.cost || 0,
			generationTimeMs: response.metadata?.generation_time_ms || 0,
			finishReason: response.metadata?.finish_reason,
			systemPrompt: response.metadata?.system_prompt,
			userPrompt: response.metadata?.user_prompt,
			lorebookContextIncluded: response.metadata?.lorebook_context_included || false,
			lorebookEntriesCount: response.metadata?.lorebook_entries_count || 0,
			queryTextUsed: response.metadata?.query_text_used || ''
		}
	};
}

/**
 * Generate content with streaming
 */
export async function* generateStream(request: GenerationRequest): AsyncGenerator<GenerationChunk> {
	try {
		const generator = apiClient.generateCharacterFieldStream({
			fieldName: request.fieldName,
			fieldValue: request.mode === 'create' ? undefined : request.fieldValue,
			characterContext: request.characterContext,
			mode: request.mode,
			style: request.style === 'auto' ? undefined : request.style,
			userPrompt: request.userPrompt,
			maxTokens: request.maxTokens
		});

		let _accumulatedContent = '';

		for await (const chunk of generator) {
			if ('done' in chunk && chunk.done) {
				// Final chunk with metadata
				yield {
					content: '',
					done: true,
					metadata: {
						model: chunk.metadata?.model || 'unknown',
						tokensUsed: chunk.metadata?.tokens_used || 0,
						cost: chunk.metadata?.cost || 0,
						generationTimeMs: chunk.metadata?.generation_time_ms || 0,
						systemPrompt: chunk.metadata?.system_prompt,
						userPrompt: chunk.metadata?.user_prompt,
						lorebookContextIncluded: chunk.metadata?.lorebook_context_included || false,
						lorebookEntriesCount: chunk.metadata?.lorebook_entries_count || 0,
						queryTextUsed: chunk.metadata?.query_text_used || ''
					}
				};
			} else if ('content' in chunk && chunk.content) {
				// Content chunk
				_accumulatedContent += chunk.content;
				yield {
					content: chunk.content,
					done: false
				};
			}
		}
	} catch (error) {
		if (error instanceof Error) {
			throw new Error(`Streaming generation failed: ${error.message}`);
		}
		throw error;
	}
}

/**
 * Check if generation is ready
 * For scribe, always true if user is logged in (backend handles auth)
 */
export function isGenerationReady(): { ready: boolean; reason?: string } {
	// Scribe uses backend authentication, so generation is always "ready"
	// if the user is logged in (which they must be to access this)
	return { ready: true };
}

/**
 * Get current usage stats
 * Scribe tracks usage on the backend
 */
export function getUsageStats() {
	return {
		totalRequests: 0, // Backend tracks this
		totalTokens: 0,
		totalCost: 0,
		rateLimits: {
			requests: { used: 0, limit: Infinity },
			tokens: { used: 0, limit: Infinity }
		}
	};
}
