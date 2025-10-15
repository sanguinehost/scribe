/**
 * AI Models Configuration
 *
 * Curated list of recommended models from OpenRouter.
 * Balanced across cost, quality, and speed.
 */

import type { AIModel } from '$lib/types/ai';

/**
 * Recommended models for character generation via OpenRouter
 * Sorted by cost (free first, then ascending)
 */
export const RECOMMENDED_MODELS: AIModel[] = [
	// === FREE MODELS ===
	{
		id: 'deepseek/deepseek-chat-v3.1:free',
		name: 'DeepSeek V3.1 (Free)',
		provider: 'DeepSeek',
		contextWindow: 163800,
		costPer1kTokens: { input: 0, output: 0 },
		supportsStreaming: true,
		recommendedFor: ['reasoning', 'coding', 'fast']
	},

	// === BUDGET MODELS ($0.001 or less per 1k tokens) ===
	{
		id: 'openai/gpt-5-nano',
		name: 'GPT-5 Nano',
		provider: 'OpenAI',
		contextWindow: 400000,
		costPer1kTokens: { input: 0.00005, output: 0.0004 },
		supportsStreaming: true,
		recommendedFor: ['ultra-fast', 'budget', 'high-volume']
	},
	{
		id: 'google/gemini-2.5-flash-lite-preview-09-2025',
		name: 'Gemini 2.5 Flash Lite Preview 09-2025',
		provider: 'Google',
		contextWindow: 1050000,
		costPer1kTokens: { input: 0.0001, output: 0.0004 },
		supportsStreaming: true,
		recommendedFor: ['ultra-fast', 'cost-effective', 'high-volume', 'reasoning']
	},
	{
		id: 'x-ai/grok-4-fast',
		name: 'Grok 4 Fast',
		provider: 'xAI',
		contextWindow: 2000000,
		costPer1kTokens: { input: 0.0002, output: 0.0005 },
		supportsStreaming: true,
		recommendedFor: ['fast', 'long-context', 'balanced']
	},
	{
		id: 'deepseek/deepseek-v3.2-exp',
		name: 'DeepSeek V3.2 Exp',
		provider: 'DeepSeek',
		contextWindow: 164000,
		costPer1kTokens: { input: 0.00027, output: 0.0004 },
		supportsStreaming: true,
		recommendedFor: ['reasoning', 'coding', 'long-context', 'experimental']
	},
	{
		id: 'google/gemini-2.5-flash-preview-09-2025',
		name: 'Gemini 2.5 Flash Preview 09-2025',
		provider: 'Google',
		contextWindow: 1050000,
		costPer1kTokens: { input: 0.0003, output: 0.0025 },
		supportsStreaming: true,
		recommendedFor: ['reasoning', 'coding', 'fast', 'high-quality']
	},
	{
		id: 'openai/gpt-4.1-mini',
		name: 'GPT-4.1 Mini',
		provider: 'OpenAI',
		contextWindow: 1047576,
		costPer1kTokens: { input: 0.0004, output: 0.0016 },
		supportsStreaming: true,
		recommendedFor: ['cost-effective', 'reliable', 'fast']
	},

	// === MID-TIER MODELS ($0.001-0.01 per 1k tokens) ===
	{
		id: 'google/gemini-2.5-pro',
		name: 'Gemini 2.5 Pro',
		provider: 'Google',
		contextWindow: 1048576,
		costPer1kTokens: { input: 0.00125, output: 0.01 },
		supportsStreaming: true,
		recommendedFor: ['long-context', 'high-quality', 'complex', 'coding']
	},

	// === PREMIUM MODELS ($0.01+ per 1k tokens) ===
	{
		id: 'openai/gpt-5',
		name: 'GPT-5',
		provider: 'OpenAI',
		contextWindow: 400000,
		costPer1kTokens: { input: 0.00125, output: 0.01 },
		supportsStreaming: true,
		recommendedFor: ['best-quality', 'creative', 'complex']
	},
	{
		id: 'anthropic/claude-sonnet-4.5',
		name: 'Claude Sonnet 4.5',
		provider: 'Anthropic',
		contextWindow: 1000000,
		costPer1kTokens: { input: 0.003, output: 0.015 },
		supportsStreaming: true,
		recommendedFor: ['best-quality', 'creative-writing', 'nuanced', 'latest']
	},

	// === IMAGE GENERATION MODELS ===
	{
		id: 'google/gemini-2.5-flash-image-preview',
		name: 'Gemini 2.5 Flash Image Preview (Nano Banana)',
		provider: 'Google',
		contextWindow: 33000, // 33K context
		costPer1kTokens: { input: 0.0003, output: 0.0025 }, // $0.30/M input, $2.50/M output
		supportsStreaming: false,
		supportsImageGeneration: true,
		outputModalities: ['text', 'image'],
		recommendedFor: ['image-generation', 'image-edits', 'multimodal', 'contextual-understanding']
	}
];

/**
 * Get model by ID
 */
export function getModelById(modelId: string): AIModel | undefined {
	return RECOMMENDED_MODELS.find((m) => m.id === modelId);
}

/**
 * Get default model (free DeepSeek V3.1)
 */
export function getDefaultModel(): AIModel {
	return RECOMMENDED_MODELS[0];
}

/**
 * Group models by provider
 */
export function getModelsByProvider(): Record<string, AIModel[]> {
	return RECOMMENDED_MODELS.reduce(
		(acc, model) => {
			if (!acc[model.provider]) {
				acc[model.provider] = [];
			}
			acc[model.provider].push(model);
			return acc;
		},
		{} as Record<string, AIModel[]>
	);
}

/**
 * Get models sorted by cost (free first)
 */
export function getModelsByCost(): AIModel[] {
	return [...RECOMMENDED_MODELS].sort((a, b) => {
		const costA = a.costPer1kTokens.input + a.costPer1kTokens.output;
		const costB = b.costPer1kTokens.input + b.costPer1kTokens.output;
		return costA - costB;
	});
}

/**
 * Filter free models
 */
export function getFreeModels(): AIModel[] {
	return RECOMMENDED_MODELS.filter(
		(m) => m.costPer1kTokens.input === 0 && m.costPer1kTokens.output === 0
	);
}

/**
 * Filter image generation capable models
 */
export function getImageGenerationModels(): AIModel[] {
	return RECOMMENDED_MODELS.filter(
		(m) => m.supportsImageGeneration && m.outputModalities?.includes('image')
	);
}
