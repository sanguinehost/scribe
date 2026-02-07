export const DEFAULT_CHAT_MODEL: string = 'gemini-2.5-flash'; // Changed as per previous conversation summary

// Default Context Allocation
export const DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT = 200000;
export const DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET = 150000;
export const DEFAULT_CONTEXT_RAG_BUDGET = 40000; // Leaves 10k buffer

interface ChatModel {
	id: string;
	name: string;
	description: string;
	isLocal?: boolean; // Flag to indicate if this is a local model
	supportsReasoning?: boolean; // Flag to indicate if this model supports thinking_level
}

export const cloudModels: Array<ChatModel> = [
	{
		id: 'gemini-3-pro-preview',
		name: 'Gemini 3 Pro Preview',
		description: 'Next-generation Pro model with advanced reasoning',
		supportsReasoning: true
	},
	{
		id: 'gemini-3-flash-preview',
		name: 'Gemini 3 Flash Preview',
		description: 'Next-generation Flash model (Preview)',
		supportsReasoning: true
	},
	{
		id: 'gemini-2.5-pro',
		name: 'Gemini 2.5 Pro',
		description: 'Most intelligent and expensive model',
		supportsReasoning: true
	},
	{
		id: 'gemini-2.5-flash',
		name: 'Gemini 2.5 Flash',
		description: 'Fast and efficient model',
		supportsReasoning: true
	},
	{
		id: 'gemini-2.5-flash-preview-09-2025',
		name: 'Gemini 2.5 Flash Preview',
		description: 'Latest preview with enhanced capabilities',
		supportsReasoning: true
	},
	{
		id: 'gemini-2.5-flash-lite-preview-09-2025',
		name: 'Gemini 2.5 Flash Lite',
		description: 'Ultra-fast and cost-effective model (FREE)',
		supportsReasoning: true
	},
	{
		id: 'gemini-2.5-flash-image',
		name: 'Gemini 2.5 Flash Image',
		description: 'Chat model with image generation support',
		supportsReasoning: true
	}
];

// Backward compatibility - same as cloudModels for now
export const chatModels: Array<ChatModel> = cloudModels;

// Function to get all available models (cloud + local)
export function getAllAvailableModels(
	localModels: Array<{ id: string; name: string; description?: string }> = []
): Array<ChatModel> {
	const localChatModels: Array<ChatModel> = localModels.map((model) => ({
		id: model.id,
		name: model.name,
		description: model.description || 'Local model',
		isLocal: true
	}));

	return [...cloudModels, ...localChatModels];
}
