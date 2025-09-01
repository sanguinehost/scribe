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
}

export const cloudModels: Array<ChatModel> = [
	{
		id: 'gemini-2.5-pro',
		name: 'Gemini 2.5 Pro',
		description: 'More intelligent and expensive model'
	},
	{
		id: 'gemini-2.5-flash',
		name: 'Gemini 2.5 Flash',
		description: 'Fast and efficient model'
	},
	{
		id: 'gemini-2.5-flash-lite-preview-06-17',
		name: 'Gemini 2.5 Flash Lite',
		description: 'Ultra-fast and cost-effective model for summarization'
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
