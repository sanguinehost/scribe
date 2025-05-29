export const DEFAULT_CHAT_MODEL: string = 'gemini-2.5-flash-preview-04-17'; // Changed as per previous conversation summary

// Default Context Allocation
export const DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT = 200000;
export const DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET = 150000;
export const DEFAULT_CONTEXT_RAG_BUDGET = 40000; // Leaves 10k buffer

interface ChatModel {
	id: string;
	name: string;
	description: string;
}

export const chatModels: Array<ChatModel> = [
    {
		id: 'gemini-2.5-pro-preview-05-06',
		name: 'Gemini 2.5 Pro Preview',
		description: 'Stable preview of the Pro model'
	},
    {
		id: 'gemini-2.5-flash-preview-04-17',
		name: 'Gemini 2.5 Flash Preview',
		description: 'Fast and efficient preview model'
	}
];
