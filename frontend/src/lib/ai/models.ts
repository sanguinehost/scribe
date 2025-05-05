export const DEFAULT_CHAT_MODEL: string = 'gemini-2.5-pro-preview-03-25';

interface ChatModel {
	id: string;
	name: string;
	description: string;
}

export const chatModels: Array<ChatModel> = [
    {
		id: 'gemini-2.5-pro-preview-03-25',
		name: 'Gemini 2.5 Pro Preview',
		description: 'Stable preview of the Pro model'
	},
    {
		id: 'gemini-2.5-flash-preview-04-17',
		name: 'Gemini 2.5 Flash Preview',
		description: 'Fast and efficient preview model'
	}
];
