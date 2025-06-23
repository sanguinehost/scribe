import { error } from '@sveltejs/kit';
import { apiClient } from '$lib/api';
import type {
	ScribeChatMessage,
	ScribeChatSession,
	ScribeCharacter,
	MessageRole,
	BackendAuthResponse,
	Message
} from '$lib/types.ts';

export async function load({ params: { chatId }, parent }) {
	try {
		const parentData = await parent();
		const { user } = parentData; // Get user from parent layout

		// Fetch chat session details
		const chatResult = await apiClient.getChatById(chatId);
		if (chatResult.isErr()) {
			if ('statusCode' in chatResult.error && chatResult.error.statusCode === 404) {
				error(404, 'Chat not found');
			}
			console.error('Failed to fetch chat:', chatResult.error);
			error(500, 'Failed to load chat details');
		}
		const chat: ScribeChatSession = chatResult.value;

		// Fetch chat messages
		const messagesResult = await apiClient.getMessagesByChatId(chatId);
		if (messagesResult.isErr()) {
			console.error('Failed to fetch messages:', messagesResult.error);
			error(500, 'Failed to load chat messages');
		}
		const messagesResponseJson: Message[] = messagesResult.value;
		const messages: ScribeChatMessage[] = messagesResponseJson.map(
			(rawMsg): ScribeChatMessage => ({
				id: rawMsg.id, // For existing messages, use backend ID as main ID
				backend_id: rawMsg.id, // Also store in backend_id for consistency
				session_id: rawMsg.session_id,
				message_type: rawMsg.message_type,
				content:
					rawMsg.parts && rawMsg.parts.length > 0 && 'text' in rawMsg.parts[0] && typeof rawMsg.parts[0].text === 'string'
						? rawMsg.parts[0].text
						: '',
				created_at: typeof rawMsg.created_at === 'string' ? rawMsg.created_at : rawMsg.created_at.toISOString(),
				user_id: '', // ScribeChatMessage doesn't need user_id in the same way
				loading: false, // Messages from API are never loading
				raw_prompt: rawMsg.raw_prompt,
				prompt_tokens: rawMsg.prompt_tokens,
				completion_tokens: rawMsg.completion_tokens,
				model_name: rawMsg.model_name // Added model_name for per-message pricing
			})
		);

		// Fetch character details using the character_id from the chat session
		let character: ScribeCharacter | null = null;
		if (chat.character_id) {
			const characterResult = await apiClient.getCharacter(chat.character_id);
			if (characterResult.isOk()) {
				character = characterResult.value;
			} else {
				// Log error but don't fail the page load if character fetch fails
				console.error('Failed to fetch character details:', characterResult.error);
			}
		} else {
			console.warn(`Chat session ${chatId} does not have an associated character_id.`);
		}

		return { chat, messages, character, user };
	} catch (e) {
		console.error('Error loading chat data:', e);
		error(500, 'An error occurred while processing your request');
	}
}