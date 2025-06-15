import { error } from '@sveltejs/kit';
import { apiClient } from '$lib/api';
import type {
	ScribeChatMessage,
	ScribeChatSession,
	ScribeCharacter,
	MessageRole,
	BackendAuthResponse
} from '$lib/types.ts';

// Define an interim type for the raw message structure from the API if it uses parts
interface RawApiMessage {
	id: string;
	session_id: string;
	message_type: MessageRole;
	parts?: Array<{ text?: string }>; // text is optional, no other properties needed from parts for this transform
	content?: string;
	created_at: string;
	user_id: string;
	loading?: boolean;
	raw_prompt?: string | null; // Debug field containing the full prompt sent to AI
}

export async function load({ params: { chatId }, parent }) {
	try {
		const parentData = await parent();
		const { user } = parentData; // Get user from parent layout

		// Fetch chat session details
		const chatResult = await apiClient.getChatById(chatId);
		if (chatResult.isErr()) {
			if (chatResult.error.statusCode === 404) {
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
		const messagesResponseJson: RawApiMessage[] = messagesResult.value;
		const messages: ScribeChatMessage[] = messagesResponseJson.map(
			(rawMsg): ScribeChatMessage => ({
				id: rawMsg.id,
				session_id: rawMsg.session_id,
				message_type: rawMsg.message_type,
				content:
					rawMsg.parts && rawMsg.parts.length > 0 && typeof rawMsg.parts[0].text === 'string'
						? rawMsg.parts[0].text
						: typeof rawMsg.content === 'string'
							? rawMsg.content
							: '',
				created_at: rawMsg.created_at,
				user_id: rawMsg.user_id,
				loading: rawMsg.loading || false,
				raw_prompt: rawMsg.raw_prompt
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