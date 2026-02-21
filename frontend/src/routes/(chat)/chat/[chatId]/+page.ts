import { error, redirect } from '@sveltejs/kit';
import { apiClient as _apiClient } from '$lib/api';
import type {
	ScribeChatMessage,
	ScribeChatSession,
	ScribeCharacter,
	MessageRole as _MessageRole,
	BackendAuthResponse as _BackendAuthResponse,
	Message
} from '$lib/types.ts';
import { getCurrentUser } from '$lib/auth.svelte';
import { extractMessageContent } from '$lib/utils/message-helpers';

export async function load({ params: { chatId }, parent }) {
	try {
		const parentData = await parent();
		// In desktop mode, parent.user may be undefined, so fallback to auth store
		const user = parentData.user ?? getCurrentUser();

		// Fetch chat session details
		const chatResult = await _apiClient.getChatById(chatId);
		if (chatResult.isErr()) {
			if ('statusCode' in chatResult.error) {
				if (chatResult.error.statusCode === 404) {
					error(404, 'Chat not found');
				}
				if (chatResult.error.statusCode === 401) {
					// Authentication failed (likely DEK missing after server restart)
					redirect(307, '/signin');
				}
			}
			console.error('Failed to fetch chat:', chatResult.error);
			error(500, 'Failed to load chat details');
		}
		const chat: ScribeChatSession = chatResult.value;

		// Fetch initial batch of chat messages (first page)
		const messagesResult = await _apiClient.getMessagesByChatId(chatId, { limit: 20 });
		if (messagesResult.isErr()) {
			if ('statusCode' in messagesResult.error && messagesResult.error.statusCode === 401) {
				// Authentication failed (likely DEK missing after server restart)
				redirect(307, '/signin');
			}
			console.error('Failed to fetch messages:', messagesResult.error);
			error(500, 'Failed to load chat messages');
		}

		// Handle both old array format and new paginated format
		let messagesResponseJson: Message[];
		let initialCursor: string | null = null;

		if (Array.isArray(messagesResult.value)) {
			// Old format: array of messages
			messagesResponseJson = messagesResult.value;
		} else if ('messages' in messagesResult.value) {
			// New format: paginated response
			messagesResponseJson = messagesResult.value.messages;
			initialCursor = messagesResult.value.nextCursor;
		} else {
			console.error('Unexpected response format from getMessagesByChatId');
			error(500, 'Invalid response format from server');
		}

		console.log(
			'📥 Raw messages from backend:',
			messagesResponseJson.map((msg) => ({
				id: msg.id,
				variant_count: msg.variant_count,
				current_variant_index: msg.current_variant_index,
				is_variant: msg.is_variant,
				parent_message_id: msg.parent_message_id,
				has_game_state: !!msg.game_state
			}))
		);

		const messages: ScribeChatMessage[] = messagesResponseJson.map(
			(rawMsg): ScribeChatMessage => ({
				id: rawMsg.id, // For existing messages, use backend ID as main ID
				backend_id: rawMsg.id, // Also store in backend_id for consistency
				session_id: rawMsg.session_id,
				message_type: rawMsg.message_type,
				content: extractMessageContent(rawMsg),
				created_at:
					typeof rawMsg.created_at === 'string'
						? rawMsg.created_at
						: rawMsg.created_at.toISOString(),
				user_id: '', // ScribeChatMessage doesn't need user_id in the same way
				loading: false, // Messages from API are never loading
				shouldAnimate: false, // Historical messages should not animate
				raw_prompt: rawMsg.raw_prompt,
				prompt_tokens: rawMsg.prompt_tokens,
				completion_tokens: rawMsg.completion_tokens,
				model_name: rawMsg.model_name, // Added model_name for per-message pricing
				// Variant metadata - CRITICAL FIX for variant system
				variant_count: rawMsg.variant_count,
				current_variant_index: rawMsg.current_variant_index,
				is_variant: rawMsg.is_variant,
				parent_message_id: rawMsg.parent_message_id,
				variants: rawMsg.variants,
				status: rawMsg.status,
				superseded_at: rawMsg.superseded_at,
				game_state: rawMsg.game_state, // CRITICAL: Include game_state from backend
				reasoning_content: rawMsg.reasoning_content,
				reasoningContent: rawMsg.reasoning_content
			})
		);

		// Fetch character details using the character_id from the chat session
		let character: ScribeCharacter | null = null;
		if (chat.character_id) {
			const characterResult = await _apiClient.getCharacter(chat.character_id);
			if (characterResult.isOk()) {
				character = characterResult.value;
			} else {
				// Log error but don't fail the page load if character fetch fails
				console.error('Failed to fetch character details:', characterResult.error);
			}
		} else {
			console.warn(`Chat session ${chatId} does not have an associated character_id.`);
		}

		// Debug logging for user ID investigation
		console.log('[chat/[chatId]/+page.ts] Chat page data:', {
			chatId: chat.id,
			chatUserId: chat.user_id,
			userUserId: user?.user_id,
			characterId: chat.character_id,
			hasCharacter: character !== null,
			chatMode: chat.chat_mode,
			readonly: user?.user_id !== chat.user_id
		});

		return { chat, messages, character, user, initialCursor };
	} catch (_e) {
		console.error('Error loading chat data:', _e);
		error(500, 'An error occurred while processing your request');
	}
}
