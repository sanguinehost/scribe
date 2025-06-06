import { error } from '@sveltejs/kit';
import type {
	ScribeChatMessage,
	ScribeChatSession,
	ScribeCharacter,
	MessageRole,
	BackendAuthResponse
} from '$lib/types.ts'; // Assuming ScribeCharacter type exists or will be added

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

export async function load({ params: { chatId }, fetch, cookies }) {
	try {
		const sessionCookie = cookies.get('session');
		// Prepare headers for authenticated fetch calls
		const headers = sessionCookie ? { Cookie: `session=${sessionCookie}` } : undefined;

		// Fetch user details
		let user: BackendAuthResponse | undefined;
		const userRes = await fetch('/api/auth/me', { headers });
		if (userRes.ok) {
			user = await userRes.json();
		} else {
			console.warn('Failed to fetch user details, proceeding without user context.');
			// Depending on application requirements, you might want to throw an error here
			// if user context is strictly necessary for all chat interactions.
		}

		// Fetch chat session details
		const chatRes = await fetch(`/api/chats/fetch/${chatId}`, { headers });
		if (!chatRes.ok) {
			if (chatRes.status === 404) {
				error(404, 'Chat not found');
			}
			console.error('Failed to fetch chat:', chatRes.status, await chatRes.text());
			error(500, 'Failed to load chat details');
		}
		const chat: ScribeChatSession = await chatRes.json();

		// Basic visibility check (assuming backend handles proper authorization)
		// We might need a more robust check depending on API design
		// if (chat.visibility === 'private' && (!user || chat.user_id !== user.id)) {
		//  error(403, 'Forbidden');
		// }

		// Fetch chat messages
		const messagesRes = await fetch(`/api/chats/${chatId}/messages`, { headers });
		if (!messagesRes.ok) {
			console.error('Failed to fetch messages:', messagesRes.status, await messagesRes.text());
			error(500, 'Failed to load chat messages');
		}
		const messagesResponseJson: RawApiMessage[] = await messagesRes.json(); // Use defined interim type
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
			const characterRes = await fetch(`/api/characters/fetch/${chat.character_id}`, { headers });
			if (characterRes.ok) {
				character = await characterRes.json();
			} else {
				// Log error but don't fail the page load if character fetch fails
				console.error(
					'Failed to fetch character details:',
					characterRes.status,
					await characterRes.text()
				);
				// Optionally, you could return an error page here if character is essential
				// error(500, 'Failed to load character details');
			}
		} else {
			console.warn(`Chat session ${chatId} does not have an associated character_id.`);
			// Handle cases where character_id might be missing if necessary
		}

		return { chat, messages, character, user }; // Return character along with chat and messages
	} catch (e) {
		console.error('Error loading chat data:', e);
		error(500, 'An error occurred while processing your request');
	}
}
