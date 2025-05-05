import { error } from '@sveltejs/kit';
import type { ScribeChatMessage, ScribeChatSession, ScribeCharacter } from '$lib/types'; // Assuming ScribeCharacter type exists or will be added

export async function load({ params: { chatId }, fetch, cookies }) {
	try {
		const sessionCookie = cookies.get('session');
		// Prepare headers for authenticated fetch calls
		const headers = sessionCookie ? { Cookie: `session=${sessionCookie}` } : undefined;

		// Fetch chat session details
		const chatRes = await fetch(`/api/chats/${chatId}`, { headers });
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
		const messages: ScribeChatMessage[] = await messagesRes.json();

		// Fetch character details using the character_id from the chat session
		let character: ScribeCharacter | null = null;
		if (chat.character_id) {
			const characterRes = await fetch(`/api/characters/${chat.character_id}`, { headers });
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


		return { chat, messages, character }; // Return character along with chat and messages
	} catch (e) {
		console.error('Error loading chat data:', e);
		error(500, 'An error occurred while processing your request');
	}
}
