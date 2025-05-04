import { error } from '@sveltejs/kit';
import type { ScribeChatMessage, ScribeChatSession } from '$lib/types';

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

		return { chat, messages };
	} catch (e) {
		console.error('Error loading chat data:', e);
		error(500, 'An error occurred while processing your request');
	}
}
