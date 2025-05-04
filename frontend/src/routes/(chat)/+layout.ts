import type { ScribeChatSession } from '$lib/types.js';

export async function load({ data, fetch }) {
	const { user } = data;
	let chats = Promise.resolve<ScribeChatSession[]>([]);
	if (user) {
		// Use Scribe endpoint for fetching chats
		chats = fetch('/api/chats').then((res) => res.json());
	}
	return {
		chats,
		...data
	};
}
