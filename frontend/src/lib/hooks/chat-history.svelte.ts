// import type { VisibilityType } from '$lib/components/visibility-selector.svelte'; // Remove old import
// import type { Chat } from '$lib/server/db/schema'; // Remove old type
import type { ScribeChatSession, VisibilityType } from '$lib/types'; // Use Scribe types
import { getContext, setContext } from 'svelte';
import { toast } from 'svelte-sonner';

const contextKey = Symbol('ChatHistory');

export class ChatHistory {
	#loading = $state(false);
	#revalidating = $state(false);
	chats = $state<ScribeChatSession[]>([]); // Use Scribe type

	get loading() {
		return this.#loading;
	}

	get revalidating() {
		return this.#revalidating;
	}

	constructor(chatsPromise: Promise<ScribeChatSession[]>) { // Use Scribe type
		this.#loading = true;
		this.#revalidating = true;
		chatsPromise
			.then((chats) => (this.chats = chats))
			.finally(() => {
				this.#loading = false;
				this.#revalidating = false;
			});
	}

	getChatDetails = (chatId: string) => {
		return this.chats.find((c) => c.id === chatId);
	};

	setContext() {
		setContext(contextKey, this);
	}

	async refetch() {
		this.#revalidating = true;
		try {
			// Use Scribe endpoint for fetching chats
			const res = await fetch('/api/chats');
			if (res.ok) {
				this.chats = await res.json();
			}
		} finally {
			this.#revalidating = false;
		}
	}

	// Method to update chat visibility via API
	async updateVisibility(chatId: string, newVisibility: VisibilityType) {
		const originalChats = [...this.chats];
		// Optimistic update
		this.chats = this.chats.map(chat =>
			chat.id === chatId ? { ...chat, visibility: newVisibility } : chat // Assuming ScribeChatSession has visibility
		);

		try {
			const response = await fetch(`/api/chats/${chatId}`, {
				method: 'PATCH', // Or PUT, depending on API design
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ visibility: newVisibility }), // Adjust payload as needed
			});

			if (!response.ok) {
				const errorData = await response.json().catch(() => ({ message: 'Failed to update visibility' }));
				throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
			}

			// Optional: Refetch or update based on response if needed
			// const updatedChat = await response.json();
			// this.chats = this.chats.map(chat => chat.id === chatId ? updatedChat : chat);
			toast.success(`Chat visibility updated to ${newVisibility}.`);

		} catch (error: unknown) {
			console.error('Failed to update chat visibility:', error);
			const message = error instanceof Error ? error.message : 'Unknown error';
			toast.error(`Failed to update visibility: ${message}`);
			// Rollback optimistic update on error
			this.chats = originalChats;
		}
	}


	static fromContext(): ChatHistory {
		return getContext(contextKey);
	}
}
