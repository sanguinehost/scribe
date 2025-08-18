// import type { VisibilityType } from '$lib/components/visibility-selector.svelte'; // Remove old import
// import type { Chat } from '$lib/server/db/schema'; // Remove old type
import type { ScribeChatSession, VisibilityType } from '$lib/types'; // Use Scribe types
import { apiClient } from '$lib/api';
import { getContext, setContext } from 'svelte';
import { toast } from 'svelte-sonner';

const contextKey = Symbol('ChatHistory');

export class ChatHistory {
	#loading = $state(false);
	#revalidating = $state(false);
	chats = $state<ScribeChatSession[]>([]);

	get loading() {
		return this.#loading;
	}

	get revalidating() {
		return this.#revalidating;
	}

	constructor(initialChats: ScribeChatSession[]) {
		this.#loading = true;
		this.chats = initialChats;
		this.#loading = false;
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
			// Use apiClient for fetching chats
			const result = await apiClient.getChats();
			if (result.isOk()) {
				this.chats = result.value;
			}
		} finally {
			this.#revalidating = false;
		}
	}

	// Method to update chat visibility via API
	async updateVisibility(chatId: string, newVisibility: VisibilityType) {
		const originalChats = [...this.chats];
		// Optimistic update
		this.chats = this.chats.map(
			(chat) => (chat.id === chatId ? { ...chat, visibility: newVisibility } : chat) // Assuming ScribeChatSession has visibility
		);

		try {
			const result = await apiClient.updateChatVisibility(chatId, newVisibility);

			if (result.isErr()) {
				throw new Error(result.error.message || 'Failed to update visibility');
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

	// Method to update chat preview without API calls
	updateChatPreview(chatId: string, lastMessageContent: string) {
		this.chats = this.chats.map((chat) => {
			if (chat.id === chatId) {
				return { ...chat, last_message_preview: lastMessageContent };
			}
			return chat;
		});
	}

	static fromContext(): ChatHistory {
		return getContext(contextKey);
	}
}
