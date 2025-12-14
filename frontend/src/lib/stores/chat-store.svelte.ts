import { type ChatMessage, type MessageVariant, type MessageRole } from '$lib/types/chat';

export class ChatStore {
	messages = $state<ChatMessage[]>([]);
	isStreaming = $state(false);
	error = $state<string | null>(null);
	activeChatId = $state<string | null>(null);

	constructor() {
		// Initialize with empty state
	}

	/**
	 * Adds a new message to the chat.
	 * If the message ID already exists, it updates the existing message.
	 */
	addMessage(id: string, role: MessageRole, content: string, model?: string, isAnimating = false) {
		const existingMessageIndex = this.messages.findIndex((m) => m.id === id);

		const newVariant: MessageVariant = {
			id: crypto.randomUUID(),
			content,
			model,
			createdAt: new Date()
		};

		if (existingMessageIndex !== -1) {
			// Update existing message
			const msg = this.messages[existingMessageIndex];
			// If we are adding a new variant (e.g. regeneration), push it
			// For now, simple add/update logic:
			// If the content is different from the current variant, add as new variant
			// Otherwise update current variant (streaming case)
			const currentVariant = msg.variants[msg.currentVariantIndex];

			if (currentVariant.content !== content && !isAnimating) {
				// New completed variant
				msg.variants.push(newVariant);
				msg.currentVariantIndex = msg.variants.length - 1;
			} else {
				// Updating current variant (streaming)
				msg.variants[msg.currentVariantIndex].content = content;
				if (model) msg.variants[msg.currentVariantIndex].model = model;
			}

			msg.isAnimating = isAnimating;
		} else {
			// New message
			this.messages.push({
				id,
				role,
				variants: [newVariant],
				currentVariantIndex: 0,
				isAnimating,
				timestamp: new Date()
			});
		}
	}

	/**
	 * Updates the content of the last message (used for streaming).
	 */
	updateStreamingContent(content: string) {
		if (this.messages.length === 0) return;

		const lastMsg = this.messages[this.messages.length - 1];
		if (lastMsg.isAnimating) {
			const currentVariant = lastMsg.variants[lastMsg.currentVariantIndex];
			currentVariant.content = content;
		}
	}

	/**
	 * Appends a chunk to the streaming content
	 */
	appendStreamingChunk(chunk: string) {
		if (this.messages.length === 0) return;

		const lastMsg = this.messages[this.messages.length - 1];
		if (lastMsg.isAnimating) {
			const currentVariant = lastMsg.variants[lastMsg.currentVariantIndex];
			currentVariant.content += chunk;
		}
	}

	/**
	 * Sets the error state.
	 */
	setError(error: string | null) {
		this.error = error;
	}

	/**
	 * Sets the streaming state.
	 */
	setStreaming(isStreaming: boolean) {
		this.isStreaming = isStreaming;
	}

	/**
	 * Clears all messages.
	 */
	clear() {
		this.messages = [];
		this.error = null;
		this.isStreaming = false;
	}

	/**
	 * Switches to a specific variant for a message.
	 */
	setVariant(messageId: string, variantIndex: number) {
		const msg = this.messages.find((m) => m.id === messageId);
		if (msg && variantIndex >= 0 && variantIndex < msg.variants.length) {
			msg.currentVariantIndex = variantIndex;
		}
	}
}

// Singleton instance
export const chatStore = new ChatStore();
