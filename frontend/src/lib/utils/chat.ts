import type { Document } from '$lib/types'; // Updated import path
import type { ScribeChatMessage, MessageRole } from '$lib/types'; // Import Scribe types

// Define our own UIMessage interface to avoid depending on @ai-sdk/svelte
interface UIMessage {
	id: string;
	role: 'user' | 'assistant' | 'system';
	content: string;
	parts: Array<{ type: string; text?: string; image_url?: string }>;
	createdAt: Date;
	experimental_attachments: Array<{
		type: string;
		[key: string]: unknown;
	}>;
}

// Helper function to map roles
function mapScribeRoleToUIRole(scribeRole: MessageRole): UIMessage['role'] {
	switch (scribeRole) {
		case 'User':
			return 'user';
		case 'Assistant':
			return 'assistant';
		case 'System':
			return 'system';
		default:
			// Fallback or handle unexpected roles
			console.warn(`Unknown Scribe message role: ${scribeRole}`);
			return 'system';
	}
}

export function convertToUIMessages(messages: Array<ScribeChatMessage>): Array<UIMessage> {
	return messages.map((message) => ({
		id: message.id,
		// Map Scribe 'content' to UIMessage 'parts' (TextUIPart uses 'text')
		parts: [{ type: 'text', text: message.content }],
		// Map Scribe 'message_type' to UIMessage 'role'
		role: mapScribeRoleToUIRole(message.message_type),
		// Note: content will soon be deprecated in @ai-sdk/svelte
		content: message.content, // Keep content for now, map to parts primarily
		createdAt: new Date(message.created_at), // Convert ISO string to Date
		// Attachments are not handled by Scribe backend/types yet
		experimental_attachments: []
	}));
}

// Note: This function now expects ScribeChatMessage array
export function getMostRecentUserMessage(messages: Array<ScribeChatMessage>) {
	// Filter based on Scribe's message_type
	const userMessages = messages.filter((message) => message.message_type === 'User');
	return userMessages.at(-1);
}

export function getDocumentTimestampByIndex(documents: Array<Document>, index: number) {
	if (!documents) return new Date();
	if (index > documents.length) return new Date();

	return documents[index].createdAt;
}

// Note: This function now expects ScribeChatMessage array
export function getTrailingMessageId({
	messages
}: {
	messages: Array<ScribeChatMessage>; // Use ScribeChatMessage
}): string | null {
	const trailingMessage = messages.at(-1);

	if (!trailingMessage) return null;

	// ScribeChatMessage has an 'id' property
	return trailingMessage.id;
}
