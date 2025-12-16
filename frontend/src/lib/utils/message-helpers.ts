/**
 * Message content extraction helpers
 * 
 * Consolidates message content extraction logic that was duplicated across:
 * - routes/(chat)/chat/[chatId]/+page.ts
 * - lib/controllers/chat-controller.svelte.ts
 * - lib/components/chat.svelte
 */

import type { Message, MessagePart } from '$lib/types';

/**
 * Extracts the text content from a Message object.
 * Uses `content` field as primary source, falls back to `parts[0].text`.
 * 
 * This fixes a bug where backend responses with `content` but empty `parts`
 * would result in empty message content being rendered.
 */
export function extractMessageContent(rawMsg: Message | { content?: string; parts?: MessagePart[] }): string {
    // Primary: use content field if available and non-empty
    if (rawMsg.content && rawMsg.content.trim()) {
        return rawMsg.content;
    }

    // Fallback: extract from parts array
    if (rawMsg.parts && rawMsg.parts.length > 0 && 'text' in rawMsg.parts[0]) {
        const textPart = rawMsg.parts[0] as { text?: string };
        return textPart.text || '';
    }

    return '';
}
