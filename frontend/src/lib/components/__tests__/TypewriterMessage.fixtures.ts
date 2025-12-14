/**
 * Test fixtures for TypewriterMessage component
 *
 * These fixtures test the contentVersion field requirement for Svelte 5 reactivity.
 * The `z.prev` error occurs when Svelte 5's fine-grained reactivity system tries to
 * track a property that doesn't exist on the proxy object.
 */

import type { StreamingMessage } from '$lib/services/StreamingService.svelte';

/**
 * Valid message with contentVersion initialized
 * This should work without crashing
 */
export const validStreamingMessage: StreamingMessage = {
	id: 'test-valid-001',
	content: 'Hello world! This is a test message.',
	displayedContent: '',
	sender: 'assistant',
	created_at: new Date().toISOString(),
	isAnimating: false,
	shouldAnimate: true,
	contentVersion: 0 // ✅ CRITICAL: contentVersion must be initialized
};

/**
 * Message WITHOUT contentVersion property
 * This should reproduce the z.prev error
 */
export const brokenStreamingMessage: StreamingMessage = {
	id: 'test-broken-002',
	content: 'This message will crash!',
	displayedContent: '',
	sender: 'assistant',
	created_at: new Date().toISOString(),
	isAnimating: false,
	shouldAnimate: true
	// ❌ contentVersion is missing - this should crash with z.prev error
};

/**
 * Message with contentVersion explicitly undefined
 * Tests nullish coalescing behavior (?? 0)
 */
export const undefinedContentVersionMessage: StreamingMessage = {
	id: 'test-undefined-003',
	content: 'Message with undefined contentVersion',
	displayedContent: '',
	sender: 'assistant',
	created_at: new Date().toISOString(),
	isAnimating: false,
	shouldAnimate: true,
	contentVersion: undefined // Explicitly set to undefined
};

/**
 * Historical message (no animation)
 * These don't trigger the $effect, so contentVersion may not be critical
 */
export const historicalMessage: StreamingMessage = {
	id: 'test-historical-004',
	content: 'This is a historical message',
	displayedContent: 'This is a historical message',
	sender: 'assistant',
	created_at: new Date(Date.now() - 60000).toISOString(),
	isAnimating: false,
	shouldAnimate: false, // No animation for historical messages
	contentVersion: 0
};

/**
 * User message (no animation)
 * User messages show immediately without typewriter effect
 */
export const userMessage: StreamingMessage = {
	id: 'test-user-005',
	content: 'This is my question',
	displayedContent: 'This is my question',
	sender: 'user',
	created_at: new Date().toISOString(),
	isAnimating: false,
	shouldAnimate: false,
	contentVersion: 0
};

/**
 * Streaming message mid-animation
 * Simulates a message that's currently being typed out
 */
export const streamingMessage: StreamingMessage = {
	id: 'test-streaming-006',
	content: 'This message is streaming chunk by chunk...',
	displayedContent: 'This message is stre',
	sender: 'assistant',
	created_at: new Date().toISOString(),
	isAnimating: true,
	shouldAnimate: true,
	contentVersion: 2 // Has been updated twice
};

/**
 * Error message
 * Tests error state rendering
 */
export const errorMessage: StreamingMessage = {
	id: 'test-error-007',
	content: '',
	displayedContent: '',
	sender: 'assistant',
	created_at: new Date().toISOString(),
	isAnimating: false,
	shouldAnimate: false,
	error: 'Generation failed: API error',
	retryable: true,
	contentVersion: 0
};

/**
 * Regenerating message
 * Shows loading state during regeneration
 */
export const regeneratingMessage: StreamingMessage = {
	id: 'test-regenerating-008',
	content: 'Old content that is being regenerated',
	displayedContent: 'Old content that is being regenerated',
	sender: 'assistant',
	created_at: new Date().toISOString(),
	isAnimating: false,
	isRegenerating: true, // Shows loading spinner
	shouldAnimate: false,
	contentVersion: 0
};
