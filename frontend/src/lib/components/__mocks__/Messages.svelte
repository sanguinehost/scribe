<script lang="ts">
	import type { ScribeChatMessage, MessageRole } from '$lib/types';

	let {
		messages: incomingMessages,
		isSending: incomingIsSending,
		currentUserId: incomingCurrentUserId
	} = $props<{
		messages?: ScribeChatMessage[];
		isSending?: boolean;
		currentUserId?: string;
	}>();

	let messages = $state(incomingMessages || []);
	let isSending = $state(incomingIsSending || false);
	let currentUserId = $state(incomingCurrentUserId);

	// This helper function can be used to determine if a message is from the current user
	// For styling or logic if needed, though not strictly required for basic mock rendering.
	// const isCurrentUser = (messageUserId?: string) => currentUserId && messageUserId === currentUserId;

	// Optional: Log prop changes for debugging during test development
	$effect(() => {
		// Update local state if props change
		messages = incomingMessages || [];
		isSending = incomingIsSending || false;
		currentUserId = incomingCurrentUserId;
	});
</script>

<div
	data-testid="mock-messages-component"
	data-messages-count={messages.length}
	data-is-sending={isSending}
>
	{#if messages.length === 0}
		<p data-testid="no-messages">No messages</p>
	{/if}
	{#each messages as message (message.id || message.content + message.created_at)}
		<div class="message" data-message-id={message.id} data-message-type={message.message_type}>
			<p data-testid="message-content">{message.content}</p>
			{#if message.loading}
				<span data-testid="message-loading"> (loading...)</span>
			{/if}
			{#if message.message_type === 'Assistant' && (message as any).error}
				<p data-testid="message-error" style="color: red;">Error: {(message as any).error}</p>
			{/if}
		</div>
	{/each}
</div>

<style>
	.message {
		padding: 8px;
		margin-bottom: 4px;
		border: 1px solid #eee;
		border-radius: 4px;
	}
</style>
