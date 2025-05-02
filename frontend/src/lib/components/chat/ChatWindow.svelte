<script lang="ts">
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import MessageInput from './MessageInput.svelte';
	import { onMount } from 'svelte';
	import { chatStore, type Message } from '$lib/stores/chatStore';
	import MessageBubble from './MessageBubble.svelte';
	import { Button } from '$lib/components/ui/button';
	import SettingsPanel from '$lib/components/settings/SettingsPanel.svelte';
	import Settings from 'lucide-svelte/icons/settings'; // Icon for the button

	// Props
	export let sessionId: string;

	// Subscribe to store values
	$: messages = $chatStore.messages;
	$: isLoading = $chatStore.isLoading;

	// State for settings panel visibility
	let isSettingsOpen = false;

	// Load messages when the component mounts and sessionId is available
	onMount(() => {
		if (sessionId) {
			console.log(`ChatWindow mounted with sessionId: ${sessionId}`);
			chatStore.loadMessages(sessionId);
		} else {
			console.warn('ChatWindow mounted without a sessionId.');
		}
	});

	// Reactive statement to reload messages if sessionId changes after mount
	// This might be redundant if the page navigation handles this, but added for robustness
	$: if (sessionId && $chatStore.currentSessionId !== sessionId && typeof window !== 'undefined') {
		console.log(`SessionId changed to: ${sessionId}, reloading messages.`);
		chatStore.loadMessages(sessionId);
	}

	// TODO: Implement auto-scrolling to the bottom when new messages arrive
</script>

<div class="flex flex-col h-full border rounded-lg overflow-hidden" data-testid="chat-window-container">
	<!-- Header with Settings Button -->
	<div class="flex items-center justify-between p-2 border-b">
		<h2 class="text-lg font-semibold">Chat</h2>
		<Button variant="ghost" size="icon" on:click={() => (isSettingsOpen = true)}>
			<Settings class="h-5 w-5" />
			<span class="sr-only">Open Settings</span>
		</Button>
	</div>

	<ScrollArea class="flex-1 p-4 space-y-4"> <!-- Added space-y-4 for spacing -->
		{#if messages.length === 0 && !isLoading}
			<div class="text-muted-foreground text-center py-10">
				Start the conversation by typing a message below.
			</div>
		{:else}
			{#each messages as message (message.id)}
				<MessageBubble
					sender={message.sender}
					messageContent={message.content}
					isStreaming={message.isStreaming ?? false}
				/>
			{/each}
		{/if}

		{#if isLoading && messages.length === 0} <!-- Show loading only if no messages yet -->
			<div class="text-muted-foreground text-center py-10" data-testid="chat-loading-indicator">Loading chat...</div>
		{/if}
		{#if isLoading && messages.length > 0 && messages[messages.length - 1]?.sender === 'user'} <!-- Show indicator when AI is *about* to type (after user sends) -->
			<!-- Optionally show a thinking indicator here -->
			<!-- <MessageBubble sender="ai" messageContent="..." isStreaming={true} /> -->
            <!-- The actual streaming bubble is added by the store itself -->
		{/if}

		{#if $chatStore.error}
			<div class="text-red-500 text-center py-4" data-testid="chat-error-message">
				Error: {$chatStore.error}
			</div>
		{/if}
	</ScrollArea>

	<MessageInput /> <!-- MessageInput will handle sending -->

	<!-- Settings Panel (Dialog) -->
	<SettingsPanel bind:open={isSettingsOpen} />
</div>