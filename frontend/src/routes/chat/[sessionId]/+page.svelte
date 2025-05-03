<script lang="ts">
	// Imports must come first
	import { onMount } from 'svelte';
	import { chatStore } from '$lib/stores/chatStore'; // Import the store
	import ChatWindow from '$lib/components/chat/ChatWindow.svelte';
	import type { PageData } from './$types';

	// Props and reactive declarations
	export let data: PageData;
	$: sessionId = data.sessionId; // Get sessionId from load function result

	// Lifecycle hooks and logic
	onMount(() => {
		console.log('ChatPage mounted. Initial chatStore state:', $chatStore);
	});

	// Event handler for sending messages
	function handleSendMessage(event: CustomEvent<string>) {
		const content = event.detail;
		if (content && $chatStore.sessionId) { // Ensure content and sessionId exist
			chatStore.sendMessage(content);
		} else {
			console.error("Cannot send message: Content or Session ID missing.", { content, sessionId: $chatStore.sessionId });
			// Optionally show an error to the user via the store
			chatStore.setError("Failed to send message: Missing required information.");
		}
	}
</script>

<svelte:head>
	<title>Chat: {sessionId || 'Loading...'}</title>
</svelte:head>

<!-- The surrounding layout (sidebar, main area padding) comes from +layout.svelte -->
<!-- ChatWindow is now driven by the store state passed as props -->
<!-- Listen for the sendMessage event and call the handler -->
<ChatWindow
	messages={$chatStore.messages}
	isLoadingHistory={$chatStore.isLoadingHistory}
	isGeneratingResponse={$chatStore.isGeneratingResponse}
	error={$chatStore.error}
	on:sendMessage={handleSendMessage}
/>