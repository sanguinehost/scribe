<script lang="ts">
	// This page renders the chat interface for a specific session.
	// The main layout is handled by +layout.svelte.
	// The ChatWindow component handles its own state based on the chatStore.
	import ChatWindow from '$lib/components/chat/ChatWindow.svelte';
	import type { PageData } from './$types'; // Keep for accessing sessionId for the title

	export let data: PageData;
	$: sessionId = data.sessionId; // Get sessionId from load function result
</script>

<svelte:head>
	<title>Chat: {sessionId || 'Loading...'}</title>
</svelte:head>

<!-- The surrounding layout (sidebar, main area padding) comes from +layout.svelte -->
<!-- ChatWindow handles its internal loading/error states based on the store -->
<ChatWindow {sessionId} />