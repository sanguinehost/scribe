<script lang="ts">
	// Imports must come first
	import { onMount } from 'svelte';
	import { chatStore } from '$lib/stores/chatStore'; // Import the store
	import ChatWindow from '$lib/components/chat/ChatWindow.svelte';
	import SettingsPanel from '$lib/components/settings/SettingsPanel.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Dialog, DialogContent, DialogHeader, DialogTitle } from '$lib/components/ui/dialog';
	import { Settings } from 'lucide-svelte'; // Assuming lucide-svelte is used
	import type { PageData } from './$types';

	// Props and reactive declarations using runes
	const { data } = $props<{ data: PageData }>();
	const sessionId = data.sessionId; // Get sessionId directly from props

	// State for settings panel
	let settingsOpen = $state(false);

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

<div class="flex flex-col h-full">
	<!-- Header area within the page content -->
	<div class="flex justify-between items-center p-2 border-b">
		<h2 class="text-lg font-semibold">Chat Session</h2>
		<Button variant="ghost" size="icon" onclick={() => settingsOpen = true} title="Chat Settings">
			<Settings class="h-5 w-5" />
		</Button>
	</div>

	<!-- ChatWindow is now driven by the store state passed as props -->
	<!-- Listen for the sendMessage event and call the handler -->
	<div class="flex-grow overflow-hidden">
		<ChatWindow
			messages={$chatStore.messages}
			isLoadingHistory={$chatStore.isLoadingHistory}
			isGeneratingResponse={$chatStore.isGeneratingResponse}
			error={$chatStore.error}
			on:sendMessage={handleSendMessage}
		/>
	</div>
</div>


{#if settingsOpen}
	<Dialog bind:open={settingsOpen}>
		<DialogContent class="sm:max-w-[425px]">
			<DialogHeader>
				<DialogTitle>Chat Settings</DialogTitle>
			</DialogHeader>
			{#if sessionId}
				<SettingsPanel {sessionId} />
			{:else}
				<p class="text-destructive">Error: Session ID is missing.</p>
			{/if}
		</DialogContent>
	</Dialog>
{/if}