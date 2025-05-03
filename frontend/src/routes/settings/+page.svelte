<script lang="ts">
	import SettingsPanel from '$lib/components/settings/SettingsPanel.svelte';
	import { page } from '$app/stores';
	import { getActiveSessionId } from '$lib/stores/chatStore';
	import { onMount } from 'svelte';
	
	let sessionId = $state<string | null>(null);

	onMount(() => {
		// Get the active session ID for settings
		sessionId = getActiveSessionId();
	});
</script>

<div class="container mx-auto py-6 px-4 md:px-6">
	<h1 class="text-3xl font-bold mb-4">Chat Settings</h1>
	<p class="text-muted-foreground mb-6">
		Adjust your chat model settings for the current session.
	</p>

	{#if sessionId}
		<SettingsPanel {sessionId} />
	{:else}
		<div class="bg-muted p-4 rounded-md my-4">
			<p>No active chat session found. Please start a chat session first.</p>
			<a href="/characters" class="text-primary hover:underline mt-2 inline-block">
				Start a New Chat
			</a>
		</div>
	{/if}
</div> 