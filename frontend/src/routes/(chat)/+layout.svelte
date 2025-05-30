<script lang="ts">
	import AppSidebar from '$lib/components/app-sidebar.svelte';
	import { SidebarInset, SidebarProvider } from '$lib/components/ui/sidebar';
	import { ChatHistory } from '$lib/hooks/chat-history.svelte.js';
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { toast } from 'svelte-sonner';
	import { onMount } from 'svelte';

	let { data, children } = $props();

	const chatHistory = new ChatHistory(data.chats);
	chatHistory.setContext();
	data.selectedChatModel.setContext();

	const selectedCharacterStore = new SelectedCharacterStore();
	selectedCharacterStore.setContext();

	const selectedPersonaStore = new SelectedPersonaStore();
	selectedPersonaStore.setContext();

	const settingsStore = SettingsStore.toContext(new SettingsStore());

	// Show toast notification if chat loading failed during SSR/initial load
	onMount(() => {
		if (data.chatsError) {
			toast.error('Could not load chat history.', {
				description: 'The server might be restarting. Please try refreshing the page.',
				duration: 10000 // Show for 10 seconds
			});
		}
	});

</script>

<SidebarProvider open={!data.sidebarCollapsed}>
	<AppSidebar user={data.user} />
	<SidebarInset>{@render children?.()}</SidebarInset>
</SidebarProvider>
