<script lang="ts">
	import AppSidebar from '$lib/components/app-sidebar.svelte';
	import { SidebarInset, SidebarProvider } from '$lib/components/ui/sidebar';
	import { ChatHistory } from '$lib/hooks/chat-history.svelte.js';
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SelectedLorebookStore } from '$lib/stores/selected-lorebook.svelte';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { SidebarStore } from '$lib/stores/sidebar.svelte';
	import { LLMStore } from '$lib/stores/llm.svelte';
	import { ModelLifecycleStore } from '$lib/stores/modelLifecycle.svelte';
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

	const selectedLorebookStore = new SelectedLorebookStore();
	selectedLorebookStore.setContext();

	const selectedChronicleStore = new SelectedChronicleStore();
	selectedChronicleStore.setInContext();

	const _settingsStore = SettingsStore.toContext(new SettingsStore());

	const _sidebarStore = SidebarStore.toContext(new SidebarStore());

	// Initialize LlmStore for chat components
	const _llmStore = LLMStore.toContext(new LLMStore());

	// Initialize ModelLifecycleStore for chat components
	const _modelLifecycleStore = ModelLifecycleStore.toContext(new ModelLifecycleStore());

	// Show toast notification if chat loading failed during SSR/initial load
	onMount(() => {
		// Fetch models for chat components
		_llmStore.fetchModels().catch((error) => {
			console.warn('Failed to fetch models in chat layout:', error);
		});

		if (data.chatsError) {
			toast.error('Could not load chat history.', {
				description: 'The server might be restarting. Please try refreshing the page.',
				duration: 10000 // Show for 10 seconds
			});
		}
	});
</script>

<SidebarProvider open={!data.sidebarCollapsed}>
	<AppSidebar />
	<SidebarInset>{@render children?.()}</SidebarInset>
</SidebarProvider>
