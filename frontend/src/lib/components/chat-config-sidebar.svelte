<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button } from './ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
	import { Input } from './ui/input';
	import { Label } from './ui/label';
	import { Textarea } from './ui/textarea';
	import { Separator } from './ui/separator';
	import { Skeleton } from './ui/skeleton';
	import { toast } from 'svelte-sonner';
	import type { ScribeChatSession } from '$lib/types';
	import { apiClient, type UserPersona, type UpdateChatSessionSettingsRequest } from '$lib/api';
	import { chatModels, DEFAULT_CHAT_MODEL, DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT, DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET, DEFAULT_CONTEXT_RAG_BUDGET } from '$lib/ai/models';
	import ChevronLeft from './icons/chevron-down.svelte';
	import ChevronRight from './icons/chevron-up.svelte';
	import ContextConfigurator from '$lib/components/shared/ContextConfigurator.svelte';
	// import { debounce } from 'lodash-es'; // Removed as debounced auto-save is not used

	let {
		isOpen = $bindable(false),
		chat,
		availablePersonas = []
	}: {
		isOpen?: boolean;
		chat: ScribeChatSession | null;
		availablePersonas?: UserPersona[];
	} = $props();

	const dispatch = createEventDispatcher();

	let isLoading = $state(false);
	let localSettings = $state({
		temperature: 1.0,
		max_output_tokens: 1000,
		frequency_penalty: 0.0,
		presence_penalty: 0.0,
		top_p: 0.95,
		top_k: 40,
		repetition_penalty: 1.0,
		min_p: 0.0,
		top_a: 0.0,
		seed: null as number | null,
		logit_bias: null as any,
		system_prompt: '',
		active_custom_persona_id: null as string | null,
		model_name: '',
		gemini_thinking_budget: null as number | null,
		gemini_enable_code_execution: false,
		context_total_token_limit: DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
		context_recent_history_budget: DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
		context_rag_budget: DEFAULT_CONTEXT_RAG_BUDGET
	});

	// Load current chat settings when chat changes
	$effect(() => {
		if (chat) {
			loadChatSettings();
		}
	});

	async function loadChatSettings() {
		if (!chat?.id) return;

		isLoading = true;
		const result = await apiClient.getChatSessionSettings(chat.id);

		if (result.isOk()) {
			const settings = result.value;
			localSettings = {
				temperature: settings.temperature ?? 1.0,
				max_output_tokens: settings.max_output_tokens ?? 1000,
				frequency_penalty: settings.frequency_penalty ?? 0.0,
				presence_penalty: settings.presence_penalty ?? 0.0,
				top_p: settings.top_p ?? 0.95,
				top_k: settings.top_k ?? 40,
				repetition_penalty: settings.repetition_penalty ?? 1.0,
				min_p: settings.min_p ?? 0.0,
				top_a: settings.top_a ?? 0.0,
				seed: settings.seed ?? null,
				logit_bias: settings.logit_bias ?? null,
				system_prompt: settings.system_prompt ?? '',
				active_custom_persona_id: chat.active_custom_persona_id ?? null, // This comes from the chat prop
				model_name: settings.model_name ?? '',
				gemini_thinking_budget: settings.gemini_thinking_budget ?? null,
				gemini_enable_code_execution: settings.gemini_enable_code_execution ?? false,
				context_total_token_limit: settings.context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
				context_recent_history_budget: settings.context_recent_history_budget ?? DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
				context_rag_budget: settings.context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET
			};
		} else {
			console.error('Failed to load chat settings:', result.error);
			toast.error(`Failed to load chat settings: ${result.error.message}`);
			// Fallback for context settings if API fails, using chat prop values if available
			localSettings.context_total_token_limit = chat.context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT;
			localSettings.context_recent_history_budget = chat.context_recent_history_budget ?? DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET;
			localSettings.context_rag_budget = chat.context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET;
		}
		isLoading = false;
	}

	async function saveChatSettings() {
		if (!chat?.id) return;

		isLoading = true;

		const payload: UpdateChatSessionSettingsRequest = {
			temperature: localSettings.temperature,
			max_output_tokens: localSettings.max_output_tokens,
			frequency_penalty: localSettings.frequency_penalty,
			presence_penalty: localSettings.presence_penalty,
			top_p: localSettings.top_p,
			top_k: localSettings.top_k,
			repetition_penalty: localSettings.repetition_penalty,
			min_p: localSettings.min_p,
			top_a: localSettings.top_a,
			seed: localSettings.seed,
			logit_bias: localSettings.logit_bias,
			system_prompt: localSettings.system_prompt,
			active_custom_persona_id: localSettings.active_custom_persona_id,
			model_name: localSettings.model_name,
			gemini_thinking_budget: localSettings.gemini_thinking_budget,
			gemini_enable_code_execution: localSettings.gemini_enable_code_execution,
			context_total_token_limit: localSettings.context_total_token_limit,
			context_recent_history_budget: localSettings.context_recent_history_budget,
			context_rag_budget: localSettings.context_rag_budget
			// Note: 'title' and 'visibility' are not managed by this form currently
			// but are part of UpdateChatSessionSettingsRequest.
		};

		const result = await apiClient.updateChatSessionSettings(chat.id, payload);

		if (result.isOk()) {
			toast.success('Chat settings saved');
			// Update local chat prop with new settings from response if needed,
			// or rely on parent component to refetch/update.
			// For now, dispatching the saved localSettings which should be accurate.
			dispatch('settingsUpdated', result.value); // Dispatch the response from API
		} else {
			console.error('Failed to save chat settings:', result.error);
			toast.error(`Failed to save chat settings: ${result.error.message}`);
		}
		isLoading = false;
	}

	// const debouncedSaveChatSettings = debounce(saveChatSettings, 1000); // Removed for now

	// $effect(() => { // Removed for now - rely on explicit save button
	// 	const { context_total_token_limit, context_recent_history_budget, context_rag_budget } = localSettings;
	// 	if (chat?.id) {
	// 		// Complex logic to determine if actual change occurred vs initial load/default set
	// 		// To avoid unwanted saves, relying on explicit save button for now.
	// 	}
	// });

	function handlePersonaChange(personaId: string | null) {
		localSettings.active_custom_persona_id = personaId;
		dispatch('personaChanged', { personaId });
		// Potentially save settings here too, or let the main save button handle it.
		// saveChatSettings(); // Or debouncedSaveChatSettings();
	}

	function toggleSidebar() {
		isOpen = !isOpen;
	}
</script>

<!-- Toggle Button (always visible on the right edge) -->
<div class="fixed right-4 top-1/2 z-50 -translate-y-1/2">
	<Button
		variant="ghost"
		size="sm"
		onclick={toggleSidebar}
		class="rounded-l-lg rounded-r-none border-l border-y bg-background shadow-lg hover:bg-accent"
		aria-label={isOpen ? 'Close chat settings' : 'Open chat settings'}
	>
		{#if isOpen}
			<ChevronRight class="h-4 w-4" />
		{:else}
			<ChevronLeft class="h-4 w-4" />
		{/if}
	</Button>
</div>

<!-- Sidebar Panel -->
{#if isOpen}
	<div 
		class="fixed right-0 top-0 z-40 h-full w-80 border-l bg-background shadow-xl transition-transform duration-300 ease-in-out"
		style="transform: translateX(0)"
	>
		<div class="flex h-full flex-col">
			<!-- Header -->
			<div class="border-b p-4">
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold">Chat Settings</h2>
					<Button variant="ghost" size="sm" onclick={toggleSidebar}>
						<ChevronRight class="h-4 w-4" />
					</Button>
				</div>
				{#if chat}
					<p class="text-sm text-muted-foreground mt-1">
						{chat.title || 'Untitled Chat'}
					</p>
				{/if}
			</div>

			<!-- Content -->
			<div class="flex-1 overflow-y-auto p-4 space-y-6">
				{#if !chat}
					<div class="text-center text-muted-foreground">
						<p>No chat selected</p>
						<p class="text-sm">Open a chat to configure its settings</p>
					</div>
				{:else if isLoading}
					<!-- Loading skeleton -->
					<div class="space-y-4">
						{#each Array(5) as _}
							<div class="space-y-2">
								<Skeleton class="h-4 w-20" />
								<Skeleton class="h-8 w-full" />
							</div>
						{/each}
					</div>
				{:else}
					<!-- Persona Configuration -->
					<Card>
						<CardHeader>
							<CardTitle class="text-base">Active Persona</CardTitle>
						</CardHeader>
						<CardContent class="space-y-3">
							<div class="space-y-2">
								<Label for="persona-select">Custom Persona</Label>
								<select
									id="persona-select"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={localSettings.active_custom_persona_id}
									onchange={(e) => {
										const target = e.target as HTMLSelectElement | null;
										handlePersonaChange(target?.value || null);
									}}
								>
									<option value="">No custom persona</option>
									{#each availablePersonas as persona}
										<option value={persona.id}>{persona.name}</option>
									{/each}
								</select>
							</div>
						</CardContent>
					</Card>

					<!-- Generation Settings -->
					<Card>
						<CardHeader>
							<CardTitle class="text-base">Generation Settings</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<Label for="temperature">Temperature</Label>
									<Input
										id="temperature"
										type="number"
										min="0"
										max="2"
										step="0.1"
										bind:value={localSettings.temperature}
									/>
								</div>
								<div class="space-y-2">
									<Label for="max-tokens">Max Tokens</Label>
									<Input
										id="max-tokens"
										type="number"
										min="1"
										max="8192"
										bind:value={localSettings.max_output_tokens}
									/>
								</div>
							</div>

							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<Label for="top-p">Top P</Label>
									<Input
										id="top-p"
										type="number"
										min="0"
										max="1"
										step="0.05"
										bind:value={localSettings.top_p}
									/>
								</div>
								<div class="space-y-2">
									<Label for="top-k">Top K</Label>
									<Input
										id="top-k"
										type="number"
										min="0"
										max="100"
										step="1"
										bind:value={localSettings.top_k}
									/>
								</div>
							</div>

							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<Label for="freq-penalty">Frequency Penalty</Label>
									<Input
										id="freq-penalty"
										type="number"
										min="-2"
										max="2"
										step="0.1"
										bind:value={localSettings.frequency_penalty}
									/>
								</div>
								<div class="space-y-2">
									<Label for="presence-penalty">Presence Penalty</Label>
									<Input
										id="presence-penalty"
										type="number"
										min="-2"
										max="2"
										step="0.1"
										bind:value={localSettings.presence_penalty}
									/>
								</div>
							</div>

							<div class="grid grid-cols-3 gap-3">
								<div class="space-y-2">
									<Label for="repetition-penalty">Repetition Penalty</Label>
									<Input
										id="repetition-penalty"
										type="number"
										min="0"
										max="2"
										step="0.1"
										bind:value={localSettings.repetition_penalty}
									/>
								</div>
								<div class="space-y-2">
									<Label for="min-p">Min P</Label>
									<Input
										id="min-p"
										type="number"
										min="0"
										max="1"
										step="0.05"
										bind:value={localSettings.min_p}
									/>
								</div>
								<div class="space-y-2">
									<Label for="top-a">Top A</Label>
									<Input
										id="top-a"
										type="number"
										min="0"
										max="1"
										step="0.05"
										bind:value={localSettings.top_a}
									/>
								</div>
							</div>

							<div class="space-y-2">
								<Label for="seed">Seed (optional)</Label>
								<Input
									id="seed"
									type="number"
									placeholder="Leave empty for random"
									bind:value={localSettings.seed}
								/>
							</div>
						</CardContent>
					</Card>

					<!-- Model & History -->
					<Card>
						<CardHeader>
							<CardTitle class="text-base">Model & History</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="space-y-2">
								<Label for="model">Model Override</Label>
								<select
									id="model"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={localSettings.model_name}
								>
									<option value="">Use global default ({chatModels.find(m => m.id === DEFAULT_CHAT_MODEL)?.name || DEFAULT_CHAT_MODEL})</option>
									{#each chatModels as model}
										<option value={model.id}>{model.name}</option>
									{/each}
								</select>
								<p class="text-xs text-muted-foreground">
									Override the global model setting for this specific chat
								</p>
							</div>
							
							<!-- Context Configuration Override -->
							<ContextConfigurator
								bind:total_token_limit={localSettings.context_total_token_limit}
								bind:recent_history_budget={localSettings.context_recent_history_budget}
								bind:rag_budget={localSettings.context_rag_budget}
								title="Context Override"
								description="Override default context allocation for this chat."
							/>

							<!-- Gemini-specific Options -->
							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<Label for="thinking-budget">Thinking Budget</Label>
									<Input
										id="thinking-budget"
										type="number"
										min="0"
										placeholder="Default"
										bind:value={localSettings.gemini_thinking_budget}
									/>
								</div>
								<div class="space-y-2">
									<Label for="code-execution">Code Execution</Label>
									<select
										id="code-execution"
										class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
										bind:value={localSettings.gemini_enable_code_execution}
									>
										<option value={false}>Disabled</option>
										<option value={true}>Enabled</option>
									</select>
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- System Prompt Override -->
					<Card>
						<CardHeader>
							<CardTitle class="text-base">System Prompt Override</CardTitle>
						</CardHeader>
						<CardContent>
							<div class="space-y-2">
								<Label for="system-prompt">Custom System Prompt</Label>
								<Textarea
									id="system-prompt"
									placeholder="Override the default system prompt for this chat..."
									rows={6}
									bind:value={localSettings.system_prompt}
								/>
								<p class="text-xs text-muted-foreground">
									Leave empty to use the active persona or character's default system prompt
								</p>
							</div>
						</CardContent>
					</Card>

					<!-- Save Button -->
					<div class="sticky bottom-0 bg-background pt-4">
						<Button
							onclick={saveChatSettings}
							disabled={isLoading}
							class="w-full"
						>
							{#if isLoading}
								<svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
									<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
									<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
								</svg>
								Saving...
							{:else}
								Save Settings
							{/if}
						</Button>
					</div>
				{/if}
			</div>
		</div>
	</div>
{/if}

<!-- Backdrop -->
{#if isOpen}
	<div 
		class="fixed inset-0 z-30 bg-black/20 md:hidden"
		onclick={toggleSidebar}
		onkeydown={(e) => e.key === 'Escape' && toggleSidebar()}
		role="button"
		tabindex="0"
		aria-label="Close sidebar"
	></div>
{/if}