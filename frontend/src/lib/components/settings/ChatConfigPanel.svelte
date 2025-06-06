<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button } from '../ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { Textarea } from '../ui/textarea';
	import { Separator } from '../ui/separator';
	import { Skeleton } from '../ui/skeleton';
	import { Badge } from '../ui/badge';
	import { Checkbox } from '../ui/checkbox';
	import { toast } from 'svelte-sonner';
	import type { ScribeChatSession, EnhancedChatSessionLorebookAssociation } from '$lib/types';
	import { apiClient } from '$lib/api';
	import type {
		UserPersona,
		UpdateChatSessionSettingsRequest,
		ChatSessionSettingsResponse,
		UserSettingsResponse // Import UserSettingsResponse
	} from '$lib/types';
	import {
		chatModels,
		DEFAULT_CHAT_MODEL,
		DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
		DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
		DEFAULT_CONTEXT_RAG_BUDGET
	} from '$lib/ai/models';
	import { SettingsStore } from '$lib/stores/settings.svelte'; // Import SettingsStore
	import ChevronDown from '../icons/chevron-down.svelte';
	import ChevronUp from '../icons/chevron-up.svelte';
	import LorebookSelectionDialog from '$lib/components/shared/LorebookSelectionDialog.svelte';
	import ContextConfigurator from '$lib/components/shared/ContextConfigurator.svelte';

	let {
		chat,
		availablePersonas = []
	}: {
		chat: ScribeChatSession | null;
		availablePersonas?: UserPersona[];
	} = $props();

	const dispatch = createEventDispatcher();

	let isLoading = $state(false);
	let globalUserSettings = $state<UserSettingsResponse | null>(null); // New state for global settings

	let localSettings = $state({
		model_name: '', // Will be set from global or chat settings
		active_custom_persona_id: null as string | null,
		system_prompt: '',
		temperature: 1.0, // Will be set from global or chat settings
		max_output_tokens: 1000, // Will be set from global or chat settings
		frequency_penalty: 0.0, // Will be set from global or chat settings
		presence_penalty: 0.0, // Will be set from global or chat settings
		top_p: 0.95, // Will be set from global or chat settings
		top_k: 40, // Will be set from global or chat settings
		seed: null as number | null, // Will be set from global or chat settings
		gemini_thinking_budget: null as number | null, // Will be set from global or chat settings
		gemini_enable_code_execution: false, // Will be set from global or chat settings
		context_total_token_limit: DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT, // Will be set from global or chat settings
		context_recent_history_budget: DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET, // Will be set from global or chat settings
		context_rag_budget: DEFAULT_CONTEXT_RAG_BUDGET // Will be set from global or chat settings
	});

	// Expandable sections
	let expandedSections = $state({
		persona: true,
		lorebooks: true,
		generation: false,
		advanced: false
	});

	// Lorebook state
	let chatLorebookAssociations = $state<EnhancedChatSessionLorebookAssociation[]>([]);
	let isLorebookDialogOpen = $state(false);
	let isLoadingLorebooks = $state(false);

	// Override tracking
	let hasOverrides = $derived(() => {
		return (
			localSettings.temperature !== 1.0 ||
			localSettings.max_output_tokens !== 1000 ||
			localSettings.frequency_penalty !== 0.0 ||
			localSettings.presence_penalty !== 0.0 ||
			localSettings.top_p !== 0.95 ||
			localSettings.top_k !== 40 ||
			localSettings.seed !== null ||
			localSettings.gemini_thinking_budget !== null ||
			localSettings.gemini_enable_code_execution !== false ||
			(localSettings.system_prompt && localSettings.system_prompt.trim() !== '') ||
			localSettings.model_name !== '' ||
			localSettings.context_total_token_limit !== DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT ||
			localSettings.context_recent_history_budget !== DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET ||
			localSettings.context_rag_budget !== DEFAULT_CONTEXT_RAG_BUDGET
		);
	});

	// Load global settings on component mount
	$effect(() => {
		loadGlobalSettings();
	});

	// Load chat settings when chat prop changes and global settings are loaded
	$effect(() => {
		if (!globalUserSettings) {
			// Wait for global settings to load before proceeding
			return;
		}

		if (chat) {
			loadChatSettings();
			loadLorebookAssociations();
		} else {
			// If no chat is active (new chat), initialize with global defaults
			localSettings = {
				model_name: globalUserSettings.default_model_name || DEFAULT_CHAT_MODEL,
				active_custom_persona_id: null, // New chats don't have an active persona by default
				system_prompt: '', // New chats don't have a system prompt by default
				temperature: parseFloat(String(globalUserSettings.default_temperature ?? 1.0)),
				max_output_tokens: globalUserSettings.default_max_output_tokens || 1000,
				frequency_penalty: globalUserSettings.default_frequency_penalty || 0.0,
				presence_penalty: globalUserSettings.default_presence_penalty || 0.0,
				top_p: parseFloat(parseFloat(String(globalUserSettings.default_top_p ?? 0.95)).toFixed(2)),
				top_k: globalUserSettings.default_top_k ?? 40,
				seed: globalUserSettings.default_seed ?? null,
				gemini_thinking_budget: globalUserSettings.default_gemini_thinking_budget ?? null,
				gemini_enable_code_execution:
					globalUserSettings.default_gemini_enable_code_execution ?? false,
				context_total_token_limit:
					globalUserSettings.default_context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
				context_recent_history_budget:
					globalUserSettings.default_context_recent_history_budget ??
					DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
				context_rag_budget:
					globalUserSettings.default_context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET
			};
		}
	});

	async function loadChatSettings() {
		if (!chat?.id) return;
		isLoading = true;
		const result = await apiClient.getChatSessionSettings(chat.id);
		if (result.isOk()) {
			const settings: ChatSessionSettingsResponse = result.value;

			// Handle system prompt - check if it contains binary data (likely encrypted)
			let systemPrompt = settings.system_prompt ?? '';
			if (systemPrompt && /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]/.test(systemPrompt)) {
				// Contains non-printable characters - likely encrypted data that failed to decrypt
				console.warn('System prompt appears to contain encrypted data that failed to decrypt');
				systemPrompt = ''; // Clear it rather than showing garbage
			}

			localSettings = {
				model_name:
					settings.model_name ?? globalUserSettings?.default_model_name ?? DEFAULT_CHAT_MODEL,
				active_custom_persona_id: chat.active_custom_persona_id ?? null, // This comes from the chat prop
				system_prompt: systemPrompt,
				temperature: parseFloat(
					String(settings.temperature ?? globalUserSettings?.default_temperature ?? 1.0)
				),
				max_output_tokens:
					settings.max_output_tokens ?? globalUserSettings?.default_max_output_tokens ?? 1000,
				frequency_penalty:
					settings.frequency_penalty ?? globalUserSettings?.default_frequency_penalty ?? 0.0,
				presence_penalty:
					settings.presence_penalty ?? globalUserSettings?.default_presence_penalty ?? 0.0,
				top_p: parseFloat(
					parseFloat(String(settings.top_p ?? globalUserSettings?.default_top_p ?? 0.95)).toFixed(2)
				),
				top_k: settings.top_k ?? globalUserSettings?.default_top_k ?? 40,
				seed: settings.seed ?? globalUserSettings?.default_seed ?? null,
				gemini_thinking_budget:
					settings.gemini_thinking_budget ??
					globalUserSettings?.default_gemini_thinking_budget ??
					null,
				gemini_enable_code_execution:
					settings.gemini_enable_code_execution ??
					globalUserSettings?.default_gemini_enable_code_execution ??
					false,
				context_total_token_limit:
					settings.context_total_token_limit ??
					globalUserSettings?.default_context_total_token_limit ??
					DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
				context_recent_history_budget:
					settings.context_recent_history_budget ??
					globalUserSettings?.default_context_recent_history_budget ??
					DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
				context_rag_budget:
					settings.context_rag_budget ??
					globalUserSettings?.default_context_rag_budget ??
					DEFAULT_CONTEXT_RAG_BUDGET
			};
		} else {
			console.error('Failed to load chat settings:', result.error);
			toast.error(`Failed to load chat settings: ${result.error.message}`);
			// Fallback for context settings if API fails, using chat prop values if available
			localSettings.context_total_token_limit =
				chat.context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT;
			localSettings.context_recent_history_budget =
				chat.context_recent_history_budget ?? DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET;
			localSettings.context_rag_budget = chat.context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET;
		}
		isLoading = false;
	}

	async function loadGlobalSettings() {
		isLoading = true;
		try {
			const userSettingsResult = await apiClient.getUserSettings();
			if (userSettingsResult.isOk()) {
				globalUserSettings = userSettingsResult.value;
			} else {
				console.error('Failed to load global user settings:', userSettingsResult.error);
				toast.error('Failed to load global settings');
			}
		} catch (error) {
			console.error('Failed to load global settings:', error);
			toast.error('Failed to load global settings');
		} finally {
			isLoading = false;
		}
	}

	async function loadLorebookAssociations() {
		if (!chat?.id) return;

		isLoadingLorebooks = true;
		const result = await apiClient.getChatLorebookAssociations(chat.id, true); // Use enhanced API

		if (result.isOk()) {
			chatLorebookAssociations = result.value;
		} else {
			console.error('Error loading lorebook associations:', result.error);
		}
		isLoadingLorebooks = false;
	}

	async function saveSettings() {
		if (!chat?.id) return;

		isLoading = true;
		try {
			const updateRequest: UpdateChatSessionSettingsRequest = {
				temperature: localSettings.temperature,
				max_output_tokens: localSettings.max_output_tokens,
				frequency_penalty: localSettings.frequency_penalty,
				presence_penalty: localSettings.presence_penalty,
				top_p: localSettings.top_p,
				top_k: localSettings.top_k,
				seed: localSettings.seed,
				system_prompt: localSettings.system_prompt,
				active_custom_persona_id: localSettings.active_custom_persona_id,
				model_name: localSettings.model_name,
				gemini_thinking_budget: localSettings.gemini_thinking_budget,
				gemini_enable_code_execution: localSettings.gemini_enable_code_execution,
				context_total_token_limit: localSettings.context_total_token_limit,
				context_recent_history_budget: localSettings.context_recent_history_budget,
				context_rag_budget: localSettings.context_rag_budget
			};

			const result = await apiClient.updateChatSessionSettings(chat.id, updateRequest);

			if (result.isOk()) {
				toast.success('Chat settings updated');
				dispatch('settingsUpdated', result.value);
			} else {
				toast.error(`Failed to update settings: ${result.error.message}`);
			}
		} catch (error) {
			console.error('Failed to save chat settings:', error);
			toast.error('Failed to save chat settings');
		} finally {
			isLoading = false;
		}
	}

	async function changePersona(personaId: string | null) {
		if (!chat?.id) return;

		try {
			const result = await apiClient.updateChatSessionSettings(chat.id, {
				active_custom_persona_id: personaId
			});

			if (result.isOk()) {
				localSettings.active_custom_persona_id = personaId;
				toast.success(personaId ? 'Persona changed' : 'Persona removed');
				dispatch('personaChanged', { personaId });
			} else {
				toast.error(`Failed to change persona: ${result.error.message}`);
			}
		} catch (error) {
			console.error('Failed to change persona:', error);
			toast.error('Failed to change persona');
		}
	}

	function clearOverride(
		field:
			| 'temperature'
			| 'max_output_tokens'
			| 'frequency_penalty'
			| 'presence_penalty'
			| 'top_p'
			| 'top_k'
			| 'seed'
			| 'gemini_thinking_budget'
			| 'gemini_enable_code_execution'
			| 'context_total_token_limit'
			| 'context_recent_history_budget'
			| 'context_rag_budget'
	) {
		// Reset to default values based on field type
		if (!globalUserSettings) {
			toast.error('Global settings not loaded, cannot clear override to default.');
			return;
		}
		// Reset to default values based on field type from global settings
		switch (field) {
			case 'temperature':
				localSettings.temperature = parseFloat(
					String(globalUserSettings.default_temperature ?? 1.0)
				);
				break;
			case 'max_output_tokens':
				localSettings.max_output_tokens = globalUserSettings.default_max_output_tokens ?? 1000;
				break;
			case 'frequency_penalty':
				localSettings.frequency_penalty = globalUserSettings.default_frequency_penalty ?? 0.0;
				break;
			case 'presence_penalty':
				localSettings.presence_penalty = globalUserSettings.default_presence_penalty ?? 0.0;
				break;
			case 'top_p':
				localSettings.top_p = parseFloat(
					parseFloat(String(globalUserSettings.default_top_p ?? 0.95)).toFixed(2)
				);
				break;
			case 'top_k':
				localSettings.top_k = globalUserSettings.default_top_k ?? 40;
				break;
			case 'seed':
				localSettings.seed = globalUserSettings.default_seed ?? null;
				break;
			case 'gemini_thinking_budget':
				localSettings.gemini_thinking_budget =
					globalUserSettings.default_gemini_thinking_budget ?? null;
				break;
			case 'gemini_enable_code_execution':
				localSettings.gemini_enable_code_execution =
					globalUserSettings.default_gemini_enable_code_execution ?? false;
				break;
			case 'context_total_token_limit':
				localSettings.context_total_token_limit =
					globalUserSettings.default_context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT;
				break;
			case 'context_recent_history_budget':
				localSettings.context_recent_history_budget =
					globalUserSettings.default_context_recent_history_budget ??
					DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET;
				break;
			case 'context_rag_budget':
				localSettings.context_rag_budget =
					globalUserSettings.default_context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET;
				break;
		}
		toast.info('Override cleared (will use default)');
	}

	function clearAllOverrides() {
		if (!globalUserSettings) {
			toast.error('Global settings not loaded, cannot reset to defaults.');
			return;
		}
		localSettings.temperature = parseFloat(String(globalUserSettings.default_temperature ?? 1.0));
		localSettings.max_output_tokens = globalUserSettings.default_max_output_tokens ?? 1000;
		localSettings.frequency_penalty = globalUserSettings.default_frequency_penalty ?? 0.0;
		localSettings.presence_penalty = globalUserSettings.default_presence_penalty ?? 0.0;
		localSettings.top_p = parseFloat(
			parseFloat(String(globalUserSettings.default_top_p ?? 0.95)).toFixed(2)
		);
		localSettings.top_k = globalUserSettings.default_top_k ?? 40;
		localSettings.seed = globalUserSettings.default_seed ?? null;
		localSettings.gemini_thinking_budget =
			globalUserSettings.default_gemini_thinking_budget ?? null;
		localSettings.gemini_enable_code_execution =
			globalUserSettings.default_gemini_enable_code_execution ?? false;
		localSettings.system_prompt = ''; // System prompt is not part of global settings, always clear
		localSettings.model_name = globalUserSettings.default_model_name || DEFAULT_CHAT_MODEL;
		localSettings.context_total_token_limit =
			globalUserSettings.default_context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT;
		localSettings.context_recent_history_budget =
			globalUserSettings.default_context_recent_history_budget ??
			DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET;
		localSettings.context_rag_budget =
			globalUserSettings.default_context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET;
		toast.info('All overrides cleared');
	}

	async function removeLorebookAssociation(lorebookId: string) {
		if (!chat?.id) return;

		try {
			const result = await apiClient.disassociateLorebookFromChat(chat.id, lorebookId);
			if (result.isOk()) {
				await loadLorebookAssociations(); // Reload to get updated state
				toast.success('Lorebook removed from chat');
			} else {
				toast.error(`Failed to remove lorebook: ${result.error.message}`);
			}
		} catch (error) {
			console.error('Failed to remove lorebook:', error);
			toast.error('Failed to remove lorebook');
		}
	}

	async function toggleCharacterLorebookOverride(lorebookId: string, currentAction?: string) {
		if (!chat?.id) return;

		try {
			// If there's already an override, remove it; otherwise, disable the character lorebook
			if (currentAction) {
				const result = await apiClient.removeCharacterLorebookOverride(chat.id, lorebookId);
				if (result.isOk()) {
					await loadLorebookAssociations();
					toast.success('Override removed');
				} else {
					toast.error(`Failed to remove override: ${result.error.message}`);
				}
			} else {
				const result = await apiClient.setCharacterLorebookOverride(chat.id, lorebookId, 'disable');
				if (result.isOk()) {
					await loadLorebookAssociations();
					toast.success('Character lorebook disabled for this chat');
				} else {
					toast.error(`Failed to disable lorebook: ${result.error.message}`);
				}
			}
		} catch (error) {
			console.error('Failed to toggle lorebook override:', error);
			toast.error('Failed to toggle lorebook override');
		}
	}

	function handleLorebookSelected(
		event: CustomEvent<{ associations: EnhancedChatSessionLorebookAssociation[] }>
	) {
		// Use the updated associations directly from the event payload
		// This avoids a re-fetch and potential timing issues.
		if (event.detail && event.detail.associations) {
			chatLorebookAssociations = event.detail.associations;
		} else {
			// Fallback to refetch if payload is not as expected, though it should be.
			console.warn('Lorebook update event did not contain associations, refetching.');
			loadLorebookAssociations();
		}
	}
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="flex items-center justify-between border-b p-4">
		<div>
			<h2 class="text-lg font-semibold">Chat Configuration</h2>
			<p class="text-sm text-muted-foreground">
				{chat?.title || 'Configure this chat'}
			</p>
		</div>
		{#if hasOverrides()}
			<Button
				variant="ghost"
				size="sm"
				onclick={clearAllOverrides}
				class="text-muted-foreground hover:text-foreground"
			>
				Clear All
			</Button>
		{/if}
	</div>

	<!-- Content -->
	<div class="flex-1 overflow-y-auto">
		<div class="space-y-4 p-4">
			{#if isLoading}
				<div class="space-y-4">
					<Skeleton class="h-20 w-full" />
					<Skeleton class="h-20 w-full" />
					<Skeleton class="h-20 w-full" />
				</div>
			{:else}
				<!-- Active Persona -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.persona = !expandedSections.persona)}
						class="cursor-pointer {expandedSections.persona ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<CardTitle class="text-base">Active Persona</CardTitle>
							{#if expandedSections.persona}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.persona}
						<CardContent class="space-y-3">
							<div class="space-y-2">
								<select
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={localSettings.active_custom_persona_id}
									onchange={(e) => changePersona((e.target as HTMLSelectElement).value || null)}
								>
									<option value="">No persona</option>
									{#each availablePersonas as persona}
										<option value={persona.id}>{persona.name}</option>
									{/each}
								</select>
								<p class="text-xs text-muted-foreground">Override the user persona for this chat</p>
							</div>
						</CardContent>
					{/if}
				</Card>

				<!-- Lorebook Associations -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.lorebooks = !expandedSections.lorebooks)}
						class="cursor-pointer {expandedSections.lorebooks ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<CardTitle class="text-base">
								Lorebooks ({chatLorebookAssociations.length})
							</CardTitle>
							{#if expandedSections.lorebooks}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.lorebooks}
						<CardContent class="space-y-3">
							{#if isLoadingLorebooks}
								<div class="space-y-2">
									<Skeleton class="h-8 w-full" />
									<Skeleton class="h-8 w-full" />
								</div>
							{:else if chatLorebookAssociations.length === 0}
								<p class="text-sm text-muted-foreground">No lorebooks associated</p>
							{:else}
								<div class="space-y-2">
									{#each chatLorebookAssociations as assoc (assoc.lorebook_id)}
										<div class="space-y-2 rounded border p-3">
											<div class="flex items-center justify-between">
												<div class="flex items-center gap-2">
													<span class="text-sm font-medium">{assoc.lorebook_name}</span>
													<Badge
														variant={assoc.source === 'Chat' ? 'default' : 'secondary'}
														class="text-xs"
													>
														{assoc.source === 'Chat' ? 'Chat' : 'Character'}
													</Badge>
													{#if assoc.is_overridden}
														<Badge variant="outline" class="text-xs">
															{assoc.override_action === 'disable' ? 'Disabled' : 'Enabled'}
														</Badge>
													{/if}
												</div>
											</div>

											<div class="flex items-center gap-2" data-testid="lorebook-card">
												{#if assoc.source === 'Chat'}
													<Button
														variant="destructive"
														size="sm"
														onclick={() => removeLorebookAssociation(assoc.lorebook_id)}
														class="text-xs"
													>
														Remove
													</Button>
												{:else if assoc.source === 'Character'}
													<!-- Character lorebook -->
													<Button
														variant={assoc.is_overridden && assoc.override_action === 'disable'
															? 'outline'
															: 'destructive'}
														size="sm"
														onclick={() =>
															toggleCharacterLorebookOverride(
																assoc.lorebook_id,
																assoc.override_action
															)}
														class="text-xs"
													>
														{#if assoc.is_overridden && assoc.override_action === 'disable'}
															Restore
														{:else}
															Disable
														{/if}
													</Button>
												{/if}
												<span class="text-xs text-muted-foreground">
													{#if assoc.source === 'Chat'}
														Directly associated with this chat
													{:else if assoc.source === 'Character' && assoc.is_overridden}
														Character lorebook (overridden)
													{:else if assoc.source === 'Character'}
														From character
													{/if}
												</span>
											</div>
										</div>
									{/each}
								</div>
							{/if}

							<Button
								variant="outline"
								onclick={() => (isLorebookDialogOpen = true)}
								class="w-full"
							>
								Manage Lorebooks
							</Button>
						</CardContent>
					{/if}
				</Card>

				<!-- Generation Settings -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.generation = !expandedSections.generation)}
						class="cursor-pointer {expandedSections.generation ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<CardTitle class="text-base">Generation Settings</CardTitle>
							{#if expandedSections.generation}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.generation}
						<CardContent class="space-y-4">
							<div class="space-y-2">
								<Label for="model">Model Override</Label>
								<select
									id="model"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={localSettings.model_name}
								>
									<option value="">
										Use global default ({chatModels.find((m) => m.id === DEFAULT_CHAT_MODEL)
											?.name || DEFAULT_CHAT_MODEL})
									</option>
									{#each chatModels as model}
										<option value={model.id}>{model.name}</option>
									{/each}
								</select>
								<p class="text-xs text-muted-foreground">
									Override the global model setting for this specific chat
								</p>
							</div>

							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<Label for="temperature">Temperature</Label>
										{#if localSettings.temperature !== 1.0}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('temperature')}
											>
												Clear
											</Button>
										{/if}
									</div>
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
									<div class="flex items-center justify-between">
										<Label for="max-tokens">Max Tokens</Label>
										{#if localSettings.max_output_tokens !== 1000}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('max_output_tokens')}
											>
												Clear
											</Button>
										{/if}
									</div>
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
									<div class="flex items-center justify-between">
										<Label for="top-p">Top P</Label>
										{#if localSettings.top_p !== 0.95}
											<Button variant="ghost" size="sm" onclick={() => clearOverride('top_p')}>
												Clear
											</Button>
										{/if}
									</div>
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
									<div class="flex items-center justify-between">
										<Label for="top-k">Top K</Label>
										{#if localSettings.top_k !== 40}
											<Button variant="ghost" size="sm" onclick={() => clearOverride('top_k')}>
												Clear
											</Button>
										{/if}
									</div>
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
									<div class="flex items-center justify-between">
										<Label for="freq-penalty">Frequency Penalty</Label>
										{#if localSettings.frequency_penalty !== 0.0}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('frequency_penalty')}
											>
												Clear
											</Button>
										{/if}
									</div>
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
									<div class="flex items-center justify-between">
										<Label for="presence-penalty">Presence Penalty</Label>
										{#if localSettings.presence_penalty !== 0.0}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('presence_penalty')}
											>
												Clear
											</Button>
										{/if}
									</div>
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

							<div class="space-y-2">
								<div class="flex items-center justify-between">
									<Label for="seed">Seed (optional)</Label>
									{#if localSettings.seed !== null}
										<Button variant="ghost" size="sm" onclick={() => clearOverride('seed')}>
											Clear
										</Button>
									{/if}
								</div>
								<Input
									id="seed"
									type="number"
									placeholder="Leave empty for random"
									bind:value={localSettings.seed}
								/>
							</div>
						</CardContent>
					{/if}
				</Card>

				<!-- Model & History -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.advanced = !expandedSections.advanced)}
						class="cursor-pointer {expandedSections.advanced ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<CardTitle class="text-base">Advanced Settings</CardTitle>
							{#if expandedSections.advanced}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.advanced}
						<CardContent class="space-y-4">
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
									<div class="flex items-center justify-between">
										<Label for="thinking-budget">Thinking Budget</Label>
										{#if localSettings.gemini_thinking_budget !== null}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('gemini_thinking_budget')}
											>
												Clear
											</Button>
										{/if}
									</div>
									<Input
										id="thinking-budget"
										type="number"
										min="0"
										placeholder="Default"
										bind:value={localSettings.gemini_thinking_budget}
									/>
								</div>
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<Label for="code-execution">Code Execution</Label>
										{#if localSettings.gemini_enable_code_execution !== false}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('gemini_enable_code_execution')}
											>
												Clear
											</Button>
										{/if}
									</div>
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

							<!-- System Prompt Override -->
							<div class="space-y-2">
								<div class="flex items-center justify-between">
									<Label for="system-prompt">System Prompt Override</Label>
									{#if localSettings.system_prompt && localSettings.system_prompt.trim() !== ''}
										<Button
											variant="ghost"
											size="sm"
											onclick={() => {
												localSettings.system_prompt = '';
												toast.info('System prompt cleared');
											}}
										>
											Clear
										</Button>
									{/if}
								</div>
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
					{/if}
				</Card>
			{/if}
		</div>
	</div>

	<!-- Footer -->
	<div class="border-t p-4">
		<Button onclick={saveSettings} disabled={isLoading} class="w-full">
			{#if isLoading}
				<svg
					class="-ml-1 mr-2 h-4 w-4 animate-spin"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
				>
					<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"
					></circle>
					<path
						class="opacity-75"
						fill="currentColor"
						d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
					></path>
				</svg>
				Saving...
			{:else}
				Save Chat Settings
			{/if}
		</Button>
	</div>
</div>

<!-- Lorebook Selection Dialog -->
{#if isLorebookDialogOpen && chat}
	<LorebookSelectionDialog
		bind:open={isLorebookDialogOpen}
		chatId={chat.id}
		currentAssociations={chatLorebookAssociations}
		on:updated={handleLorebookSelected}
	/>
{/if}
