<script lang="ts">
	import { createEventDispatcher, onMount } from 'svelte';
	import { Button as ButtonComponent } from '../ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { Textarea as TextareaComponent } from '../ui/textarea';
	import { Separator as _SeparatorComponent } from '../ui/separator';
	import { Skeleton } from '../ui/skeleton';
	import { Badge as BadgeComponent } from '../ui/badge';
	import { Checkbox as CheckboxComponent } from '../ui/checkbox';
	import { toast } from 'svelte-sonner';
	import type {
		ScribeChatSession,
		EnhancedChatSessionLorebookAssociation,
		PlayerChronicleWithCounts,
		UserSettingsResponse
	} from '$lib/types';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import type {
		UserPersona,
		UpdateChatSessionSettingsRequest,
		ChatSessionSettingsResponse,
		UserSettingsResponse as _UserSettingsResponse, // Import UserSettingsResponse
		CreateChronicleRequest,
		TemplatePreferenceResponse,
		UpdateTemplatePreferenceRequest,
		NarrativeTense,
		NarrativeNarration,
		NarrativePerspective,
		ResponseLength
	} from '$lib/types';
	import {
		chatModels,
		DEFAULT_CHAT_MODEL,
		DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
		DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
		DEFAULT_CONTEXT_RAG_BUDGET
	} from '$lib/ai/models';
	import { SettingsStore as _SettingsStore } from '$lib/stores/settings.svelte';
	import ChevronDown from '../icons/chevron-down.svelte';
	import ChevronUp from '../icons/chevron-up.svelte';
	import LorebookSelectionDialog from '$lib/components/shared/LorebookSelectionDialog.svelte';
	import ContextConfigurator from '$lib/components/shared/ContextConfigurator.svelte';
	import ContextConfiguratorCompact from '$lib/components/shared/ContextConfiguratorCompact.svelte';
	import TemplateSelector from '$lib/components/shared/TemplateSelector.svelte';

	let {
		chat,
		availablePersonas = [],
		compact = false
	}: {
		chat: ScribeChatSession | null;
		availablePersonas?: UserPersona[];
		compact?: boolean; // When true, use compact layout for sidebar
	} = $props();

	const dispatch = createEventDispatcher();

	let isLoading = $state(false);
	let globalUserSettings = $state<UserSettingsResponse | null>(null); // New state for global settings

	let localSettings = $state({
		model_name: '', // Will be set from global or chat settings
		active_custom_persona_id: null as string | null,
		temperature: 1.0, // Will be set from global or chat settings
		max_output_tokens: 1000, // Will be set from global or chat settings
		frequency_penalty: 0.0, // Will be set from global or chat settings
		presence_penalty: 0.0, // Will be set from global or chat settings
		top_p: 0.95, // Will be set from global or chat settings
		top_k: 40, // Will be set from global or chat settings
		seed: null as number | null, // Will be set from global or chat settings
		gemini_thinking_budget: null as number | null, // Will be set from global or chat settings
		gemini_thinking_level: null as string | null, // Will be set from global or chat settings
		gemini_enable_code_execution: false, // Will be set from global or chat settings
		context_total_token_limit: DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT, // Will be set from global or chat settings
		context_recent_history_budget: DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET, // Will be set from global or chat settings
		context_rag_budget: DEFAULT_CONTEXT_RAG_BUDGET, // Will be set from global or chat settings
		rag_chronicles_limit: 20000,
		rag_lorebooks_limit: 20000,
		rag_older_chat_limit: 10000,
		agent_mode: 'disabled' as 'disabled' | 'pre_processing' | 'post_processing', // Context enrichment agent mode
		prompt_template_id: 'neutral_roleplay', // Will be set from global or chat settings
		game_master_mode_enabled: false // Will be set from chat settings
	});

	// Typing speed state (client-side preference)
	let typingSpeed = $state(30); // milliseconds per character

	// Get SettingsStore reference during component initialization
	let settingsStore: _SettingsStore;
	try {
		settingsStore = _SettingsStore.fromContext();
	} catch (e) {
		console.warn('SettingsStore not available in ChatConfigPanel context:', e);
	}

	// Expandable sections
	let expandedSections = $state({
		persona: true,
		lorebooks: true,
		chronicles: true,
		templates: true,
		sessionStyle: false,
		generation: false,
		advanced: false,
		gamemaster: false
	});

	// Lorebook state
	let chatLorebookAssociations = $state<EnhancedChatSessionLorebookAssociation[]>([]);
	let isLorebookDialogOpen = $state(false);
	let isLoadingLorebooks = $state(false);

	// Chronicle state
	let currentChronicleId = $state<string | null>(null);
	let availableChronicles = $state<PlayerChronicleWithCounts[]>([]);
	let isLoadingChronicles = $state(false);

	// Chronicle creation state
	let showChronicleCreationForm = $state(false);
	let newChronicleName = $state('');
	let newChronicleDescription = $state('');
	let isCreatingChronicle = $state(false);

	// Session narrative style override state
	let sessionNarrativeStyle = $state<TemplatePreferenceResponse | null>(null);
	let isLoadingSessionStyle = $state(false);
	let hasSessionStyleOverride = $derived(sessionNarrativeStyle !== null);

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
			localSettings.gemini_thinking_level !== null ||
			localSettings.gemini_enable_code_execution !== false ||
			localSettings.model_name !== '' ||
			localSettings.context_total_token_limit !== DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT ||
			localSettings.context_recent_history_budget !== DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET ||
			localSettings.context_rag_budget !== DEFAULT_CONTEXT_RAG_BUDGET ||
			localSettings.rag_chronicles_limit !== 20000 ||
			localSettings.rag_lorebooks_limit !== 20000 ||
			localSettings.rag_older_chat_limit !== 10000 ||
			localSettings.game_master_mode_enabled !== false
		);
	});

	// Load global settings and typing speed on component mount
	$effect(() => {
		loadGlobalSettings();
		loadTypingSpeed();
	});

	// Listen for chronicle creation events to refresh the chronicle list
	onMount(() => {
		const handleChronicleCreated = async (_event: CustomEvent) => {
			console.log('[Chat Config] New chronicle created, refreshing chronicles');
			await loadChronicles();
		};

		window.addEventListener('chronicle-created', handleChronicleCreated as unknown as () => void);

		return () => {
			window.removeEventListener(
				'chronicle-created',
				handleChronicleCreated as unknown as () => void
			);
		};
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
			loadChronicles();
			// Initialize current chronicle from chat data
			currentChronicleId = chat.chronicle_id || null;
		} else {
			// If no chat is active (new chat), initialize with global defaults
			localSettings = {
				model_name: globalUserSettings.default_model_name || DEFAULT_CHAT_MODEL,
				active_custom_persona_id: null, // New chats don't have an active persona by default
				temperature: parseFloat(String(globalUserSettings.default_temperature ?? 1.0)),
				max_output_tokens: globalUserSettings.default_max_output_tokens || 1000,
				frequency_penalty: globalUserSettings.default_frequency_penalty || 0.0,
				presence_penalty: globalUserSettings.default_presence_penalty || 0.0,
				top_p: parseFloat(parseFloat(String(globalUserSettings.default_top_p ?? 0.95)).toFixed(2)),
				top_k: globalUserSettings.default_top_k ?? 40,
				seed: globalUserSettings.default_seed ?? null,
				gemini_thinking_budget: globalUserSettings.default_gemini_thinking_budget ?? null,
				gemini_thinking_level: globalUserSettings.default_gemini_thinking_level ?? null,
				gemini_enable_code_execution:
					globalUserSettings.default_gemini_enable_code_execution ?? false,
				context_total_token_limit:
					globalUserSettings.default_context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT,
				context_recent_history_budget:
					globalUserSettings.default_context_recent_history_budget ??
					DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET,
				context_rag_budget:
					globalUserSettings.default_context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET,
				rag_chronicles_limit: globalUserSettings.default_rag_chronicles_limit ?? 20000,
				rag_lorebooks_limit: globalUserSettings.default_rag_lorebooks_limit ?? 20000,
				rag_older_chat_limit: globalUserSettings.default_rag_older_chat_limit ?? 10000,
				agent_mode: 'disabled',
				prompt_template_id: 'neutral_roleplay',
				game_master_mode_enabled: false
			};
		}
	});

	async function loadChatSettings() {
		if (!chat?.id) return;
		isLoading = true;
		const result = await _apiClient.getChatSessionSettings(chat.id);
		if (result.isOk()) {
			const settings: ChatSessionSettingsResponse = result.value;

			localSettings = {
				model_name:
					settings.model_name ?? globalUserSettings?.default_model_name ?? DEFAULT_CHAT_MODEL,
				active_custom_persona_id: chat.active_custom_persona_id ?? null, // This comes from the chat prop
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
				gemini_thinking_level:
					settings.gemini_thinking_level ??
					globalUserSettings?.default_gemini_thinking_level ??
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
					DEFAULT_CONTEXT_RAG_BUDGET,
				rag_chronicles_limit:
					settings.rag_chronicles_limit ??
					globalUserSettings?.default_rag_chronicles_limit ??
					20000,
				rag_lorebooks_limit:
					settings.rag_lorebooks_limit ?? globalUserSettings?.default_rag_lorebooks_limit ?? 20000,
				rag_older_chat_limit:
					settings.rag_older_chat_limit ??
					globalUserSettings?.default_rag_older_chat_limit ??
					10000,
				agent_mode:
					(settings.agent_mode as 'pre_processing' | 'post_processing' | 'disabled') ?? 'disabled',
				prompt_template_id: settings.prompt_template_id ?? 'neutral_roleplay',
				game_master_mode_enabled: settings.game_master_mode_enabled ?? false
			};

			// IMPORTANT: Update currentChronicleId from the fresh backend settings
			// This ensures the UI shows the correct chronicle association from the database
			currentChronicleId = settings.chronicle_id || null;
		} else {
			console.error('Failed to load chat settings:', result.error);
			toast.error(`Failed to load chat settings: ${result.error.message}`);
			// Fallback for context settings if API fails, using chat prop values if available
			localSettings.context_total_token_limit =
				chat.context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT;
			localSettings.context_recent_history_budget =
				chat.context_recent_history_budget ?? DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET;
			localSettings.context_rag_budget = chat.context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET;
			localSettings.agent_mode = 'disabled';
		}
		isLoading = false;
	}

	let lastGlobalSettingsLoad = 0;
	const GLOBAL_SETTINGS_THROTTLE = 2000; // 2 seconds minimum between loads

	async function loadGlobalSettings() {
		const now = Date.now();
		if (now - lastGlobalSettingsLoad < GLOBAL_SETTINGS_THROTTLE) {
			console.log('Throttling global settings load request');
			return;
		}

		lastGlobalSettingsLoad = now;
		isLoading = true;
		try {
			const userSettingsResult = await _apiClient.getUserSettings();
			if (userSettingsResult.isOk()) {
				globalUserSettings = userSettingsResult.value;
			} else {
				console.error('Failed to load global user settings:', userSettingsResult.error);
				// Don't show error toast if rate limited, as it's expected
				if (
					'statusCode' in userSettingsResult.error &&
					userSettingsResult.error.statusCode !== 429
				) {
					toast.error('Failed to load global settings');
				} else if (!('statusCode' in userSettingsResult.error)) {
					// Show error for non-response errors (client/network errors)
					toast.error('Failed to load global settings');
				}
			}
		} catch (_error) {
			console.error('Failed to load global settings:', _error);
			toast.error('Failed to load global settings');
		} finally {
			isLoading = false;
		}
	}

	async function loadTypingSpeed() {
		try {
			if (!settingsStore) {
				console.warn('SettingsStore not available, using default typing speed');
				typingSpeed = 30;
				return;
			}
			await settingsStore.loadTypingSpeed();
			typingSpeed = settingsStore.typingSpeed;
		} catch (_error) {
			console.warn('Failed to load typing speed, using default:', _error);
			typingSpeed = 30; // Fallback to default
		}
	}

	async function saveTypingSpeed() {
		try {
			if (!settingsStore) {
				toast.error('Settings not available');
				return;
			}
			settingsStore.typingSpeed = typingSpeed;
			await settingsStore.saveTypingSpeed();
			toast.success('Typing speed updated');
		} catch (_error) {
			console.error('Failed to save typing speed:', _error);
			toast.error('Failed to save typing speed');
		}
	}

	async function loadLorebookAssociations() {
		if (!chat?.id) return;

		isLoadingLorebooks = true;
		const result = await _apiClient.getChatLorebookAssociations(chat.id, true); // Use enhanced API

		if (result.isOk()) {
			chatLorebookAssociations = result.value;
		} else {
			console.error('Error loading lorebook associations:', result.error);
		}
		isLoadingLorebooks = false;
	}

	async function loadChronicles() {
		isLoadingChronicles = true;
		try {
			const result = await _apiClient.getChronicles();
			if (result.isOk()) {
				availableChronicles = result.value;
			} else {
				console.error('Error loading chronicles:', result.error);
				toast.error('Failed to load chronicles');
			}
		} catch (_error) {
			console.error('Error loading chronicles:', _error);
			toast.error('Failed to load chronicles');
		}
		isLoadingChronicles = false;
	}

	async function updateChronicleAssociation(chronicleId: string | null) {
		if (!chat?.id) return;

		isLoading = true;
		try {
			const updateRequest: UpdateChatSessionSettingsRequest = {
				chronicle_id: chronicleId
			};

			const result = await _apiClient.updateChatSessionSettings(chat.id, updateRequest);
			if (result.isOk()) {
				currentChronicleId = chronicleId;
				// Update the chat object to reflect the change
				if (chat) {
					chat.chronicle_id = chronicleId;
				}
				// Refresh chronicle store to update chat counts
				await chronicleStore.refresh();
				toast.success(chronicleId ? 'Chat linked to chronicle' : 'Chat unlinked from chronicle');
				dispatch('settingsUpdated', { chronicle_id: chronicleId });
			} else {
				toast.error('Failed to update chronicle association');
				console.error('Error updating chronicle association:', result.error);
			}
		} catch (_error) {
			console.error('Error updating chronicle association:', _error);
			toast.error('Failed to update chronicle association');
		}
		isLoading = false;
	}

	async function createChronicle() {
		if (!newChronicleName.trim()) {
			toast.error('Chronicle name is required');
			return;
		}

		isCreatingChronicle = true;
		try {
			const data: CreateChronicleRequest = {
				name: newChronicleName.trim(),
				description: newChronicleDescription.trim() || undefined
			};

			const result = await _apiClient.createChronicle(data);
			if (result.isOk()) {
				toast.success('Chronicle created successfully');
				// Refresh chronicles list
				await loadChronicles();
				// Auto-link the new chronicle to this chat if we have one
				if (chat?.id) {
					await updateChronicleAssociation(result.value.id);
				}
				// Reset form and hide it
				newChronicleName = '';
				newChronicleDescription = '';
				showChronicleCreationForm = false;
			} else {
				toast.error('Failed to create chronicle');
				console.error('Error creating chronicle:', result.error);
			}
		} catch (_error) {
			console.error('Error creating chronicle:', _error);
			toast.error('Failed to create chronicle');
		}
		isCreatingChronicle = false;
	}

	function cancelChronicleCreation() {
		newChronicleName = '';
		newChronicleDescription = '';
		showChronicleCreationForm = false;
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
				active_custom_persona_id: localSettings.active_custom_persona_id,
				model_name: localSettings.model_name,
				gemini_thinking_budget: localSettings.gemini_thinking_budget,
				gemini_thinking_level: localSettings.gemini_thinking_level,
				gemini_enable_code_execution: localSettings.gemini_enable_code_execution,
				// NOTE: context fields removed - backend doesn't have these (causes 422)
				chronicle_id: currentChronicleId,
				agent_mode: localSettings.agent_mode,
				prompt_template_id: localSettings.prompt_template_id,
				game_master_mode_enabled: localSettings.game_master_mode_enabled,
				rag_chronicles_limit: localSettings.rag_chronicles_limit,
				rag_lorebooks_limit: localSettings.rag_lorebooks_limit,
				rag_older_chat_limit: localSettings.rag_older_chat_limit
			};

			const result = await _apiClient.updateChatSessionSettings(chat.id, updateRequest);

			if (result.isOk()) {
				// Update the chat object to reflect the chronicle association change
				if (chat) {
					chat.chronicle_id = result.value.chronicle_id || null;
				}
				// Update local state to match the response
				currentChronicleId = result.value.chronicle_id || null;
				// Refresh chronicle store to update chat counts if chronicle was changed
				if (result.value.chronicle_id) {
					await chronicleStore.refresh();
				}
				toast.success('Chat settings updated');
				dispatch('settingsUpdated', result.value);
			} else {
				toast.error(`Failed to update settings: ${result.error.message}`);
			}
		} catch (_error) {
			console.error('Failed to save chat settings:', _error);
			toast.error('Failed to save chat settings');
		} finally {
			isLoading = false;
		}
	}

	async function changePersona(personaId: string | null) {
		if (!chat?.id) return;

		try {
			const result = await _apiClient.updateChatSessionSettings(chat.id, {
				active_custom_persona_id: personaId
			});

			if (result.isOk()) {
				localSettings.active_custom_persona_id = personaId;
				toast.success(personaId ? 'Persona changed' : 'Persona removed');
				dispatch('personaChanged', { personaId });
			} else {
				toast.error(`Failed to change persona: ${result.error.message}`);
			}
		} catch (_error) {
			console.error('Failed to change persona:', _error);
			toast.error('Failed to change persona');
		}
	}

	async function handleTemplateChange(templateId: string) {
		if (!chat?.id) return;

		try {
			localSettings.prompt_template_id = templateId;

			const result = await _apiClient.updateChatSessionSettings(chat.id, {
				prompt_template_id: templateId
			});

			if (result.isOk()) {
				toast.success('Prompt template updated');
				dispatch('settingsUpdated', { prompt_template_id: templateId });
			} else {
				console.error('Failed to update template:', result.error);
				toast.error('Failed to update prompt template');
				// Revert the local setting
				await loadChatSettings();
			}
		} catch (_error) {
			console.error('Failed to change template:', _error);
			toast.error('Failed to change template');
			// Revert the local setting
			await loadChatSettings();
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
			| 'gemini_thinking_level'
			| 'gemini_enable_code_execution'
			| 'context_total_token_limit'
			| 'context_recent_history_budget'
			| 'context_rag_budget'
			| 'rag_chronicles_limit'
			| 'rag_lorebooks_limit'
			| 'rag_older_chat_limit'
			| 'game_master_mode_enabled'
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
			case 'gemini_thinking_level':
				localSettings.gemini_thinking_level =
					globalUserSettings.default_gemini_thinking_level ?? null;
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
			case 'rag_chronicles_limit':
				localSettings.rag_chronicles_limit =
					globalUserSettings.default_rag_chronicles_limit ?? 20000;
				break;
			case 'rag_lorebooks_limit':
				localSettings.rag_lorebooks_limit = globalUserSettings.default_rag_lorebooks_limit ?? 20000;
				break;
			case 'rag_older_chat_limit':
				localSettings.rag_older_chat_limit =
					globalUserSettings.default_rag_older_chat_limit ?? 10000;
				break;
			case 'game_master_mode_enabled':
				localSettings.game_master_mode_enabled = false;
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
		localSettings.gemini_thinking_level = globalUserSettings.default_gemini_thinking_level ?? null;
		localSettings.gemini_enable_code_execution =
			globalUserSettings.default_gemini_enable_code_execution ?? false;
		localSettings.model_name = globalUserSettings.default_model_name || DEFAULT_CHAT_MODEL;
		localSettings.context_total_token_limit =
			globalUserSettings.default_context_total_token_limit ?? DEFAULT_CONTEXT_TOTAL_TOKEN_LIMIT;
		localSettings.context_recent_history_budget =
			globalUserSettings.default_context_recent_history_budget ??
			DEFAULT_CONTEXT_RECENT_HISTORY_BUDGET;
		localSettings.context_rag_budget =
			globalUserSettings.default_context_rag_budget ?? DEFAULT_CONTEXT_RAG_BUDGET;
		localSettings.rag_chronicles_limit = globalUserSettings.default_rag_chronicles_limit ?? 20000;
		localSettings.rag_lorebooks_limit = globalUserSettings.default_rag_lorebooks_limit ?? 20000;
		localSettings.rag_older_chat_limit = globalUserSettings.default_rag_older_chat_limit ?? 10000;
		localSettings.game_master_mode_enabled = false;
		toast.info('All overrides cleared');
	}

	async function removeLorebookAssociation(lorebookId: string) {
		if (!chat?.id) return;

		try {
			const result = await _apiClient.disassociateLorebookFromChat(chat.id, lorebookId);
			if (result.isOk()) {
				await loadLorebookAssociations(); // Reload to get updated state
				toast.success('Lorebook removed from chat');
			} else {
				toast.error(`Failed to remove lorebook: ${result.error.message}`);
			}
		} catch (_error) {
			console.error('Failed to remove lorebook:', _error);
			toast.error('Failed to remove lorebook');
		}
	}

	async function toggleCharacterLorebookOverride(lorebookId: string, currentAction?: string) {
		if (!chat?.id) return;

		try {
			// If there's already an override, remove it; otherwise, disable the character lorebook
			if (currentAction) {
				const result = await _apiClient.removeCharacterLorebookOverride(chat.id, lorebookId);
				if (result.isOk()) {
					await loadLorebookAssociations();
					toast.success('Override removed');
				} else {
					toast.error(`Failed to remove override: ${result.error.message}`);
				}
			} else {
				const result = await _apiClient.setCharacterLorebookOverride(
					chat.id,
					lorebookId,
					'disable'
				);
				if (result.isOk()) {
					await loadLorebookAssociations();
					toast.success('Character lorebook disabled for this chat');
				} else {
					toast.error(`Failed to disable lorebook: ${result.error.message}`);
				}
			}
		} catch (_error) {
			console.error('Failed to toggle lorebook override:', _error);
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

	// Session narrative style functions
	// TODO: Implement GET endpoint for session narrative style
	async function _loadSessionNarrativeStyle() {
		if (!chat?.id) return;

		isLoadingSessionStyle = true;
		try {
			// The session style endpoint doesn't exist yet - for now we'll just set it to null
			// TODO: This will be implemented when we add the GET endpoint
			sessionNarrativeStyle = null;
		} catch (_error) {
			console.error('Failed to load session narrative style:', _error);
		} finally {
			isLoadingSessionStyle = false;
		}
	}

	async function updateSessionNarrativeStyle(updates: UpdateTemplatePreferenceRequest) {
		if (!chat?.id) return;

		try {
			const result = await _apiClient.updateSessionNarrativeStyle(chat.id, updates);
			if (result.isOk()) {
				sessionNarrativeStyle = result.value;
				toast.success('Session writing style updated');
			} else {
				console.error('Failed to update session narrative style:', result.error);
				toast.error('Failed to update session writing style');
			}
		} catch (_error) {
			console.error('Failed to update session narrative style:', _error);
			toast.error('Failed to update session writing style');
		}
	}

	async function clearSessionNarrativeStyle() {
		if (!chat?.id) return;

		try {
			// Clear by sending an empty object (all fields null)
			const result = await _apiClient.updateSessionNarrativeStyle(chat.id, {});
			if (result.isOk()) {
				sessionNarrativeStyle = null;
				toast.success('Session writing style cleared');
			} else {
				console.error('Failed to clear session narrative style:', result.error);
				toast.error('Failed to clear session writing style');
			}
		} catch (_error) {
			console.error('Failed to clear session narrative style:', _error);
			toast.error('Failed to clear session writing style');
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
			<ButtonComponent
				variant="ghost"
				size="sm"
				onclick={clearAllOverrides}
				class="text-muted-foreground hover:text-foreground"
			>
				Clear All
			</ButtonComponent>
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

				<!-- Prompt Template Selection -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.templates = !expandedSections.templates)}
						class="cursor-pointer {expandedSections.templates ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<CardTitle class="text-base">Prompt Style</CardTitle>
							{#if expandedSections.templates}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.templates}
						<CardContent class="space-y-3">
							<TemplateSelector
								bind:selectedTemplateId={localSettings.prompt_template_id}
								onTemplateChange={handleTemplateChange}
								currentChatMode={chat?.chat_mode || 'Character'}
								showCompatibility={false}
								disabled={isLoading}
								hideLabel={true}
							/>
						</CardContent>
					{/if}
				</Card>

				<!-- Session Writing Style Override -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.sessionStyle = !expandedSections.sessionStyle)}
						class="cursor-pointer {expandedSections.sessionStyle ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<CardTitle class="text-base">Session Writing Style</CardTitle>
								{#if hasSessionStyleOverride && !expandedSections.sessionStyle}
									<BadgeComponent variant="secondary" class="text-xs">Temporary</BadgeComponent>
								{/if}
							</div>
							{#if expandedSections.sessionStyle}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.sessionStyle}
						<CardContent class="space-y-4">
							{#if isLoadingSessionStyle}
								<div class="space-y-2">
									<Skeleton class="h-8 w-full" />
									<Skeleton class="h-8 w-full" />
								</div>
							{:else}
								<p class="text-sm text-muted-foreground">
									Temporarily override narrative preferences for this conversation only. These
									changes won't affect your character or global defaults.
								</p>

								<!-- Inline narrative style controls -->
								<div class="space-y-3 rounded-md border p-3">
									<div class="space-y-2">
										<Label class="text-xs font-medium">Tense</Label>
										<select
											class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
											value={sessionNarrativeStyle?.tense || ''}
											onchange={(e) => {
												const value = (e.target as HTMLSelectElement).value;
												updateSessionNarrativeStyle({
													tense: value as NarrativeTense | undefined
												});
											}}
										>
											<option value="">Use character/global default</option>
											<option value="past-tense">Past Tense</option>
											<option value="present-tense">Present Tense</option>
											<option value="future-tense">Future Tense</option>
										</select>
									</div>

									<div class="space-y-2">
										<Label class="text-xs font-medium">Narration</Label>
										<select
											class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
											value={sessionNarrativeStyle?.narration || ''}
											onchange={(e) => {
												const value = (e.target as HTMLSelectElement).value;
												updateSessionNarrativeStyle({
													narration: value as NarrativeNarration | undefined
												});
											}}
										>
											<option value="">Use character/global default</option>
											<option value="first-person">First Person</option>
											<option value="second-person">Second Person</option>
											<option value="third-person">Third Person</option>
										</select>
									</div>

									<div class="space-y-2">
										<Label class="text-xs font-medium">Point of View</Label>
										<select
											class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
											value={sessionNarrativeStyle?.perspective || ''}
											onchange={(e) => {
												const value = (e.target as HTMLSelectElement).value;
												updateSessionNarrativeStyle({
													perspective: value as NarrativePerspective | undefined
												});
											}}
										>
											<option value="">Use character/global default</option>
											<option value="character-pov">Character POV</option>
											<option value="omniscient">Omniscient</option>
											<option value="limited">Limited</option>
										</select>
									</div>

									<div class="space-y-2">
										<Label class="text-xs font-medium">Response Length</Label>
										<select
											class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
											value={sessionNarrativeStyle?.response_length || ''}
											onchange={(e) => {
												const value = (e.target as HTMLSelectElement).value;
												updateSessionNarrativeStyle({
													response_length: value as ResponseLength | undefined
												});
											}}
										>
											<option value="">Use character/global default</option>
											<option value="concise">Concise</option>
											<option value="balanced">Balanced</option>
											<option value="detailed">Detailed</option>
											<option value="flexible">Flexible</option>
										</select>
									</div>
								</div>

								{#if hasSessionStyleOverride}
									<ButtonComponent
										variant="destructive"
										size="sm"
										onclick={clearSessionNarrativeStyle}
										class="w-full"
									>
										Clear Session Overrides
									</ButtonComponent>
								{/if}
							{/if}
						</CardContent>
					{/if}
				</Card>

				<!-- Chronicle Association -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.chronicles = !expandedSections.chronicles)}
						class="cursor-pointer {expandedSections.chronicles ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<CardTitle class="text-base">
								Chronicle
								{#if currentChronicleId}
									<BadgeComponent variant="secondary" class="ml-2">Linked</BadgeComponent>
								{/if}
							</CardTitle>
							{#if expandedSections.chronicles}
								<ChevronUp />
							{:else}
								<ChevronDown />
							{/if}
						</div>
					</CardHeader>
					{#if expandedSections.chronicles}
						<CardContent class="space-y-3">
							{#if isLoadingChronicles}
								<div class="space-y-2">
									<Skeleton class="h-8 w-full" />
									<Skeleton class="h-4 w-3/4" />
								</div>
							{:else}
								<div class="space-y-3">
									{#if !showChronicleCreationForm}
										<div class="space-y-2">
											<div class="flex items-center justify-between">
												<Label for="chronicle-select">Link to Chronicle</Label>
												<ButtonComponent
													variant="outline"
													size="sm"
													onclick={() => (showChronicleCreationForm = true)}
													disabled={isCreatingChronicle}
												>
													Create New
												</ButtonComponent>
											</div>
											<select
												id="chronicle-select"
												class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
												bind:value={currentChronicleId}
												onchange={(e) => updateChronicleAssociation(e.currentTarget.value || null)}
											>
												<option value={null}>No chronicle (unlinked)</option>
												{#each availableChronicles as chronicle}
													<option value={chronicle.id}>{chronicle.name}</option>
												{/each}
											</select>
											<p class="text-xs text-muted-foreground">
												Link this chat to a chronicle to organize related conversations and make
												them available for RAG queries.
											</p>
										</div>
									{:else}
										<!-- Chronicle Creation Form -->
										<div class="space-y-3 rounded-md border p-3">
											<div class="flex items-center justify-between">
												<Label class="text-sm font-medium">Create New Chronicle</Label>
												<ButtonComponent
													variant="ghost"
													size="sm"
													onclick={cancelChronicleCreation}
													disabled={isCreatingChronicle}
												>
													Cancel
												</ButtonComponent>
											</div>
											<div class="space-y-2">
												<Label for="chronicle-name">Name</Label>
												<Input
													id="chronicle-name"
													bind:value={newChronicleName}
													placeholder="Enter chronicle name..."
													disabled={isCreatingChronicle}
												/>
											</div>
											<div class="space-y-2">
												<Label for="chronicle-description">Description (optional)</Label>
												<TextareaComponent
													id="chronicle-description"
													bind:value={newChronicleDescription}
													placeholder="Describe what this chronicle is about..."
													disabled={isCreatingChronicle}
													rows={3}
												/>
											</div>
											<ButtonComponent
												onclick={createChronicle}
												disabled={isCreatingChronicle || !newChronicleName.trim()}
												class="w-full"
											>
												{isCreatingChronicle ? 'Creating...' : 'Create Chronicle'}
											</ButtonComponent>
										</div>
									{/if}

									{#if currentChronicleId && !showChronicleCreationForm}
										{@const linkedChronicle = availableChronicles.find(
											(c) => c.id === currentChronicleId
										)}
										{#if linkedChronicle}
											<div class="rounded-md bg-muted p-3">
												<div class="text-sm font-medium">{linkedChronicle.name}</div>
												{#if linkedChronicle.description}
													<div class="mt-1 text-xs text-muted-foreground">
														{linkedChronicle.description}
													</div>
												{/if}
												<div class="mt-2 text-xs text-muted-foreground">
													{linkedChronicle.event_count} events • {linkedChronicle.chat_count}
													chats
												</div>
											</div>
										{/if}
									{/if}
								</div>
							{/if}
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
													<BadgeComponent
														variant={assoc.source === 'Chat' ? 'default' : 'secondary'}
														class="text-xs"
													>
														{assoc.source === 'Chat' ? 'Chat' : 'Character'}
													</BadgeComponent>
													{#if assoc.is_overridden}
														<BadgeComponent variant="outline" class="text-xs">
															{assoc.override_action === 'disable' ? 'Disabled' : 'Enabled'}
														</BadgeComponent>
													{/if}
												</div>
											</div>

											<div class="flex items-center gap-2" data-testid="lorebook-card">
												{#if assoc.source === 'Chat'}
													<ButtonComponent
														variant="destructive"
														size="sm"
														onclick={() => removeLorebookAssociation(assoc.lorebook_id)}
														class="text-xs"
													>
														Remove
													</ButtonComponent>
												{:else if assoc.source === 'Character'}
													<!-- Character lorebook -->
													<ButtonComponent
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
													</ButtonComponent>
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

							<ButtonComponent
								variant="outline"
								onclick={() => (isLorebookDialogOpen = true)}
								class="w-full"
							>
								Manage Lorebooks
							</ButtonComponent>
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

							<div class="space-y-2">
								<Label for="agent-mode">Context Enhancement Agent</Label>
								<select
									id="agent-mode"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={localSettings.agent_mode}
								>
									<option value="disabled">Disabled</option>
									<option value="pre_processing">Pre-process (before AI response)</option>
									<option value="post_processing">Post-process (after AI response)</option>
								</select>
								<p class="text-xs text-muted-foreground">
									{#if localSettings.agent_mode === 'pre_processing'}
										Agent searches for context before generating response (slight delay)
									{:else if localSettings.agent_mode === 'post_processing'}
										Agent enriches context after response (no delay)
									{:else}
										No automatic context enrichment
									{/if}
								</p>
							</div>

							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<Label for="temperature">Temperature</Label>
										{#if localSettings.temperature !== 1.0}
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('temperature')}
											>
												Clear
											</ButtonComponent>
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
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('max_output_tokens')}
											>
												Clear
											</ButtonComponent>
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
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('top_p')}
											>
												Clear
											</ButtonComponent>
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
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('top_k')}
											>
												Clear
											</ButtonComponent>
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
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('frequency_penalty')}
											>
												Clear
											</ButtonComponent>
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
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('presence_penalty')}
											>
												Clear
											</ButtonComponent>
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
										<ButtonComponent
											variant="ghost"
											size="sm"
											onclick={() => clearOverride('seed')}
										>
											Clear
										</ButtonComponent>
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
							{#if compact}
								<ContextConfiguratorCompact
									bind:total_token_limit={localSettings.context_total_token_limit}
									bind:recent_history_budget={localSettings.context_recent_history_budget}
									bind:rag_budget={localSettings.context_rag_budget}
									bind:rag_chronicles_limit={localSettings.rag_chronicles_limit}
									bind:rag_lorebooks_limit={localSettings.rag_lorebooks_limit}
									bind:rag_older_chat_limit={localSettings.rag_older_chat_limit}
									title="Context Override"
									description="Override default context allocation for this chat."
								/>
							{:else}
								<ContextConfigurator
									bind:total_token_limit={localSettings.context_total_token_limit}
									bind:recent_history_budget={localSettings.context_recent_history_budget}
									bind:rag_budget={localSettings.context_rag_budget}
									bind:rag_chronicles_limit={localSettings.rag_chronicles_limit}
									bind:rag_lorebooks_limit={localSettings.rag_lorebooks_limit}
									bind:rag_older_chat_limit={localSettings.rag_older_chat_limit}
									title="Context Override"
									description="Override default context allocation for this chat."
								/>
							{/if}

							<!-- Gemini-specific Options -->
							<div class="grid grid-cols-2 gap-3">
								<div class="space-y-2">
									<div class="flex items-center justify-between">
										<Label for="thinking-budget">Thinking Budget</Label>
										{#if localSettings.gemini_thinking_budget !== null}
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('gemini_thinking_budget')}
											>
												Clear
											</ButtonComponent>
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
										<Label for="thinking-level">Thinking Level</Label>
										{#if localSettings.gemini_thinking_level !== null}
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('gemini_thinking_level')}
											>
												Clear
											</ButtonComponent>
										{/if}
									</div>
									<select
										id="thinking-level"
										class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
										bind:value={localSettings.gemini_thinking_level}
									>
										<option value={null}>Default</option>
										<option value="Low">Low</option>
										<option value="Medium">Medium</option>
										<option value="High">High</option>
									</select>
								</div>
								<div class="col-span-2 space-y-2">
									<div class="flex items-center justify-between">
										<Label for="code-execution">Code Execution</Label>
										{#if localSettings.gemini_enable_code_execution !== false}
											<ButtonComponent
												variant="ghost"
												size="sm"
												onclick={() => clearOverride('gemini_enable_code_execution')}
											>
												Clear
											</ButtonComponent>
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

							<!-- Streaming Animation Speed -->
							<div class="space-y-2">
								<div class="flex items-center justify-between">
									<Label for="typing-speed">Typing Animation Speed</Label>
									<span class="text-xs text-muted-foreground">{typingSpeed}ms</span>
								</div>
								<input
									id="typing-speed"
									type="range"
									min="1"
									max="100"
									step="1"
									bind:value={typingSpeed}
									onchange={() => saveTypingSpeed()}
									class="h-2 w-full cursor-pointer appearance-none rounded-lg bg-muted accent-primary"
								/>
								<p class="text-xs text-muted-foreground">
									Lower = faster (1ms), Higher = slower (100ms). Default: 30ms
								</p>
							</div>
						</CardContent>
					{/if}
				</Card>

				<!-- Game Master Mode (Expandable) -->
				<Card>
					<CardHeader
						onclick={() => (expandedSections.gamemaster = !expandedSections.gamemaster)}
						class="cursor-pointer {expandedSections.gamemaster ? '' : 'pb-6'}"
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<CardTitle class="text-lg">Game Master Mode</CardTitle>
								{#if localSettings.game_master_mode_enabled}
									<BadgeComponent variant="default" class="bg-purple-600 hover:bg-purple-700"
										>Active</BadgeComponent
									>
								{/if}
							</div>
							<ButtonComponent variant="ghost" size="sm" class="pointer-events-none">
								{#if expandedSections.gamemaster}
									<ChevronUp />
								{:else}
									<ChevronDown />
								{/if}
							</ButtonComponent>
						</div>
					</CardHeader>
					{#if expandedSections.gamemaster}
						<CardContent class="space-y-4">
							<div class="flex items-center justify-between space-x-2">
								<div class="space-y-0.5">
									<Label for="gm-mode">Enable Game Master</Label>
									<p class="text-xs text-muted-foreground">Tracks inventory, quests, and vitals.</p>
								</div>
								<div class="flex items-center gap-2">
									{#if localSettings.game_master_mode_enabled !== false}
										<ButtonComponent
											variant="ghost"
											size="icon"
											class="h-6 w-6 text-muted-foreground hover:text-foreground"
											onclick={() => clearOverride('game_master_mode_enabled')}
											title="Reset to default"
										>
											<span class="sr-only">Reset</span>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												width="12"
												height="12"
												viewBox="0 0 24 24"
												fill="none"
												stroke="currentColor"
												stroke-width="2"
												stroke-linecap="round"
												stroke-linejoin="round"
											>
												<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74-2.74L3 12" />
											</svg>
										</ButtonComponent>
									{/if}
									<CheckboxComponent
										id="gm-mode"
										checked={localSettings.game_master_mode_enabled}
										on:change={(e) => {
											localSettings.game_master_mode_enabled = e.detail;
											saveSettings();
										}}
									/>
								</div>
							</div>
						</CardContent>
					{/if}
				</Card>
			{/if}
		</div>
	</div>

	<!-- Footer -->
	<div class="border-t p-4">
		<ButtonComponent onclick={saveSettings} disabled={isLoading} class="w-full">
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
		</ButtonComponent>
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
