<script lang="ts">
	import { fly } from 'svelte/transition';
	import { quintOut } from 'svelte/easing';
	import { Button } from '../ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { Separator } from '../ui/separator';
	import { Checkbox } from '../ui/checkbox';
	import { toast } from 'svelte-sonner';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { chatModels, DEFAULT_CHAT_MODEL } from '$lib/ai/models';
	import ContextConfigurator from '$lib/components/shared/ContextConfigurator.svelte';
	import ChevronDown from '../icons/chevron-down.svelte';
	import ChevronUp from '../icons/chevron-up.svelte';
	import { apiClient } from '$lib/api';
	import type { UserSettingsResponse, UpdateUserSettingsRequest } from '$lib/types';

	const settingsStore = SettingsStore.fromContext();

	// Tab state
	let activeTab = $state('generation');

	// Consolidated settings state
	let isLoading = $state(false);
	let settings = $state({
		// Model & Basic Generation
		model_name: 'gemini-2.5-flash', // System default from backend config
		temperature: 1.0,
		max_output_tokens: 1000,
		top_p: 0.95 as number | null,
		top_k: 0,

		// Advanced Generation
		frequency_penalty: 0.0,
		presence_penalty: 0.0,
		seed: null as number | null,

		// Gemini-Specific
		gemini_thinking_budget: null as number | null,

		// Context Management
		context_total_token_limit: 200000,
		context_recent_history_budget: 150000,
		context_rag_budget: 50000, // Updated to match backend default

		// Application Preferences
		auto_save_chats: true,
		theme: 'system',
		notifications_enabled: true,
		typing_speed: 30 // milliseconds between characters for streaming text
	});

	// Expandable sections state
	let expandedSections = $state({
		advanced: false,
		gemini: false
	});

	function closeSettings() {
		settingsStore.hide();
	}

	async function saveSettings() {
		isLoading = true;
		try {
			const updateRequest: UpdateUserSettingsRequest = {
				// Generation Settings
				default_model_name: settings.model_name || null,
				default_temperature: settings.temperature || null,
				default_max_output_tokens: settings.max_output_tokens || null,
				default_frequency_penalty: settings.frequency_penalty || null,
				default_presence_penalty: settings.presence_penalty || null,
				default_top_p: settings.top_p ?? null,
				default_top_k: settings.top_k ?? null,
				default_seed: settings.seed ?? null,

				// Gemini-Specific Settings
				default_gemini_thinking_budget: settings.gemini_thinking_budget || null,
				default_gemini_enable_code_execution: null, // Not exposed in this UI yet

				// Context Management Settings
				default_context_total_token_limit: settings.context_total_token_limit || null,
				default_context_recent_history_budget: settings.context_recent_history_budget || null,
				default_context_rag_budget: settings.context_rag_budget || null,

				// Application Preferences
				auto_save_chats: settings.auto_save_chats,
				theme: settings.theme || null,
				notifications_enabled: settings.notifications_enabled,
				typing_speed: settings.typing_speed
			};

			const result = await apiClient.updateUserSettings(updateRequest);
			if (result.isOk()) {
				toast.success('Settings saved successfully');
				// Reload to show the updated settings
				await loadSettings();
			} else {
				console.error('Failed to save settings:', result.error);
				toast.error(`Failed to save settings: ${result.error.message}`);
			}
		} catch (error) {
			console.error('Failed to save settings:', error);
			toast.error('Failed to save settings');
		} finally {
			isLoading = false;
		}
	}

	async function loadSettings() {
		isLoading = true;
		try {
			const userSettingsResult = await apiClient.getUserSettings();
			if (userSettingsResult.isOk()) {
				const userSettings = userSettingsResult.value;
				console.log('Loaded user settings:', userSettings);

				// Map the user settings to our local state
				settings = {
					// Model & Basic Generation
					model_name: userSettings.default_model_name || 'gemini-2.5-flash',
					temperature: parseFloat(String(userSettings.default_temperature ?? 1.0)),
					max_output_tokens: userSettings.default_max_output_tokens || 1000,
					top_p: parseFloat(parseFloat(String(userSettings.default_top_p ?? 0.95)).toFixed(2)),
					top_k: userSettings.default_top_k ?? 0,

					// Advanced Generation
					frequency_penalty: userSettings.default_frequency_penalty || 0.0,
					presence_penalty: userSettings.default_presence_penalty || 0.0,
					seed: userSettings.default_seed || null,

					// Gemini-Specific
					gemini_thinking_budget: userSettings.default_gemini_thinking_budget || null,

					// Context Management
					context_total_token_limit: userSettings.default_context_total_token_limit || 200000,
					context_recent_history_budget:
						userSettings.default_context_recent_history_budget || 150000,
					context_rag_budget: userSettings.default_context_rag_budget || 50000,

					// Application Preferences
					auto_save_chats: userSettings.auto_save_chats ?? true,
					theme: userSettings.theme || 'system',
					notifications_enabled: userSettings.notifications_enabled ?? true,
					typing_speed: userSettings.typing_speed ?? 30
				};
			} else {
				console.error('Failed to load user settings:', userSettingsResult.error);
				toast.error('Failed to load settings');
			}
		} catch (error) {
			console.error('Failed to load settings:', error);
			toast.error('Failed to load settings');
		} finally {
			isLoading = false;
		}
	}

	function resetToDefaults() {
		settings = {
			model_name: 'gemini-2.5-flash', // System default from backend config
			temperature: 1.0,
			max_output_tokens: 1000,
			top_p: 0.95,
			top_k: 0,
			frequency_penalty: 0.0,
			presence_penalty: 0.0,
			seed: null,
			gemini_thinking_budget: null,
			context_total_token_limit: 200000,
			context_recent_history_budget: 150000,
			context_rag_budget: 50000, // Updated to match backend default
			auto_save_chats: true,
			theme: 'system',
			notifications_enabled: true,
			typing_speed: 30
		};
		toast.info('Settings reset to system defaults');
	}

	// Load settings when component mounts
	$effect(() => {
		loadSettings();
	});

	const tabs = [
		{ id: 'generation', label: 'Generation', icon: '🎛️' },
		{ id: 'context', label: 'Context', icon: '🧠' },
		{ id: 'application', label: 'Application', icon: '⚙️' }
	];
</script>

<div class="mx-auto max-w-4xl md:mt-8">
	<div class="flex flex-col gap-6">
		<!-- Header -->
		<div class="flex items-center gap-4">
			<div class="flex-1">
				<h1 class="text-2xl font-bold">Settings</h1>
				<p class="text-muted-foreground">Configure default values and application preferences</p>
			</div>
			<Button variant="outline" onclick={resetToDefaults}>Reset to Defaults</Button>
			<Button variant="ghost" onclick={closeSettings}>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					width="16"
					height="16"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
				>
					<path d="m18 6 6 6-6 6" />
					<path d="M6 12h12" />
				</svg>
				Close
			</Button>
		</div>

		{#if isLoading}
			<div class="py-8 text-center">
				<div class="inline-block h-8 w-8 animate-spin rounded-full border-b-2 border-primary"></div>
				<p class="mt-2 text-muted-foreground">Loading settings...</p>
			</div>
		{:else}
			<!-- Tabs -->
			<div class="border-b">
				<nav class="flex space-x-8">
					{#each tabs as tab}
						<button
							onclick={() => (activeTab = tab.id)}
							class="flex items-center gap-2 border-b-2 px-1 py-2 text-sm font-medium transition-colors {activeTab ===
							tab.id
								? 'border-primary text-primary'
								: 'border-transparent text-muted-foreground hover:border-border hover:text-foreground'}"
						>
							<span>{tab.icon}</span>
							{tab.label}
						</button>
					{/each}
				</nav>
			</div>

			<div class="space-y-6">
				<!-- Generation Tab -->
				{#if activeTab === 'generation'}
					<!-- Model Selection -->
					<Card>
						<CardHeader>
							<CardTitle class="text-lg">Default Model</CardTitle>
						</CardHeader>
						<CardContent>
							<div class="space-y-2">
								<Label for="model">Language Model</Label>
								<select
									id="model"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={settings.model_name}
								>
									{#each chatModels as model}
										<option value={model.id}>{model.name}</option>
									{/each}
								</select>
								<p class="text-xs text-muted-foreground">Default model for new chats</p>
							</div>
						</CardContent>
					</Card>

					<!-- Core Generation Parameters -->
					<Card>
						<CardHeader>
							<CardTitle class="text-lg">Core Generation Parameters</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<Label for="temperature">Temperature</Label>
									<Input
										id="temperature"
										type="number"
										min="0"
										max="2"
										step="0.1"
										bind:value={settings.temperature}
									/>
									<p class="text-xs text-muted-foreground">Controls randomness (0-2)</p>
								</div>
								<div class="space-y-2">
									<Label for="max-tokens">Max Output Tokens</Label>
									<Input
										id="max-tokens"
										type="number"
										min="1"
										max="8192"
										bind:value={settings.max_output_tokens}
									/>
									<p class="text-xs text-muted-foreground">Maximum response length</p>
								</div>
							</div>

							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<Label for="top-p">Top P (Nucleus Sampling)</Label>
									<Input
										id="top-p"
										type="number"
										min="0"
										max="1"
										step="0.01"
										bind:value={settings.top_p}
										onblur={() => {
											if (settings.top_p !== null) {
												settings.top_p = parseFloat(settings.top_p.toFixed(2));
											}
										}}
									/>
									<p class="text-xs text-muted-foreground">Probability cutoff (0-1)</p>
								</div>
								<div class="space-y-2">
									<Label for="top-k">Top K</Label>
									<Input
										id="top-k"
										type="number"
										min="0"
										max="100"
										step="1"
										bind:value={settings.top_k}
									/>
									<p class="text-xs text-muted-foreground">Number of top tokens (0-100)</p>
								</div>
							</div>
						</CardContent>
					</Card>

					<!-- Advanced Generation (Expandable) -->
					<Card>
						<CardHeader>
							<div class="flex items-center justify-between">
								<CardTitle class="text-lg">Advanced Generation</CardTitle>
								<Button
									variant="ghost"
									size="sm"
									onclick={() => (expandedSections.advanced = !expandedSections.advanced)}
								>
									{#if expandedSections.advanced}
										<ChevronUp />
									{:else}
										<ChevronDown />
									{/if}
								</Button>
							</div>
						</CardHeader>
						{#if expandedSections.advanced}
							<CardContent class="space-y-4">
								<div class="grid grid-cols-2 gap-4">
									<div class="space-y-2">
										<Label for="freq-penalty">Frequency Penalty</Label>
										<Input
											id="freq-penalty"
											type="number"
											min="-2"
											max="2"
											step="0.1"
											bind:value={settings.frequency_penalty}
										/>
										<p class="text-xs text-muted-foreground">Reduce repetition (-2 to 2)</p>
									</div>
									<div class="space-y-2">
										<Label for="presence-penalty">Presence Penalty</Label>
										<Input
											id="presence-penalty"
											type="number"
											min="-2"
											max="2"
											step="0.1"
											bind:value={settings.presence_penalty}
										/>
										<p class="text-xs text-muted-foreground">Encourage new topics (-2 to 2)</p>
									</div>
								</div>

								<div class="space-y-2">
									<Label for="seed">Default Seed (optional)</Label>
									<Input
										id="seed"
										type="number"
										placeholder="Leave empty for random"
										bind:value={settings.seed}
									/>
									<p class="text-xs text-muted-foreground">For reproducible generation</p>
								</div>
							</CardContent>
						{/if}
					</Card>

					<!-- Gemini-Specific (Expandable) -->
					<Card>
						<CardHeader>
							<div class="flex items-center justify-between">
								<CardTitle class="text-lg">Gemini-Specific Options</CardTitle>
								<Button
									variant="ghost"
									size="sm"
									onclick={() => (expandedSections.gemini = !expandedSections.gemini)}
								>
									{#if expandedSections.gemini}
										<ChevronUp />
									{:else}
										<ChevronDown />
									{/if}
								</Button>
							</div>
						</CardHeader>
						{#if expandedSections.gemini}
							<CardContent class="space-y-4">
								<div class="space-y-2">
									<Label for="thinking-budget">Thinking Budget (Reasoning Tokens)</Label>
									<Input
										id="thinking-budget"
										type="number"
										min="0"
										placeholder="Default (1000-24000 based on model)"
										bind:value={settings.gemini_thinking_budget}
									/>
									<p class="text-xs text-muted-foreground">
										Token budget for reasoning. Common values: 1000 (low), 8000 (medium), 24000
										(high)
									</p>
								</div>
							</CardContent>
						{/if}
					</Card>
				{/if}

				<!-- Context Tab -->
				{#if activeTab === 'context'}
					<ContextConfigurator
						bind:total_token_limit={settings.context_total_token_limit}
						bind:recent_history_budget={settings.context_recent_history_budget}
						bind:rag_budget={settings.context_rag_budget}
						title="Default Context Window Management"
						description="Set default token allocation for new chats."
					/>
				{/if}

				<!-- Application Tab -->
				{#if activeTab === 'application'}
					<Card>
						<CardHeader>
							<CardTitle class="text-lg">Appearance</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="space-y-2">
								<Label for="theme">Theme</Label>
								<select
									id="theme"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={settings.theme}
								>
									<option value="system">System Default</option>
									<option value="light">Light</option>
									<option value="dark">Dark</option>
								</select>
							</div>
						</CardContent>
					</Card>

					<Card>
						<CardHeader>
							<CardTitle class="text-lg">Behavior</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="flex items-center space-x-2">
								<Checkbox id="auto-save" bind:checked={settings.auto_save_chats} />
								<Label for="auto-save">Auto-save chats</Label>
							</div>

							<div class="flex items-center space-x-2">
								<Checkbox id="notifications" bind:checked={settings.notifications_enabled} />
								<Label for="notifications">Enable notifications</Label>
							</div>

							<div class="space-y-2">
								<Label for="typing-speed">Text Streaming Speed</Label>
								<Input
									id="typing-speed"
									type="number"
									min="1"
									max="200"
									step="1"
									bind:value={settings.typing_speed}
								/>
								<p class="text-xs text-muted-foreground">
									Milliseconds between characters (lower = faster). Common values: 10 (very fast),
									30 (default), 50 (slow)
								</p>
							</div>
						</CardContent>
					</Card>
				{/if}

				<!-- Save Button -->
				<div class="flex justify-end gap-4 border-t pt-6">
					<Button variant="outline" onclick={closeSettings}>Cancel</Button>
					<Button onclick={saveSettings} disabled={isLoading}>
						{#if isLoading}
							<svg
								class="-ml-1 mr-2 h-4 w-4 animate-spin"
								xmlns="http://www.w3.org/2000/svg"
								fill="none"
								viewBox="0 0 24 24"
							>
								<circle
									class="opacity-25"
									cx="12"
									cy="12"
									r="10"
									stroke="currentColor"
									stroke-width="4"
								></circle>
								<path
									class="opacity-75"
									fill="currentColor"
									d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
								></path>
							</svg>
							Saving...
						{:else}
							Save Settings
						{/if}
					</Button>
				</div>
			</div>
		{/if}
	</div>
</div>
