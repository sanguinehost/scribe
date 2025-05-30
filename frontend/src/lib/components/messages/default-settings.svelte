<script lang="ts">
	import { scale } from 'svelte/transition';
	import { Button } from '../ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { toast } from 'svelte-sonner';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { chatModels, DEFAULT_CHAT_MODEL } from '$lib/ai/models';
	import ContextConfigurator from '$lib/components/shared/ContextConfigurator.svelte';

	const settingsStore = SettingsStore.fromContext();

	// Default settings state
	let isLoading = $state(false);
	let defaultSettings = $state({
		model_name: DEFAULT_CHAT_MODEL,
		temperature: 1.0,
		max_output_tokens: 1000,
		top_p: 0.95,
		top_k: 40,
		frequency_penalty: 0.0,
		presence_penalty: 0.0,
		seed: null as number | null,
		gemini_thinking_budget: null as number | null,
		gemini_enable_code_execution: false,
		context_total_token_limit: 200000,
		context_recent_history_budget: 150000,
		context_rag_budget: 40000 // Leave 10k buffer from 200k total
	});

	function goBack() {
		settingsStore.setViewMode('overview');
	}

	async function saveDefaultSettings() {
		isLoading = true;
		try {
			// TODO: Implement API call to save default settings
			// This would be something like: PUT /api/user-settings/defaults
			await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
			toast.success('Default settings saved successfully');
		} catch (error) {
			console.error('Failed to save default settings:', error);
			toast.error('Failed to save default settings');
		} finally {
			isLoading = false;
		}
	}

	async function loadDefaultSettings() {
		isLoading = true;
		try {
			// TODO: Implement API call to load default settings
			// This would be something like: GET /api/user-settings/defaults
			await new Promise(resolve => setTimeout(resolve, 300)); // Simulate API call
			// defaultSettings = response data
		} catch (error) {
			console.error('Failed to load default settings:', error);
			toast.error('Failed to load default settings');
		} finally {
			isLoading = false;
		}
	}

	// Load settings when component mounts
	$effect(() => {
		loadDefaultSettings();
	});
</script>

<div class="mx-auto max-w-3xl md:mt-8" transition:scale={{ opacity: 0, start: 0.98 }}>
	<div class="flex flex-col gap-6">
		<!-- Header -->
		<div class="flex items-center gap-4">
			<Button variant="ghost" onclick={goBack} class="p-2">
				<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-arrow-left">
					<path d="m12 19-7-7 7-7"/>
					<path d="M19 12H5"/>
				</svg>
			</Button>
			<div>
				<h1 class="text-2xl font-bold">Default Settings</h1>
				<p class="text-muted-foreground">Set default values for new chats</p>
			</div>
		</div>

		{#if isLoading}
			<div class="text-center py-8">
				<div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
				<p class="mt-2 text-muted-foreground">Loading settings...</p>
			</div>
		{:else}
			<div class="space-y-6">
				<!-- Model Selection -->
				<Card>
					<CardHeader>
						<CardTitle class="text-lg">Default Model</CardTitle>
					</CardHeader>
					<CardContent>
						<div class="space-y-2">
							<Label for="default-model">Language Model</Label>
							<select
								id="default-model"
								class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
								bind:value={defaultSettings.model_name}
							>
								{#each chatModels as model}
									<option value={model.id}>{model.name}</option>
								{/each}
							</select>
							<p class="text-xs text-muted-foreground">
								This model will be used for all new chats unless overridden
							</p>
						</div>
					</CardContent>
				</Card>

				<!-- Generation Parameters -->
				<Card>
					<CardHeader>
						<CardTitle class="text-lg">Generation Parameters</CardTitle>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="grid grid-cols-2 gap-4">
							<div class="space-y-2">
								<Label for="default-temperature">Temperature</Label>
								<Input
									id="default-temperature"
									type="number"
									min="0"
									max="2"
									step="0.1"
									bind:value={defaultSettings.temperature}
								/>
							</div>
							<div class="space-y-2">
								<Label for="default-max-tokens">Max Tokens</Label>
								<Input
									id="default-max-tokens"
									type="number"
									min="1"
									max="8192"
									bind:value={defaultSettings.max_output_tokens}
								/>
							</div>
						</div>

						<div class="grid grid-cols-2 gap-4">
							<div class="space-y-2">
								<Label for="default-top-p">Top P</Label>
								<Input
									id="default-top-p"
									type="number"
									min="0"
									max="1"
									step="0.05"
									bind:value={defaultSettings.top_p}
								/>
							</div>
							<div class="space-y-2">
								<Label for="default-top-k">Top K</Label>
								<Input
									id="default-top-k"
									type="number"
									min="0"
									max="100"
									step="1"
									bind:value={defaultSettings.top_k}
								/>
							</div>
						</div>
					</CardContent>
				</Card>

				<!-- Context Management -->
				<ContextConfigurator
					bind:total_token_limit={defaultSettings.context_total_token_limit}
					bind:recent_history_budget={defaultSettings.context_recent_history_budget}
					bind:rag_budget={defaultSettings.context_rag_budget}
					title="Default Context Window Management"
					description="Set default token allocation for new chats."
				/>
				
				<!-- Save Button -->
				<div class="flex justify-end gap-4">
					<Button variant="outline" onclick={goBack}>Cancel</Button>
					<Button onclick={saveDefaultSettings} disabled={isLoading}>
						{#if isLoading}
							<svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
								<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
								<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
							</svg>
							Saving...
						{:else}
							Save Default Settings
						{/if}
					</Button>
				</div>
			</div>
		{/if}
	</div>
</div>