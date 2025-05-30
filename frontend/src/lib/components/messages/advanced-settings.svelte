<script lang="ts">
	import { scale } from 'svelte/transition';
	import { Button } from '../ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { toast } from 'svelte-sonner';
	import { SettingsStore } from '$lib/stores/settings.svelte';

	const settingsStore = SettingsStore.fromContext();

	// Advanced settings state
	let isLoading = $state(false);
	let advancedSettings = $state({
		frequency_penalty: 0.0,
		presence_penalty: 0.0,
		seed: null as number | null,
		gemini_thinking_budget: null as number | null,
		gemini_enable_code_execution: false,
		// Add other advanced settings here
		auto_save_chats: true,
		theme: 'system', // 'light', 'dark', 'system'
		notifications_enabled: true
	});

	function goBack() {
		settingsStore.setViewMode('overview');
	}

	async function saveAdvancedSettings() {
		isLoading = true;
		try {
			// TODO: Implement API call to save advanced settings
			await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
			toast.success('Advanced settings saved successfully');
		} catch (error) {
			console.error('Failed to save advanced settings:', error);
			toast.error('Failed to save advanced settings');
		} finally {
			isLoading = false;
		}
	}

	async function loadAdvancedSettings() {
		isLoading = true;
		try {
			// TODO: Implement API call to load advanced settings
			await new Promise(resolve => setTimeout(resolve, 300)); // Simulate API call
		} catch (error) {
			console.error('Failed to load advanced settings:', error);
			toast.error('Failed to load advanced settings');
		} finally {
			isLoading = false;
		}
	}

	// Load settings when component mounts
	$effect(() => {
		loadAdvancedSettings();
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
				<h1 class="text-2xl font-bold">Advanced Settings</h1>
				<p class="text-muted-foreground">Fine-tune advanced parameters and preferences</p>
			</div>
		</div>

		{#if isLoading}
			<div class="text-center py-8">
				<div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
				<p class="mt-2 text-muted-foreground">Loading advanced settings...</p>
			</div>
		{:else}
			<div class="space-y-6">
				<!-- Advanced Generation Parameters -->
				<Card>
					<CardHeader>
						<CardTitle class="text-lg">Advanced Generation Parameters</CardTitle>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="grid grid-cols-2 gap-4">
							<div class="space-y-2">
								<Label for="adv-freq-penalty">Frequency Penalty</Label>
								<Input
									id="adv-freq-penalty"
									type="number"
									min="-2"
									max="2"
									step="0.1"
									bind:value={advancedSettings.frequency_penalty}
								/>
							</div>
							<div class="space-y-2">
								<Label for="adv-presence-penalty">Presence Penalty</Label>
								<Input
									id="adv-presence-penalty"
									type="number"
									min="-2"
									max="2"
									step="0.1"
									bind:value={advancedSettings.presence_penalty}
								/>
							</div>
						</div>


						<div class="space-y-2">
							<Label for="adv-seed">Default Seed (optional)</Label>
							<Input
								id="adv-seed"
								type="number"
								placeholder="Leave empty for random"
								bind:value={advancedSettings.seed}
							/>
							<p class="text-xs text-muted-foreground">
								Set a default seed for reproducible generation across new chats
							</p>
						</div>
					</CardContent>
				</Card>

				<!-- Gemini-specific Settings -->
				<Card>
					<CardHeader>
						<CardTitle class="text-lg">Gemini-specific Defaults</CardTitle>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="grid grid-cols-2 gap-4">
							<div class="space-y-2">
								<Label for="adv-thinking-budget">Thinking Budget</Label>
								<Input
									id="adv-thinking-budget"
									type="number"
									min="0"
									placeholder="Default"
									bind:value={advancedSettings.gemini_thinking_budget}
								/>
							</div>
							<div class="space-y-2">
								<Label for="adv-code-execution">Code Execution</Label>
								<select
									id="adv-code-execution"
									class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
									bind:value={advancedSettings.gemini_enable_code_execution}
								>
									<option value={false}>Disabled</option>
									<option value={true}>Enabled</option>
								</select>
							</div>
						</div>
					</CardContent>
				</Card>

				<!-- Application Preferences -->
				<Card>
					<CardHeader>
						<CardTitle class="text-lg">Application Preferences</CardTitle>
					</CardHeader>
					<CardContent class="space-y-4">
						<div class="space-y-2">
							<Label for="adv-theme">Theme</Label>
							<select
								id="adv-theme"
								class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
								bind:value={advancedSettings.theme}
							>
								<option value="system">System Default</option>
								<option value="light">Light</option>
								<option value="dark">Dark</option>
							</select>
						</div>

						<div class="flex items-center space-x-2">
							<input
								type="checkbox"
								id="adv-auto-save"
								bind:checked={advancedSettings.auto_save_chats}
								class="rounded border border-input"
							/>
							<Label for="adv-auto-save">Auto-save chats</Label>
						</div>

						<div class="flex items-center space-x-2">
							<input
								type="checkbox"
								id="adv-notifications"
								bind:checked={advancedSettings.notifications_enabled}
								class="rounded border border-input"
							/>
							<Label for="adv-notifications">Enable notifications</Label>
						</div>
					</CardContent>
				</Card>

				<!-- Save Button -->
				<div class="flex justify-end gap-4">
					<Button variant="outline" onclick={goBack}>Cancel</Button>
					<Button onclick={saveAdvancedSettings} disabled={isLoading}>
						{#if isLoading}
							<svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
								<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
								<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
							</svg>
							Saving...
						{:else}
							Save Advanced Settings
						{/if}
					</Button>
				</div>
			</div>
		{/if}
	</div>
</div>