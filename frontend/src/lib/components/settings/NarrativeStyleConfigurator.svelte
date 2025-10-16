<script lang="ts">
	import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
	import { Label } from '../ui/label';
	import { Button } from '../ui/button';
	import { RadioGroup, RadioGroupItem } from '../ui/radio-group';
	import { Checkbox } from '../ui/checkbox';
	import ChevronDown from '../icons/chevron-down.svelte';
	import ChevronUp from '../icons/chevron-up.svelte';
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api';
	import type {
		TemplatePreferenceResponse,
		UpdateTemplatePreferenceRequest,
		NarrativeTense,
		NarrativeNarration,
		NarrativePerspective,
		ResponseLength
	} from '$lib/types';

	// State management
	let isLoading = $state(false);
	let preferences = $state<TemplatePreferenceResponse | null>(null);
	let expandedSections = $state({
		narrative: true,
		response: true,
		advanced: false
	});

	// Debounced save timeout
	let saveTimeout: ReturnType<typeof setTimeout> | null = null;

	// Load global template preferences on mount
	async function loadPreferences() {
		isLoading = true;
		try {
			const result = await apiClient.getTemplatePreferences(); // No characterId = global
			if (result.isOk()) {
				preferences = result.value;
			} else {
				console.error('Failed to load template preferences:', result.error);
				toast.error(`Failed to load preferences: ${result.error.message}`);
			}
		} catch (error) {
			console.error('Failed to load template preferences:', error);
			toast.error('Failed to load preferences');
		} finally {
			isLoading = false;
		}
	}

	// Update preferences with debouncing
	async function updatePreference(updates: UpdateTemplatePreferenceRequest) {
		if (saveTimeout) clearTimeout(saveTimeout);

		saveTimeout = setTimeout(async () => {
			try {
				const result = await apiClient.updateTemplatePreferences(undefined, updates);
				if (result.isOk()) {
					preferences = result.value;
					toast.success('Preferences updated');
				} else {
					console.error('Failed to update preferences:', result.error);
					toast.error(`Failed to update: ${result.error.message}`);
				}
			} catch (error) {
				console.error('Failed to update preferences:', error);
				toast.error('Failed to update preferences');
			}
		}, 500); // 500ms debounce
	}

	// Reset to defaults
	async function resetToDefaults() {
		try {
			const result = await apiClient.deleteTemplatePreferences();
			if (result.isOk()) {
				await loadPreferences(); // Reload to get new defaults
				toast.info('Reset to system defaults');
			} else {
				console.error('Failed to reset preferences:', result.error);
				toast.error(`Failed to reset: ${result.error.message}`);
			}
		} catch (error) {
			console.error('Failed to reset preferences:', error);
			toast.error('Failed to reset preferences');
		}
	}

	// Load preferences on mount
	$effect(() => {
		loadPreferences();
	});

	// Helper function to get display text for options
	function formatOptionLabel(value: string): string {
		return value
			.split('-')
			.map((word) => word.charAt(0).toUpperCase() + word.slice(1))
			.join(' ');
	}
</script>

{#if isLoading}
	<div class="py-8 text-center">
		<div class="inline-block h-8 w-8 animate-spin rounded-full border-b-2 border-primary"></div>
		<p class="mt-2 text-muted-foreground">Loading writing style preferences...</p>
	</div>
{:else if preferences}
	<div class="space-y-6">
		<!-- Header with Reset Button -->
		<div class="flex items-center justify-between">
			<div>
				<h2 class="text-xl font-semibold">Writing Style Preferences</h2>
				<p class="text-sm text-muted-foreground">
					Customize how the AI generates narrative responses
				</p>
			</div>
			<Button variant="outline" onclick={resetToDefaults}>Reset to Defaults</Button>
		</div>

		<!-- Narrative Voice Section -->
		<Card>
			<CardHeader
				onclick={() => (expandedSections.narrative = !expandedSections.narrative)}
				class="cursor-pointer {expandedSections.narrative ? '' : 'pb-6'}"
			>
				<div class="flex items-center justify-between">
					<CardTitle class="text-base">Narrative Voice</CardTitle>
					{#if expandedSections.narrative}
						<ChevronUp />
					{:else}
						<ChevronDown />
					{/if}
				</div>
			</CardHeader>
			{#if expandedSections.narrative}
				<CardContent class="space-y-6">
					<!-- Tense -->
					<div class="space-y-3">
						<Label class="text-sm font-medium">Tense</Label>
						<RadioGroup
							value={preferences.tense}
							onValueChange={(value) => updatePreference({ tense: value as NarrativeTense })}
						>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="past-tense" id="tense-past" />
								<Label for="tense-past" class="font-normal">Past Tense</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="present-tense" id="tense-present" />
								<Label for="tense-present" class="font-normal">Present Tense</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="future-tense" id="tense-future" />
								<Label for="tense-future" class="font-normal">Future Tense</Label>
							</div>
						</RadioGroup>
						<p class="text-xs text-muted-foreground">
							Controls the time frame of the narrative (e.g., "walked" vs "walks" vs "will walk")
						</p>
					</div>

					<!-- Narration -->
					<div class="space-y-3">
						<Label class="text-sm font-medium">Narration</Label>
						<RadioGroup
							value={preferences.narration}
							onValueChange={(value) =>
								updatePreference({ narration: value as NarrativeNarration })}
						>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="first-person" id="narration-first" />
								<Label for="narration-first" class="font-normal">First Person</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="second-person" id="narration-second" />
								<Label for="narration-second" class="font-normal">Second Person</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="third-person" id="narration-third" />
								<Label for="narration-third" class="font-normal">Third Person</Label>
							</div>
						</RadioGroup>
						<p class="text-xs text-muted-foreground">
							Sets the narrative perspective (e.g., "I" vs "you" vs "they")
						</p>
					</div>

					<!-- Perspective -->
					<div class="space-y-3">
						<Label class="text-sm font-medium">Point of View</Label>
						<RadioGroup
							value={preferences.perspective}
							onValueChange={(value) =>
								updatePreference({ perspective: value as NarrativePerspective })}
						>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="character-pov" id="perspective-character" />
								<Label for="perspective-character" class="font-normal">Character POV</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="omniscient" id="perspective-omniscient" />
								<Label for="perspective-omniscient" class="font-normal">Omniscient</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="limited" id="perspective-limited" />
								<Label for="perspective-limited" class="font-normal">Limited</Label>
							</div>
						</RadioGroup>
						<p class="text-xs text-muted-foreground">
							Determines narrative insight (character's thoughts only vs all-knowing vs restricted
							view)
						</p>
					</div>
				</CardContent>
			{/if}
		</Card>

		<!-- Response Style Section -->
		<Card>
			<CardHeader
				onclick={() => (expandedSections.response = !expandedSections.response)}
				class="cursor-pointer {expandedSections.response ? '' : 'pb-6'}"
			>
				<div class="flex items-center justify-between">
					<CardTitle class="text-base">Response Style</CardTitle>
					{#if expandedSections.response}
						<ChevronUp />
					{:else}
						<ChevronDown />
					{/if}
				</div>
			</CardHeader>
			{#if expandedSections.response}
				<CardContent class="space-y-6">
					<!-- Length -->
					<div class="space-y-3">
						<Label class="text-sm font-medium">Response Length</Label>
						<RadioGroup
							value={preferences.length}
							onValueChange={(value) => updatePreference({ length: value as ResponseLength })}
						>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="concise" id="length-concise" />
								<Label for="length-concise" class="font-normal">Concise</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="balanced" id="length-balanced" />
								<Label for="length-balanced" class="font-normal">Balanced</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="detailed" id="length-detailed" />
								<Label for="length-detailed" class="font-normal">Detailed</Label>
							</div>
							<div class="flex items-center space-x-2">
								<RadioGroupItem value="flexible" id="length-flexible" />
								<Label for="length-flexible" class="font-normal">Flexible</Label>
							</div>
						</RadioGroup>
						<p class="text-xs text-muted-foreground">
							Sets the target response length (concise: brief, balanced: moderate, detailed:
							verbose, flexible: adapts to context)
						</p>
					</div>
				</CardContent>
			{/if}
		</Card>

		<!-- Advanced Features Section -->
		<Card>
			<CardHeader
				onclick={() => (expandedSections.advanced = !expandedSections.advanced)}
				class="cursor-pointer {expandedSections.advanced ? '' : 'pb-6'}"
			>
				<div class="flex items-center justify-between">
					<CardTitle class="text-base">Advanced Features</CardTitle>
					{#if expandedSections.advanced}
						<ChevronUp />
					{:else}
						<ChevronDown />
					{/if}
				</div>
			</CardHeader>
			{#if expandedSections.advanced}
				<CardContent class="space-y-4">
					<!-- Info Box -->
					<div class="flex items-start space-x-3">
						<Checkbox
							id="enable-info-box"
							checked={preferences.enable_info_box}
							on:change={(event: CustomEvent<boolean>) => {
								updatePreference({ enable_info_box: event.detail });
							}}
						/>
						<div class="grid gap-1.5 leading-none">
							<Label
								for="enable-info-box"
								class="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
							>
								Enable Info Box
							</Label>
							<p class="text-sm text-muted-foreground">
								Include contextual information boxes in responses for world-building details
							</p>
						</div>
					</div>

					<!-- Stats Tracker -->
					<div class="flex items-start space-x-3">
						<Checkbox
							id="enable-stats-tracker"
							checked={preferences.enable_stats_tracker}
							on:change={(event: CustomEvent<boolean>) => {
								updatePreference({ enable_stats_tracker: event.detail });
							}}
						/>
						<div class="grid gap-1.5 leading-none">
							<Label
								for="enable-stats-tracker"
								class="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
							>
								Enable Stats Tracker
							</Label>
							<p class="text-sm text-muted-foreground">
								Track and display character stats, attributes, or game mechanics in responses
							</p>
						</div>
					</div>

					<!-- Thinking Mode -->
					<div class="flex items-start space-x-3">
						<Checkbox
							id="enable-thinking"
							checked={preferences.enable_thinking}
							on:change={(event: CustomEvent<boolean>) => {
								updatePreference({ enable_thinking: event.detail });
							}}
						/>
						<div class="grid gap-1.5 leading-none">
							<Label
								for="enable-thinking"
								class="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
							>
								Enable Thinking Mode
							</Label>
							<p class="text-sm text-muted-foreground">
								Show the AI's reasoning process and internal thoughts before the final response
							</p>
						</div>
					</div>
				</CardContent>
			{/if}
		</Card>
	</div>
{:else}
	<div class="py-8 text-center">
		<p class="text-muted-foreground">Failed to load preferences</p>
		<Button variant="outline" onclick={loadPreferences} class="mt-4">Retry</Button>
	</div>
{/if}
