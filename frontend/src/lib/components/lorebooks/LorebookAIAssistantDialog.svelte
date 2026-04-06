<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { apiClient } from '$lib/api';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Alert from '$lib/components/ui/alert';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import { AlertCircle, Loader2, Sparkles, Check, X } from 'lucide-svelte';
	import type {
		Lorebook,
		GenerateAILorebookEntriesPayload,
		GenerateAILorebookEntriesResponse,
		LorebookAnalysis
	} from '$lib/types';
	import { toast } from 'svelte-sonner';

	interface Props {
		open: boolean;
		lorebook: Lorebook;
		onEntriesGenerated?: (count: number) => void;
	}

	let { open = $bindable(), lorebook, onEntriesGenerated }: Props = $props();

	const dispatch = createEventDispatcher<{ close: void }>();

	// State
	let activeTab = $state<string>('generate');
	let isGenerating = $state(false);
	let isAnalyzing = $state(false);
	let error = $state<string | null>(null);

	// Generate tab inputs
	let generateTheme = $state('');
	let generateCount = $state(5);
	let generateContext = $state('');

	// Results
	let generateResult = $state<GenerateAILorebookEntriesResponse | null>(null);
	let analysisResult = $state<LorebookAnalysis | null>(null);

	/**
	 * Generate lorebook entries
	 */
	async function handleGenerate() {
		if (!generateTheme.trim()) {
			error = 'Please enter a theme';
			return;
		}

		if (generateCount < 1 || generateCount > 20) {
			error = 'Count must be between 1 and 20';
			return;
		}

		isGenerating = true;
		error = null;
		generateResult = null;

		const payload: GenerateAILorebookEntriesPayload = {
			theme: generateTheme,
			count: generateCount,
			context: generateContext.trim() || undefined
		};

		const result = await apiClient.generateAILorebookEntries(lorebook.id, payload);

		if (result.isOk()) {
			generateResult = result.value;
			if (generateResult.success) {
				toast.success('Entries generated', {
					description: `Successfully generated ${generateResult.entries_generated} ${generateResult.entries_generated === 1 ? 'entry' : 'entries'}`
				});
				// Notify parent component to refresh entries list
				onEntriesGenerated?.(generateResult.entries_generated);
			} else {
				error = generateResult.message || 'Generation failed';
			}
		} else {
			error = result.error.message || 'Failed to generate entries';
		}

		isGenerating = false;
	}

	/**
	 * Analyze lorebook
	 */
	async function handleAnalyze() {
		isAnalyzing = true;
		error = null;
		analysisResult = null;

		const result = await apiClient.analyzeAILorebook(lorebook.id);

		if (result.isOk()) {
			const response = result.value;
			if (response.success) {
				analysisResult = response.analysis;
				toast.success('Analysis complete', {
					description: `Analyzed ${response.entries_analyzed} ${response.entries_analyzed === 1 ? 'entry' : 'entries'}`
				});
			} else {
				error = 'Analysis failed';
			}
		} else {
			error = result.error.message || 'Failed to analyze lorebook';
		}

		isAnalyzing = false;
	}

	/**
	 * Reset state
	 */
	function handleClose() {
		open = false;
		dispatch('close');
		// Reset after dialog closes
		setTimeout(() => {
			isGenerating = false;
			isAnalyzing = false;
			error = null;
			generateTheme = '';
			generateContext = '';
			generateResult = null;
			analysisResult = null;
		}, 300);
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Portal>
		<Dialog.Overlay />
		<Dialog.Content class="flex h-[95vh] max-w-full flex-col p-4 md:h-[90vh] md:max-w-3xl md:p-6">
			<Dialog.Header class="flex-shrink-0">
				<Dialog.Title class="flex items-center gap-2">
					<Sparkles class="h-5 w-5" />
					Lorebook AI Assistant
				</Dialog.Title>
				<Dialog.Description>
					Use AI to generate, enhance, and analyze your lorebook entries
				</Dialog.Description>
			</Dialog.Header>

			<div class="-mx-2 flex-1 space-y-4 overflow-y-auto px-2 py-4">
				<!-- Workflow Tabs -->
				<Tabs.Root bind:value={activeTab} class="w-full">
					<Tabs.List class="grid w-full grid-cols-2">
						<Tabs.Trigger value="generate">Generate Entries</Tabs.Trigger>
						<Tabs.Trigger value="analyze">Analyze Lorebook</Tabs.Trigger>
					</Tabs.List>

					<!-- Generate Entries Tab -->
					<Tabs.Content value="generate" class="space-y-4">
						<div class="space-y-2">
							<Label for="generate-theme">Theme *</Label>
							<Input
								id="generate-theme"
								placeholder="e.g., medieval fantasy tavern, sci-fi space station"
								bind:value={generateTheme}
								disabled={isGenerating}
							/>
							<p class="text-xs text-muted-foreground">Enter a theme or concept for the entries</p>
						</div>

						<div class="space-y-2">
							<Label for="generate-count">Number of Entries</Label>
							<Input
								id="generate-count"
								type="number"
								min="1"
								max="20"
								bind:value={generateCount}
								disabled={isGenerating}
							/>
							<p class="text-xs text-muted-foreground">Generate 1-20 entries (costs 1 request)</p>
						</div>

						<div class="space-y-2">
							<Label for="generate-context">Additional Context (Optional)</Label>
							<Textarea
								id="generate-context"
								placeholder="Any additional information to guide generation..."
								bind:value={generateContext}
								disabled={isGenerating}
								class="min-h-[100px] resize-y"
							/>
							<p class="text-xs text-muted-foreground">
								Provide extra context about your world or specific requirements
							</p>
						</div>

						<Button
							onclick={handleGenerate}
							disabled={isGenerating || !generateTheme.trim()}
							class="w-full"
						>
							{#if isGenerating}
								<Loader2 class="mr-2 h-4 w-4 animate-spin" />
								Generating...
							{:else}
								<Sparkles class="mr-2 h-4 w-4" />
								Generate {generateCount}
								{generateCount === 1 ? 'Entry' : 'Entries'}
							{/if}
						</Button>

						<!-- Generate Result -->
						{#if generateResult}
							<div class="space-y-3 rounded-lg border p-4">
								{#if generateResult.success}
									<div class="flex items-center gap-2 text-green-600 dark:text-green-400">
										<Check class="h-5 w-5" />
										<h4 class="font-semibold">Generation Complete</h4>
									</div>
									<p class="text-sm text-muted-foreground">{generateResult.message}</p>
									<div class="space-y-2">
										<h5 class="text-sm font-medium">Generated Entries:</h5>
										<ul class="space-y-1">
											{#each generateResult.entries as entry, i (i)}
												<li class="text-sm">
													<span class="font-medium">{entry.entry_title}</span>
													{#if entry.keys_text}
														<span class="text-muted-foreground">
															({entry.keys_text})
														</span>
													{/if}
												</li>
											{/each}
										</ul>
									</div>
								{:else}
									<div class="flex items-center gap-2 text-destructive">
										<X class="h-5 w-5" />
										<h4 class="font-semibold">Generation Failed</h4>
									</div>
									<p class="text-sm text-muted-foreground">{generateResult.message}</p>
								{/if}
							</div>
						{/if}
					</Tabs.Content>

					<!-- Analyze Lorebook Tab -->
					<Tabs.Content value="analyze" class="space-y-4">
						<Alert.Root>
							<AlertCircle class="h-4 w-4" />
							<Alert.Title>Smart Analysis</Alert.Title>
							<Alert.Description>
								The AI will analyze your lorebook to identify gaps, inconsistencies, and improvement
								suggestions.
							</Alert.Description>
						</Alert.Root>

						<Button onclick={handleAnalyze} disabled={isAnalyzing} class="w-full">
							{#if isAnalyzing}
								<Loader2 class="mr-2 h-4 w-4 animate-spin" />
								Analyzing...
							{:else}
								<Sparkles class="mr-2 h-4 w-4" />
								Analyze Lorebook
							{/if}
						</Button>

						<!-- Analysis Result -->
						{#if analysisResult}
							<div class="space-y-4 rounded-lg border p-4">
								<div class="flex items-center gap-2 text-green-600 dark:text-green-400">
									<Check class="h-5 w-5" />
									<h4 class="font-semibold">Analysis Complete</h4>
								</div>

								<!-- Gaps -->
								{#if analysisResult.gaps.length > 0}
									<div class="space-y-2">
										<h5 class="text-sm font-medium">Missing Information</h5>
										<ul class="list-inside list-disc space-y-1">
											{#each analysisResult.gaps as gap, i (i)}
												<li class="text-sm text-muted-foreground">{gap}</li>
											{/each}
										</ul>
									</div>
								{/if}

								<!-- Consistency Issues -->
								{#if analysisResult.consistency_issues.length > 0}
									<div class="space-y-2">
										<h5 class="text-sm font-medium">Consistency Issues</h5>
										<ul class="list-inside list-disc space-y-1">
											{#each analysisResult.consistency_issues as issue, i (i)}
												<li class="text-sm text-muted-foreground">{issue}</li>
											{/each}
										</ul>
									</div>
								{/if}

								<!-- Improvement Suggestions -->
								{#if analysisResult.improvement_suggestions.length > 0}
									<div class="space-y-2">
										<h5 class="text-sm font-medium">Improvement Suggestions</h5>
										<ul class="list-inside list-disc space-y-1">
											{#each analysisResult.improvement_suggestions as suggestion, i (i)}
												<li class="text-sm text-muted-foreground">{suggestion}</li>
											{/each}
										</ul>
									</div>
								{/if}

								<!-- Recommended Themes -->
								{#if analysisResult.recommended_themes.length > 0}
									<div class="space-y-2">
										<h5 class="text-sm font-medium">Recommended New Entry Themes</h5>
										<ul class="list-inside list-disc space-y-1">
											{#each analysisResult.recommended_themes as theme, i (i)}
												<li class="text-sm text-muted-foreground">{theme}</li>
											{/each}
										</ul>
									</div>
								{/if}
							</div>
						{/if}
					</Tabs.Content>
				</Tabs.Root>

				<!-- Error Display -->
				{#if error}
					<Alert.Root variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<Alert.Title>Error</Alert.Title>
						<Alert.Description>
							<p>{error}</p>
						</Alert.Description>
					</Alert.Root>
				{/if}
			</div>

			<Dialog.Footer class="mt-4 flex-shrink-0">
				<Button variant="outline" onclick={handleClose} disabled={isGenerating || isAnalyzing}>
					{isGenerating || isAnalyzing ? 'Close' : 'Done'}
				</Button>
			</Dialog.Footer>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
