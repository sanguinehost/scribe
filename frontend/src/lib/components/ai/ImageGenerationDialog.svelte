<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { characterStore } from '$lib/stores/character.svelte';
	import { aiSettings } from '$lib/stores/ai-settings.svelte';
	import { createProvider } from '$lib/utils/ai/providers';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Alert from '$lib/components/ui/alert';
	import Button from '$lib/components/ui/button/button.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import { AlertCircle, Loader2, Sparkles, Check, X } from 'lucide-svelte';

	import { ImageGenerationAgentFactory } from '$lib/utils/agentic';
	import type { WorkflowProgress } from '$lib/utils/agentic';
	import {
		buildImageGenerationWorkflowGoal,
		buildImageGenerationWorkflowContext,
		getAvailableStyles
	} from '$lib/utils/agentic';
	import type { Asset } from '$lib/types/character';

	interface Props {
		open: boolean;
		/** Optional callback when image is added to assets */
		onImageGenerated?: (imageDataUrl: string, assetType: string) => void;
	}

	let { open = $bindable(), onImageGenerated }: Props = $props();

	const dispatch = createEventDispatcher<{ close: void; imageAdded: Asset }>();
	const { character } = $derived(characterStore);

	// Workflow state
	let isExecuting = $state(false);
	let progress = $state<WorkflowProgress | null>(null);
	let error = $state<string | null>(null);

	// Form inputs
	let userDescription = $state('');
	let userGuidance = $state('');
	let selectedStyle = $state<string>('anime');
	let selectedAssetType = $state<string>('icon');

	// Generated image
	let generatedImageUrl = $state<string | null>(null);
	let generatedAssetType = $state<string>('icon');

	// Available options
	const styles = getAvailableStyles();
	const assetTypes = [
		{ value: 'icon', label: 'Icon', description: 'Character portrait or avatar' },
		{ value: 'background', label: 'Background', description: 'Environment or setting' },
		{ value: 'emotion', label: 'Emotion', description: 'Facial expression sprite' },
		{ value: 'sprite', label: 'Sprite', description: 'Full-body character sprite' },
		{ value: 'other', label: 'Other', description: 'Custom asset type' }
	];

	/**
	 * Execute image generation workflow
	 */
	async function handleGenerate() {
		if (!userDescription.trim()) {
			error = 'Please enter a description for the image';
			return;
		}

		const apiKey = aiSettings.getApiKey();

		if (!apiKey || !aiSettings.provider) {
			error = 'Please configure your AI settings first';
			console.error('[ImageGenerationDialog] API key or provider not configured');
			return;
		}

		isExecuting = true;
		error = null;
		progress = null;
		generatedImageUrl = null;

		console.log('[ImageGenerationDialog] Starting image generation workflow');

		try {
			// Create AI provider
			const provider = createProvider(aiSettings.provider, apiKey);
			console.log('[ImageGenerationDialog] Provider created:', aiSettings.provider);

			// Create image generation agent
			const agent = ImageGenerationAgentFactory.createImageGenerationAgent(provider);
			console.log('[ImageGenerationDialog] Image generation agent created');

			// Build workflow goal and context
			const goal = buildImageGenerationWorkflowGoal(
				userDescription,
				selectedStyle,
				selectedAssetType,
				userGuidance
			);
			const context = buildImageGenerationWorkflowContext(
				userDescription,
				selectedStyle,
				selectedAssetType,
				userGuidance
			);

			console.log('[ImageGenerationDialog] Goal:', goal);
			console.log('[ImageGenerationDialog] Context:', context);

			// Execute workflow with progress callback
			const workflowResult = await agent.executeWorkflowMultiStage(goal, context, (p) => {
				progress = p;
				console.log('[ImageGenerationDialog] Progress:', p);
			});

			console.log('[ImageGenerationDialog] Workflow result:', workflowResult);

			if (!workflowResult.success) {
				const errorMsg = workflowResult.error || 'Image generation failed';
				error = errorMsg;
				console.error('[ImageGenerationDialog] Workflow failed:', errorMsg);
			} else {
				console.log('[ImageGenerationDialog] Image generated successfully');

				// Extract generated image from workflow output
				if (workflowResult.output && workflowResult.output.image_data_url) {
					generatedImageUrl = workflowResult.output.image_data_url as string;
					generatedAssetType = selectedAssetType;

					console.log('[ImageGenerationDialog] Image extracted:', {
						assetType: generatedAssetType,
						urlLength: generatedImageUrl?.length ?? 0
					});
				} else {
					error = 'Image was generated but could not be extracted from workflow result';
					console.error('[ImageGenerationDialog] Output structure:', workflowResult.output);
				}
			}
		} catch (e) {
			const errorMsg = e instanceof Error ? e.message : 'Unknown error occurred';
			error = errorMsg;
			console.error('[ImageGenerationDialog] Exception during workflow:', errorMsg);
			console.error('[ImageGenerationDialog] Stack:', e instanceof Error ? e.stack : 'N/A');
		} finally {
			isExecuting = false;
		}
	}

	/**
	 * Add generated image to character assets
	 */
	function handleAddToAssets() {
		if (!generatedImageUrl || !character) {
			return;
		}

		// Create asset name from description
		const assetName = userDescription
			.trim()
			.slice(0, 50)
			.replace(/[^a-zA-Z0-9\s-]/g, '');

		const newAsset: Asset = {
			type: generatedAssetType,
			uri: generatedImageUrl,
			name: assetName || `${generatedAssetType}-${Date.now()}`,
			ext: 'png'
		};

		// Add to character assets
		const currentAssets = character.data.assets || [];
		characterStore.updateField('assets', [...currentAssets, newAsset]);

		console.log('[ImageGenerationDialog] Asset added:', newAsset.name);

		// Notify parent
		dispatch('imageAdded', newAsset);
		if (onImageGenerated) {
			onImageGenerated(generatedImageUrl, generatedAssetType);
		}

		// Close dialog
		handleClose();
	}

	/**
	 * Reset state
	 */
	function handleClose() {
		open = false;
		dispatch('close');
		// Reset after dialog closes
		setTimeout(() => {
			isExecuting = false;
			progress = null;
			error = null;
			generatedImageUrl = null;
			userDescription = '';
			userGuidance = '';
		}, 300);
	}

	/**
	 * Cancel workflow
	 */
	function handleCancel() {
		// TODO: Implement workflow cancellation
		isExecuting = false;
		error = 'Image generation cancelled';
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Portal>
		<Dialog.Overlay />
		<Dialog.Content class="max-h-[90vh] max-w-3xl overflow-y-auto">
			<Dialog.Header>
				<Dialog.Title class="flex items-center gap-2">
					<Sparkles class="h-5 w-5" />
					AI Image Generation
				</Dialog.Title>
				<Dialog.Description>
					Generate character images using AI with narrative prompts and style templates
				</Dialog.Description>
			</Dialog.Header>

			<div class="space-y-4 py-4">
				<!-- API Key Check -->
				{#if !aiSettings.hasApiKey}
					<Alert.Root variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<Alert.Title>API Key Required</Alert.Title>
						<Alert.Description>
							Please configure your OpenRouter API key in Settings → AI to use image generation.
						</Alert.Description>
					</Alert.Root>
				{/if}

				<!-- Generated Image Preview -->
				{#if generatedImageUrl}
					<div class="space-y-3">
						<Label>Generated Image</Label>
						<div
							class="relative flex flex-col items-center gap-3 rounded-lg border border-border bg-muted/20 p-4"
						>
							<img
								src={generatedImageUrl}
								alt="Generated character asset"
								class="max-h-96 max-w-full rounded-lg shadow-lg"
							/>
							<div class="flex w-full gap-2">
								<Button onclick={handleAddToAssets} class="flex-1">
									<Check class="mr-2 h-4 w-4" />
									Add to Assets
								</Button>
								<Button
									variant="outline"
									onclick={() => {
										generatedImageUrl = null;
										error = null;
									}}
									class="flex-1"
								>
									<X class="mr-2 h-4 w-4" />
									Generate New
								</Button>
							</div>
						</div>
					</div>
				{:else}
					<!-- Input Form -->
					<div class="space-y-4">
						<!-- Asset Type -->
						<div class="space-y-2">
							<Label for="asset-type">Asset Type</Label>
							<select
								id="asset-type"
								bind:value={selectedAssetType}
								disabled={isExecuting}
								class="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
							>
								{#each assetTypes as assetType}
									<option value={assetType.value}>
										{assetType.label} - {assetType.description}
									</option>
								{/each}
							</select>
						</div>

						<!-- Style -->
						<div class="space-y-2">
							<Label for="style">Art Style</Label>
							<select
								id="style"
								bind:value={selectedStyle}
								disabled={isExecuting}
								class="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
							>
								{#each styles as style}
									<option value={style.id}>
										{style.name} - {style.description}
									</option>
								{/each}
							</select>
						</div>

						<!-- User Description -->
						<div class="space-y-2">
							<Label for="description">Description</Label>
							<Textarea
								id="description"
								placeholder="Describe what you want to generate (e.g., 'confident portrait', 'dynamic action pose', 'serene background')"
								bind:value={userDescription}
								rows={3}
								disabled={isExecuting}
							/>
							<p class="text-xs text-muted-foreground">
								The AI will analyze your character card and combine it with this description.
							</p>
						</div>

						<!-- User Guidance (Fine-tuning) -->
						<div class="space-y-2">
							<Label for="guidance">Additional Guidance (Optional)</Label>
							<Textarea
								id="guidance"
								placeholder="Fine-tune details (e.g., 'blue eyes, wearing armor, golden hour lighting')"
								bind:value={userGuidance}
								rows={2}
								disabled={isExecuting}
							/>
							<p class="text-xs text-muted-foreground">
								Add specific details to refine the image generation.
							</p>
						</div>
					</div>

					<!-- Progress Indicator -->
					{#if isExecuting && progress}
						<div class="space-y-2">
							<div class="flex items-center gap-2">
								<Loader2 class="h-4 w-4 animate-spin" />
								<span class="text-sm font-medium">{progress.message}</span>
							</div>
							<div class="h-2 w-full overflow-hidden rounded-full bg-muted">
								<div
									class="h-full bg-primary transition-all duration-300"
									style="width: {progress.percentage}%"
								></div>
							</div>
							<p class="text-xs text-muted-foreground">
								Step {progress.currentStep} of {progress.totalSteps}
							</p>
						</div>
					{/if}

					<!-- Error Display -->
					{#if error}
						<Alert.Root variant="destructive">
							<AlertCircle class="h-4 w-4" />
							<Alert.Title>Error</Alert.Title>
							<Alert.Description>{error}</Alert.Description>
						</Alert.Root>
					{/if}

					<!-- Action Buttons -->
					<div class="flex gap-2">
						{#if isExecuting}
							<Button variant="outline" onclick={handleCancel} class="flex-1">
								<X class="mr-2 h-4 w-4" />
								Cancel
							</Button>
						{:else}
							<Button
								onclick={handleGenerate}
								disabled={!userDescription.trim() || !aiSettings.hasApiKey}
								class="flex-1"
							>
								<Sparkles class="mr-2 h-4 w-4" />
								Generate Image
							</Button>
							<Button variant="outline" onclick={handleClose}>Close</Button>
						{/if}
					</div>
				{/if}
			</div>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
