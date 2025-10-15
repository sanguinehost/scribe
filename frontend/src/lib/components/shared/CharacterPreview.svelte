<script lang="ts">
	/* eslint-disable svelte/no-at-html-tags */
	import { characterStore } from '$lib/stores/character.svelte';
	import * as Card from '$lib/components/ui/card';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import Separator from '$lib/components/ui/separator/separator.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import {
		AlertCircle,
		CheckCircle,
		Maximize2,
		Image as ImageIcon,
		ChevronDown,
		ChevronRight
	} from '@lucide/svelte';
	import { formatDescription } from '$lib/utils/text-formatter';

	const { character, isValid, validationErrors, baseImage } = $derived(characterStore);
	const hasChanges = $derived(characterStore.hasChanges);

	let showImageModal = $state(false);
	let isDescriptionExpanded = $state(false);
	let isPersonalityExpanded = $state(false);
	let isScenarioExpanded = $state(false);
	let showFullscreenPreview = $state(false);

	// Format text fields with proper HTML
	const formattedDescription = $derived(
		character?.data.description ? formatDescription(character.data.description) : ''
	);
	const formattedPersonality = $derived(
		character?.data.personality ? formatDescription(character.data.personality) : ''
	);
	const formattedScenario = $derived(
		character?.data.scenario ? formatDescription(character.data.scenario) : ''
	);

	function openImageModal() {
		if (baseImage) {
			showImageModal = true;
		}
	}

	function closeImageModal() {
		showImageModal = false;
	}

	function openFullscreenPreview() {
		showFullscreenPreview = true;
	}

	function closeFullscreenPreview() {
		showFullscreenPreview = false;
	}
</script>

<Card.Root class="flex max-h-[calc(100vh-8rem)] flex-col">
	<Card.Header class="flex-shrink-0">
		<div class="flex items-center justify-between">
			<Card.Title>Character Preview</Card.Title>
			<div class="flex items-center gap-2">
				{#if hasChanges}
					<Badge variant="outline" class="text-xs">Unsaved</Badge>
				{/if}
				<button
					type="button"
					class="rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
					onclick={openFullscreenPreview}
					aria-label="Expand preview"
					title="Expand fullscreen"
				>
					<Maximize2 class="h-4 w-4" />
				</button>
			</div>
		</div>
	</Card.Header>

	<div class="custom-scrollbar flex-1 overflow-y-auto scroll-smooth">
		<Card.Content class="space-y-4">
			{#if character}
				<!-- Character Avatar (Prominent Display) -->
				{#if baseImage}
					<div class="group relative">
						<button
							type="button"
							class="relative aspect-square w-full cursor-pointer overflow-hidden rounded-lg border-2 border-border bg-muted transition-all hover:border-primary hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
							onclick={openImageModal}
						>
							<img
								src={baseImage}
								alt={character.data.name || 'Character'}
								class="h-full w-full object-cover transition-transform group-hover:scale-105"
							/>
							<div
								class="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 transition-opacity group-hover:opacity-100"
							>
								<div class="flex flex-col items-center gap-2 text-white">
									<Maximize2 class="h-8 w-8" />
									<span class="text-sm font-medium">Click to expand</span>
								</div>
							</div>
						</button>
					</div>
				{:else}
					<!-- Placeholder when no image -->
					<div
						class="relative flex aspect-square w-full items-center justify-center overflow-hidden rounded-lg border-2 border-dashed border-border bg-muted/30"
					>
						<div class="text-center text-muted-foreground">
							<ImageIcon class="mx-auto mb-2 h-16 w-16 opacity-40" />
							<p class="text-sm font-medium">No avatar</p>
							<p class="mt-1 text-xs">Upload in Basic Info</p>
						</div>
					</div>
				{/if}

				<Separator />

				<!-- Name & Version -->
				<div class="space-y-2">
					<h3 class="truncate text-xl font-bold">
						{character.data.name || 'Unnamed Character'}
					</h3>
					{#if character.data.nickname}
						<p class="truncate text-sm italic text-muted-foreground">
							"{character.data.nickname}"
						</p>
					{/if}
					<div class="flex flex-wrap gap-1.5">
						<Badge variant="secondary" class="text-xs">
							{character.spec_version || '3.0'}
						</Badge>
						{#if character.data.character_version}
							<Badge variant="outline" class="text-xs">v{character.data.character_version}</Badge>
						{/if}
					</div>
				</div>

				<Separator />

				<!-- Description (Collapsible with Formatting) -->
				{#if character.data.description}
					<div class="space-y-2">
						<div
							class="group -mx-2 cursor-pointer rounded px-2 py-1 transition-colors hover:bg-muted/30"
							onclick={() => (isDescriptionExpanded = !isDescriptionExpanded)}
							role="button"
							tabindex="0"
							onkeydown={(e) =>
								e.key === 'Enter' && (isDescriptionExpanded = !isDescriptionExpanded)}
						>
							<div
								class="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors group-hover:text-foreground"
							>
								{#if isDescriptionExpanded}
									<ChevronDown class="h-3.5 w-3.5 flex-shrink-0" />
								{:else}
									<ChevronRight class="h-3.5 w-3.5 flex-shrink-0" />
								{/if}
								<span>Description</span>
							</div>
							<div
								class="formatted-text transition-all {isDescriptionExpanded ? '' : 'line-clamp-3'}"
							>
								{@html formattedDescription}
							</div>
						</div>
					</div>
				{/if}

				<!-- Personality -->
				{#if character.data.personality}
					<div class="space-y-2">
						<div
							class="group -mx-2 cursor-pointer rounded px-2 py-1 transition-colors hover:bg-muted/30"
							onclick={() => (isPersonalityExpanded = !isPersonalityExpanded)}
							role="button"
							tabindex="0"
							onkeydown={(e) =>
								e.key === 'Enter' && (isPersonalityExpanded = !isPersonalityExpanded)}
						>
							<div
								class="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors group-hover:text-foreground"
							>
								{#if isPersonalityExpanded}
									<ChevronDown class="h-3.5 w-3.5 flex-shrink-0" />
								{:else}
									<ChevronRight class="h-3.5 w-3.5 flex-shrink-0" />
								{/if}
								<span>Personality</span>
							</div>
							<div
								class="formatted-text transition-all {isPersonalityExpanded ? '' : 'line-clamp-2'}"
							>
								{@html formattedPersonality}
							</div>
						</div>
					</div>
				{/if}

				<!-- Scenario -->
				{#if character.data.scenario}
					<div class="space-y-2">
						<div
							class="group -mx-2 cursor-pointer rounded px-2 py-1 transition-colors hover:bg-muted/30"
							onclick={() => (isScenarioExpanded = !isScenarioExpanded)}
							role="button"
							tabindex="0"
							onkeydown={(e) => e.key === 'Enter' && (isScenarioExpanded = !isScenarioExpanded)}
						>
							<div
								class="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors group-hover:text-foreground"
							>
								{#if isScenarioExpanded}
									<ChevronDown class="h-3.5 w-3.5 flex-shrink-0" />
								{:else}
									<ChevronRight class="h-3.5 w-3.5 flex-shrink-0" />
								{/if}
								<span>Scenario</span>
							</div>
							<div class="formatted-text transition-all {isScenarioExpanded ? '' : 'line-clamp-2'}">
								{@html formattedScenario}
							</div>
						</div>
					</div>
				{/if}

				<!-- Tags -->
				{#if character.data.tags && character.data.tags.length > 0}
					<div class="space-y-2">
						<p class="text-xs font-medium text-muted-foreground">Tags</p>
						<div class="flex flex-wrap gap-1">
							{#each character.data.tags as tag}
								<Badge variant="outline" class="text-xs">{tag}</Badge>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Creator -->
				{#if character.data.creator}
					<div class="space-y-1">
						<p class="text-xs font-medium text-muted-foreground">Creator</p>
						<p class="text-sm">{character.data.creator}</p>
					</div>
				{/if}

				<Separator />

				<!-- Stats -->
				<div class="grid grid-cols-2 gap-3 text-xs">
					<div>
						<p class="text-muted-foreground">Greetings</p>
						<p class="font-medium">
							{1 + (character.data.alternate_greetings?.length || 0)}
						</p>
					</div>
					<div>
						<p class="text-muted-foreground">Assets</p>
						<p class="font-medium">
							{character.data.assets?.length || 0}
						</p>
					</div>
				</div>

				<!-- Validation Status -->
				<Separator />
				{#if isValid}
					<Alert.Root
						variant="default"
						class="border-green-500/50 bg-green-50 dark:bg-green-950/20"
					>
						<CheckCircle class="h-4 w-4 text-green-600 dark:text-green-400" />
						<Alert.Title class="text-green-800 dark:text-green-300">Valid Character</Alert.Title>
						<Alert.Description class="text-green-700 dark:text-green-400">
							All required fields are filled
						</Alert.Description>
					</Alert.Root>
				{:else}
					<Alert.Root variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<Alert.Title>Validation Errors</Alert.Title>
						<Alert.Description>
							{#if validationErrors.length > 0}
								<ul class="mt-2 list-inside list-disc space-y-1 text-sm">
									{#each validationErrors.slice(0, 3) as error}
										<li class="truncate">{error.path}: {error.message}</li>
									{/each}
									{#if validationErrors.length > 3}
										<li class="text-xs">+{validationErrors.length - 3} more errors</li>
									{/if}
								</ul>
							{:else}
								<p class="text-sm">Character data is invalid</p>
							{/if}
						</Alert.Description>
					</Alert.Root>
				{/if}
			{:else}
				<div class="flex min-h-[200px] items-center justify-center">
					<p class="text-sm text-muted-foreground">No character loaded</p>
				</div>
			{/if}
		</Card.Content>
	</div>
</Card.Root>

<!-- Full-Screen Image Modal (Higher z-index to appear above fullscreen preview) -->
{#if showImageModal && baseImage}
	<div
		class="fixed inset-0 z-[60] flex items-center justify-center bg-black/90 backdrop-blur-sm"
		onclick={closeImageModal}
		onkeydown={(e) => e.key === 'Escape' && closeImageModal()}
		role="button"
		tabindex="0"
	>
		<div class="relative flex h-full max-h-[90vh] w-full max-w-7xl items-center justify-center p-4">
			<img
				src={baseImage}
				alt={character?.data.name || 'Character'}
				class="max-h-full max-w-full rounded-lg object-contain shadow-2xl"
				onclick={(e) => e.stopPropagation()}
				role="presentation"
			/>
			<button
				type="button"
				class="absolute right-8 top-8 rounded-full bg-black/50 p-3 text-white transition-colors hover:bg-black/70"
				onclick={closeImageModal}
				aria-label="Close"
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-6 w-6"
					fill="none"
					viewBox="0 0 24 24"
					stroke="currentColor"
				>
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M6 18L18 6M6 6l12 12"
					/>
				</svg>
			</button>
		</div>
	</div>
{/if}

<!-- Fullscreen Preview Modal -->
{#if showFullscreenPreview && character}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
		onclick={closeFullscreenPreview}
		onkeydown={(e) => e.key === 'Escape' && closeFullscreenPreview()}
		role="button"
		tabindex="0"
	>
		<div
			class="relative flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-lg bg-card shadow-2xl"
			onclick={(e) => e.stopPropagation()}
			onkeydown={(e) => e.stopPropagation()}
			role="dialog"
			tabindex="-1"
			aria-modal="true"
			aria-labelledby="preview-title"
		>
			<!-- Header -->
			<div class="flex-shrink-0 border-b bg-card px-6 py-4">
				<div class="flex items-center justify-between">
					<h2 id="preview-title" class="text-2xl font-bold">Character Preview</h2>
					<button
						type="button"
						class="rounded-md p-2 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
						onclick={closeFullscreenPreview}
						aria-label="Close"
					>
						<svg
							xmlns="http://www.w3.org/2000/svg"
							class="h-6 w-6"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M6 18L18 6M6 6l12 12"
							/>
						</svg>
					</button>
				</div>
			</div>

			<!-- Scrollable Content -->
			<div class="custom-scrollbar flex-1 overflow-y-auto px-6 py-6">
				<div class="space-y-6">
					<!-- Avatar (larger in fullscreen) -->
					{#if baseImage}
						<div class="flex justify-center">
							<button
								type="button"
								class="group relative h-64 w-64 cursor-pointer overflow-hidden rounded-lg border-2 border-border bg-muted transition-all hover:border-primary hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
								onclick={openImageModal}
							>
								<img
									src={baseImage}
									alt={character.data.name || 'Character'}
									class="h-full w-full object-cover transition-transform group-hover:scale-105"
								/>
								<div
									class="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 transition-opacity group-hover:opacity-100"
								>
									<div class="flex flex-col items-center gap-2 text-white">
										<Maximize2 class="h-8 w-8" />
										<span class="text-sm font-medium">Click to expand</span>
									</div>
								</div>
							</button>
						</div>
					{/if}

					<!-- Name & Version -->
					<div class="space-y-3 text-center">
						<h3 class="text-3xl font-bold">
							{character.data.name || 'Unnamed Character'}
						</h3>
						{#if character.data.nickname}
							<p class="text-lg italic text-muted-foreground">
								"{character.data.nickname}"
							</p>
						{/if}
						<div class="flex flex-wrap justify-center gap-2">
							<Badge variant="secondary" class="text-sm">
								{character.spec_version || '3.0'}
							</Badge>
							{#if character.data.character_version}
								<Badge variant="outline" class="text-sm">v{character.data.character_version}</Badge>
							{/if}
							{#if hasChanges}
								<Badge variant="outline" class="text-sm">Unsaved</Badge>
							{/if}
						</div>
					</div>

					<Separator />

					<!-- Description (always expanded in fullscreen) -->
					{#if character.data.description}
						<div class="space-y-3">
							<h4 class="text-lg font-semibold">Description</h4>
							<div class="formatted-text">
								<!-- eslint-disable-next-line svelte/no-at-html-tags -->
								{@html formattedDescription}
							</div>
						</div>
					{/if}

					<!-- Personality -->
					{#if character.data.personality}
						<div class="space-y-3">
							<h4 class="text-lg font-semibold">Personality</h4>
							<div class="formatted-text">
								<!-- eslint-disable-next-line svelte/no-at-html-tags -->
								{@html formattedPersonality}
							</div>
						</div>
					{/if}

					<!-- Scenario -->
					{#if character.data.scenario}
						<div class="space-y-3">
							<h4 class="text-lg font-semibold">Scenario</h4>
							<div class="formatted-text">
								<!-- eslint-disable-next-line svelte/no-at-html-tags -->
								{@html formattedScenario}
							</div>
						</div>
					{/if}

					<!-- Tags -->
					{#if character.data.tags && character.data.tags.length > 0}
						<div class="space-y-3">
							<h4 class="text-lg font-semibold">Tags</h4>
							<div class="flex flex-wrap gap-2">
								{#each character.data.tags as tag}
									<Badge variant="outline">{tag}</Badge>
								{/each}
							</div>
						</div>
					{/if}

					<!-- Creator -->
					{#if character.data.creator}
						<div class="space-y-2">
							<h4 class="text-lg font-semibold">Creator</h4>
							<p class="text-base">{character.data.creator}</p>
						</div>
					{/if}

					<Separator />

					<!-- Stats -->
					<div class="grid grid-cols-2 gap-4">
						<div class="rounded-lg bg-muted p-4 text-center">
							<p class="mb-1 text-sm text-muted-foreground">Greetings</p>
							<p class="text-2xl font-bold">
								{1 + (character.data.alternate_greetings?.length || 0)}
							</p>
						</div>
						<div class="rounded-lg bg-muted p-4 text-center">
							<p class="mb-1 text-sm text-muted-foreground">Assets</p>
							<p class="text-2xl font-bold">
								{character.data.assets?.length || 0}
							</p>
						</div>
					</div>

					<!-- Validation Status -->
					<Separator />
					{#if isValid}
						<Alert.Root
							variant="default"
							class="border-green-500/50 bg-green-50 dark:bg-green-950/20"
						>
							<CheckCircle class="h-4 w-4 text-green-600 dark:text-green-400" />
							<Alert.Title class="text-green-800 dark:text-green-300">Valid Character</Alert.Title>
							<Alert.Description class="text-green-700 dark:text-green-400">
								All required fields are filled
							</Alert.Description>
						</Alert.Root>
					{:else}
						<Alert.Root variant="destructive">
							<AlertCircle class="h-4 w-4" />
							<Alert.Title>Validation Errors</Alert.Title>
							<Alert.Description>
								{#if validationErrors.length > 0}
									<ul class="mt-2 list-inside list-disc space-y-1">
										{#each validationErrors as error}
											<li>{error.path}: {error.message}</li>
										{/each}
									</ul>
								{:else}
									<p>Character data is invalid</p>
								{/if}
							</Alert.Description>
						</Alert.Root>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}

<style>
	/* Code block styling */
	:global(.code-block) {
		margin-top: 0.5rem;
		margin-bottom: 0.5rem;
		border-radius: 0.375rem;
		border-width: 1px;
		border-color: hsl(var(--border));
		background-color: hsl(var(--muted));
		padding: 0.75rem;
		font-size: 0.875rem;
		font-family: ui-monospace, monospace;
		overflow-x: auto;
	}

	/* Status block special styling */
	:global(.status-block) {
		border-color: hsl(var(--primary) / 0.3);
		background-color: hsl(var(--primary) / 0.05);
	}

	:global(.dark .status-block) {
		background-color: hsl(var(--primary) / 0.1);
	}

	/* Code content */
	:global(.code-block code) {
		font-size: 0.75rem;
		white-space: pre-wrap;
		word-break: break-word;
	}

	/* Formatted text container */
	:global(.formatted-text) {
		font-size: 0.875rem;
		line-height: 1.625;
	}

	:global(.formatted-text strong) {
		font-weight: 600;
		color: hsl(var(--foreground));
	}

	:global(.formatted-text em) {
		font-style: italic;
		color: hsl(var(--muted-foreground));
	}

	:global(.formatted-text ul) {
		margin-top: 0.5rem;
		margin-bottom: 0.5rem;
		margin-left: 1rem;
		list-style-type: disc;
	}

	:global(.formatted-text li) {
		font-size: 0.875rem;
		margin-top: 0.25rem;
	}

	/* Custom scrollbar styling */
	.custom-scrollbar::-webkit-scrollbar {
		width: 8px;
	}

	.custom-scrollbar::-webkit-scrollbar-track {
		background-color: transparent;
	}

	.custom-scrollbar::-webkit-scrollbar-thumb {
		background-color: hsl(var(--border));
		border-radius: 9999px;
	}

	.custom-scrollbar::-webkit-scrollbar-thumb:hover {
		background-color: hsl(var(--border) / 0.8);
	}
</style>
