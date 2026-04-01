<script lang="ts">
	import { apiClient as _apiClient } from '$lib/api';
	import type { UserPersona, UpdateUserPersonaRequest } from '$lib/types';
	import { toast } from 'svelte-sonner';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { fly as _fly } from 'svelte/transition';
	import DOMPurify from 'dompurify';
	import { quintOut as _quintOut } from 'svelte/easing';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { slideAndFade } from '$lib/utils/transitions';
	import {
		Card,
		CardHeader,
		CardTitle as _CardTitle,
		CardDescription as _CardDescription,
		CardContent
	} from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import ImageLightbox from '$lib/components/ui/image-lightbox.svelte';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea as TextareaComponent } from '$lib/components/ui/textarea';
	import {
		AlertDialog,
		AlertDialogAction,
		AlertDialogCancel,
		AlertDialogContent,
		AlertDialogDescription,
		AlertDialogFooter,
		AlertDialogHeader,
		AlertDialogTitle
	} from '$lib/components/ui/alert-dialog';
	import TrashIcon from '../icons/trash.svelte';
	import PencilEditIcon from '../icons/pencil-edit.svelte';
	import CheckCircleFill from '../icons/check-circle-fill.svelte';
	import MarkdownRenderer from '../markdown/renderer.svelte';
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription,
		DialogFooter
	} from '$lib/components/ui/dialog';

	let {
		personaId,
		_onEdit,
		onSetDefault
	}: {
		personaId: string;
		_onEdit?: (persona: UserPersona) => void;
		onSetDefault?: (personaId: string) => void;
	} = $props();

	let persona = $state<UserPersona | null>(null);
	let isLoading = $state(true);
	let deleteDialogOpen = $state(false);
	let isDeletingPersona = $state(false);
	let isSettingDefault = $state(false);

	// Edit mode state
	let isEditMode = $state(false);
	let isSaving = $state(false);
	let editedName = $state('');
	let editedDescription = $state('');
	let editedPersonality = $state('');
	let editedScenario = $state('');
	let editedFirstMes = $state('');
	let editedSystemPrompt = $state('');
	let editedMesExample = $state('');
	let editedPostHistoryInstructions = $state('');

	// Appearance & Banner state
	let bannerTimestamp = $state(Date.now());
	let bannerUrl = $state('');
	let bannerLoadError = $state(false);
	let appearanceEditorOpen = $state(false);
	let editBannerFile = $state<File | null>(null);

	// Image lightbox state
	let avatarLightboxOpen = $state(false);

	const selectedPersonaStore = SelectedPersonaStore.fromContext();

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Check if content contains HTML tags
	function containsHtml(text: string | null | undefined): boolean {
		if (!text) return false;
		return /<[^>]*>/g.test(text);
	}

	// Secure HTML sanitization using DOMPurify
	function sanitizeHtml(html: string | null | undefined): string {
		if (!html) return '';

		// Configure DOMPurify to allow safe formatting tags while removing dangerous content
		return DOMPurify.sanitize(html, {
			ALLOWED_TAGS: [
				'p',
				'br',
				'strong',
				'em',
				'i',
				'b',
				'span',
				'div',
				'h1',
				'h2',
				'h3',
				'h4',
				'h5',
				'h6'
			],
			ALLOWED_ATTR: ['style'],
			ALLOW_DATA_ATTR: false,
			// Remove any remaining black/white color styles that don't work with themes
			SANITIZE_DOM: true,
			KEEP_CONTENT: true
		});
	}

	async function loadPersonaData() {
		if (!personaId) return;

		isLoading = true;
		try {
			const result = await _apiClient.getUserPersona(personaId);
			if (result.isOk()) {
				persona = result.value;
				// Initialize edit values
				editedName = persona.name || '';
				editedDescription = persona.description || '';
				editedPersonality = persona.personality || '';
				editedScenario = persona.scenario || '';
				editedFirstMes = persona.first_mes || '';
				editedSystemPrompt = persona.system_prompt || '';
				editedMesExample = persona.mes_example || '';
				editedPostHistoryInstructions = persona.post_history_instructions || '';
			} else {
				toast.error('Failed to load persona', {
					description: result.error.message
				});
			}
		} catch (_error) {
			console.error('Error loading persona:', _error);
			toast.error('An unexpected error occurred');
		} finally {
			isLoading = false;
		}

		// Reset banner variables on load
		bannerLoadError = false;
		bannerUrl = '';
		bannerTimestamp = Date.now();
	}

	function handleEdit() {
		if (!persona) return;

		// Reset edit values to current persona data
		editedName = persona.name || '';
		editedDescription = persona.description || '';
		editedPersonality = persona.personality || '';
		editedScenario = persona.scenario || '';
		editedFirstMes = persona.first_mes || '';
		editedSystemPrompt = persona.system_prompt || '';
		editedMesExample = persona.mes_example || '';
		editedPostHistoryInstructions = persona.post_history_instructions || '';

		isEditMode = true;
	}

	function handleCancelEdit() {
		isEditMode = false;
		// Reset values back to original
		if (persona) {
			editedName = persona.name || '';
			editedDescription = persona.description || '';
			editedPersonality = persona.personality || '';
			editedScenario = persona.scenario || '';
			editedFirstMes = persona.first_mes || '';
			editedSystemPrompt = persona.system_prompt || '';
			editedMesExample = persona.mes_example || '';
			editedPostHistoryInstructions = persona.post_history_instructions || '';
		}
	}

	async function handleSave() {
		if (!persona) return;

		isSaving = true;

		try {
			const updateData: UpdateUserPersonaRequest = {};

			// Only include changed fields
			if (editedName !== (persona.name || '') && editedName.trim()) {
				updateData.name = editedName.trim();
			}
			if (editedDescription !== (persona.description || '')) {
				updateData.description = editedDescription.trim();
			}
			if (editedPersonality !== (persona.personality || '')) {
				updateData.personality = editedPersonality.trim();
			}
			if (editedScenario !== (persona.scenario || '')) {
				updateData.scenario = editedScenario.trim();
			}
			if (editedFirstMes !== (persona.first_mes || '')) {
				updateData.first_mes = editedFirstMes.trim();
			}
			if (editedSystemPrompt !== (persona.system_prompt || '')) {
				updateData.system_prompt = editedSystemPrompt.trim();
			}
			if (editedMesExample !== (persona.mes_example || '')) {
				updateData.mes_example = editedMesExample.trim();
			}
			if (editedPostHistoryInstructions !== (persona.post_history_instructions || '')) {
				updateData.post_history_instructions = editedPostHistoryInstructions.trim();
			}

			// Only make API call if there are changes
			if (Object.keys(updateData).length > 0) {
				const result = await _apiClient.updateUserPersona(persona.id, updateData);
				if (result.isOk()) {
					// Update local persona data
					persona.name = editedName.trim();
					persona.description = editedDescription.trim() || null;
					persona.personality = editedPersonality.trim() || null;
					persona.scenario = editedScenario.trim() || null;
					persona.first_mes = editedFirstMes.trim() || null;
					persona.system_prompt = editedSystemPrompt.trim() || null;
					persona.mes_example = editedMesExample.trim() || null;
					persona.post_history_instructions = editedPostHistoryInstructions.trim() || null;

					toast.success('Persona updated successfully');
					isEditMode = false;
				} else {
					toast.error('Failed to update persona: ' + result.error.message);
				}
			} else {
				// No changes, just exit edit mode
				isEditMode = false;
			}
		} catch (_error) {
			toast.error('Error updating persona');
			console.error('Error updating persona:', _error);
		} finally {
			isSaving = false;
		}
	}

	function handleDeleteClick() {
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!persona) return;

		isDeletingPersona = true;
		try {
			const result = await _apiClient.deleteUserPersona(persona.id);
			if (result.isOk()) {
				toast.success('Persona deleted successfully');

				// Trigger refresh of persona list
				selectedPersonaStore.triggerRefresh();

				// Clear the selected persona and navigate back to list view
				selectedPersonaStore.clear();
				window.history.back();
			} else {
				toast.error('Failed to delete persona', {
					description: result.error.message
				});
			}
		} catch (_error) {
			console.error('Error deleting persona:', _error);
			toast.error('An unexpected error occurred');
		} finally {
			isDeletingPersona = false;
			deleteDialogOpen = false;
		}
	}

	async function handleSetDefault() {
		if (!persona) return;

		isSettingDefault = true;
		try {
			const result = await _apiClient.setDefaultPersona(persona.id);
			if (result.isOk()) {
				toast.success(`'${persona.name}' is now your default persona`);
				if (onSetDefault) {
					onSetDefault(persona.id);
				}
			} else {
				toast.error('Failed to set default persona', {
					description: result.error.message
				});
			}
		} catch (_error) {
			console.error('Error setting default persona:', _error);
			toast.error('An unexpected error occurred');
		} finally {
			isSettingDefault = false;
		}
	}

	// Note: loadPersonaData is now called in $effect below to handle prop changes

	// Track previous persona ID for transition detection
	let previousPersonaId = $state<string | null>(null);
	let isTransitioning = $state(false);

	// Reactively load persona data when personaId changes
	$effect(() => {
		if (personaId && personaId !== previousPersonaId) {
			if (previousPersonaId !== null) {
				// This is a persona change, not initial load - trigger transition
				isTransitioning = true;
				setTimeout(() => {
					loadPersonaData();
					setTimeout(() => {
						isTransitioning = false;
					}, 100);
				}, 200);
			} else {
				// Initial load
				loadPersonaData();
			}
			previousPersonaId = personaId;
		}
	});

	async function handleSaveAppearance() {
		if (!persona) return;
		
		if (editBannerFile) {
			isSaving = true;
			try {
				const uploadResult = await _apiClient.uploadPersonaBanner(persona.id, editBannerFile);
				if (uploadResult.isOk()) {
					toast.success('Persona banner updated successfully');
					// Trigger banner reload
					bannerTimestamp = Date.now();
					bannerUrl = `/api/personas/${persona.id}/banner?t=${bannerTimestamp}`;
					bannerLoadError = false;
					appearanceEditorOpen = false;
					editBannerFile = null;
				} else {
					toast.error('Failed to upload banner: ' + uploadResult.error.message);
				}
			} catch (_error) {
				toast.error('An unexpected error occurred while saving the banner');
			} finally {
				isSaving = false;
			}
		} else {
			appearanceEditorOpen = false;
		}
	}

</script>

<div
	class="h-full w-full overflow-y-auto px-4"
	in:slideAndFade={{ y: 20, duration: 300 }}
	out:slideAndFade={{ y: -20, duration: 200 }}
>
	<div class="flex min-h-full w-full items-center justify-center py-8">
		<div class="mx-auto w-full max-w-6xl">
			<div
				class="space-y-6"
				style="opacity: {isTransitioning ? 0.3 : 1}; transition: opacity 300ms ease-in-out;"
			>
				<!-- Persona Header Card -->
				{#if isLoading}
					<Card class="border-0 shadow-none">
						<CardHeader class="px-0">
							<div class="flex items-center space-x-6">
								<Skeleton class="h-24 w-24 rounded-full" />
								<div class="flex-1 space-y-3">
									<Skeleton class="h-8 w-2/3" />
									<Skeleton class="h-4 w-full" />
									<Skeleton class="h-4 w-5/6" />
								</div>
							</div>
						</CardHeader>
					</Card>
				{:else if persona}
					<Card
class="border-border/10 shadow-sm bg-background/50 backdrop-blur-sm rounded-xl overflow-hidden transition-all duration-300 relative border-0 sm:border"
>
<!-- Hero Banner Image -->
<div class="h-32 sm:h-48 w-full relative overflow-hidden bg-muted/30">
{#if bannerUrl}
<img src={bannerUrl} alt="Banner" class="w-full h-full object-cover" onerror={() => { bannerLoadError = true; bannerUrl = ''; }} />
<div class="absolute inset-0 bg-gradient-to-t from-background via-background/20 to-transparent"></div>
{:else if !bannerLoadError && persona.avatar}
<!-- Attempt to load banner -->
<img src={`/api/personas/${persona?.id}/banner?t=${bannerTimestamp}`} alt="Banner" class="w-full h-full object-cover" onload={() => { bannerUrl = `/api/personas/${persona?.id}/banner?t=${bannerTimestamp}` }} onerror={() => { bannerLoadError = true; bannerUrl = ''; }} class:hidden={!bannerUrl} />
<!-- Fallback to blurred avatar -->
{#if !bannerUrl}
<img src={`${persona?.avatar}?width=128&height=128`} alt="" class="w-full h-full object-cover blur-[32px] scale-125 opacity-40 dark:opacity-30" />
<div class="absolute inset-0 bg-gradient-to-t from-background via-background/50 to-background/10"></div>
{/if}
{:else if persona?.avatar}
<img src={`${persona?.avatar}?width=128&height=128`} alt="" class="w-full h-full object-cover blur-[32px] scale-125 opacity-40 dark:opacity-30" />
<div class="absolute inset-0 bg-gradient-to-t from-background via-background/50 to-background/10"></div>
{:else}
<div class="absolute inset-0 bg-gradient-to-br from-primary/10 to-primary/5"></div>
<div class="absolute inset-0 bg-gradient-to-t from-background to-transparent"></div>
{/if}

<!-- Top Right Appearance Buttons -->
<div class="absolute top-4 right-4 z-10 flex gap-2">
<ButtonComponent variant="outline" size="sm" class="bg-background/40 backdrop-blur-md border-border/20 text-foreground hover:bg-background/80" onclick={() => (appearanceEditorOpen = true)}>
Settings
</ButtonComponent>
</div>
</div>

<div class="px-4 sm:px-6 pb-6 relative">
<div class="flex flex-col sm:flex-row gap-4 sm:gap-6 -mt-12 sm:-mt-16">
<Avatar
class="h-24 w-24 sm:h-32 sm:w-32 border-4 border-background shadow-lg transition-transform hover:scale-105 {persona?.avatar ? 'cursor-pointer' : ''} bg-background z-10 shrink-0"
onclick={() => persona?.avatar && (avatarLightboxOpen = true)}
>
{#if persona?.avatar}
<AvatarImage src={`${persona?.avatar}?width=128&height=128`} alt={persona?.name} class="object-cover" />
{/if}
<AvatarFallback class="text-3xl sm:text-4xl font-bold bg-muted text-muted-foreground">
{getInitials(persona?.name || '')}
</AvatarFallback>
</Avatar>

<!-- Persona Name and Actions -->
<div class="min-w-0 flex-1 pt-2 sm:pt-16 flex flex-col justify-between gap-4">
<div class="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
<!-- Name Section -->
<div class="min-w-0 flex-1 space-y-1">
{#if !isEditMode}
<div class="relative flex items-center max-w-full">
<h1 class="text-2xl sm:text-4xl font-extrabold tracking-tight text-balance leading-tight pr-8 drop-shadow-sm">{persona?.name}</h1>
</div>
{#if persona?.description}
<div class="mt-2 text-sm text-muted-foreground line-clamp-2">
{persona?.description}
</div>
{/if}
{:else}
<div class="space-y-3">
<div>
<Label for="edit-name" class="text-xs font-medium uppercase text-muted-foreground">Name</Label>
<Input
id="edit-name"
bind:value={editedName}
class="mt-1 h-auto py-1 text-2xl font-bold w-full max-w-sm"
placeholder="Persona name"
/>
</div>
<div>
<Label for="edit-description" class="text-xs font-medium uppercase text-muted-foreground">Description</Label>
<TextareaComponent
id="edit-description"
bind:value={editedDescription}
class="mt-1"
placeholder="Persona description"
rows={2}
/>
</div>
</div>
{/if}
</div>

<!-- Primary Actions -->
<div class="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0 w-full sm:w-auto mt-2 sm:mt-0">
{#if !isEditMode}
<ButtonComponent onclick={handleEdit} class="gap-2 shadow-sm flex-1 sm:flex-none justify-center">
<PencilEditIcon class="h-4 w-4" />
Edit
</ButtonComponent>
<ButtonComponent
onclick={handleSetDefault}
variant="outline"
disabled={isSettingDefault}
class="bg-background/50 flex-1 sm:flex-none justify-center border-border/40"
>
{isSettingDefault ? 'Setting...' : 'Set as Default'}
</ButtonComponent>
<ButtonComponent onclick={handleDeleteClick} variant="outline" class="text-destructive border-destructive/20 hover:bg-destructive/10">
<TrashIcon class="h-4 w-4" />
</ButtonComponent>
{:else}
<ButtonComponent
onclick={handleSave}
disabled={isSaving}
class="gap-2 shadow-sm flex-1 sm:flex-none justify-center"
>
{#if isSaving}
<div class="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
Saving...
{:else}
<CheckCircleFill class="h-4 w-4" />
Save Changes
{/if}
</ButtonComponent>
<ButtonComponent onclick={handleCancelEdit} variant="outline" class="flex-none bg-background/50 border-border/40">Cancel</ButtonComponent>
{/if}
</div>
</div>
</div>
</div>
</div>

						{#if isEditMode || persona.scenario || persona.personality || persona.first_mes || persona.system_prompt || persona.mes_example || persona.post_history_instructions}
							<CardContent class="grid grid-cols-1 md:grid-cols-2 gap-6 px-6 pb-6 mt-4">
								{#if isEditMode || persona.personality}
									<div class="space-y-2 rounded-xl border border-border/20 bg-muted/10 p-5 shadow-sm flex flex-col h-full">
										<h4 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80 mb-2 border-b border-border/10 pb-2">Personality</h4>
										{#if isEditMode}
											<TextareaComponent
												id="edit-personality"
												bind:value={editedPersonality}
												placeholder="Describe personality traits..."
												rows={5}
												class="resize-y bg-background/50 focus:bg-background transition-colors flex-grow"
											/>
										{:else}
											<div class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground flex-grow">
												{#if containsHtml(persona.personality)}
													<!-- eslint-disable-next-line svelte/no-at-html-tags -->
													{@html sanitizeHtml(persona.personality)}
												{:else}
													<MarkdownRenderer md={persona.personality || ''} />
												{/if}
											</div>
										{/if}
									</div>
								{/if}

								{#if isEditMode || persona.scenario}
									<div class="space-y-2 rounded-xl border border-border/20 bg-muted/10 p-5 shadow-sm flex flex-col h-full">
										<h4 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80 mb-2 border-b border-border/10 pb-2">Scenario</h4>
										{#if isEditMode}
											<TextareaComponent
												id="edit-scenario"
												bind:value={editedScenario}
												placeholder="Context and scenario..."
												rows={5}
												class="resize-y bg-background/50 focus:bg-background transition-colors flex-grow"
											/>
										{:else}
											<div class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground flex-grow">
												{#if containsHtml(persona.scenario)}
													<!-- eslint-disable-next-line svelte/no-at-html-tags -->
													{@html sanitizeHtml(persona.scenario)}
												{:else}
													<MarkdownRenderer md={persona.scenario || ''} />
												{/if}
											</div>
										{/if}
									</div>
								{/if}
								
								{#if isEditMode || persona.system_prompt}
									<div class="space-y-2 md:col-span-2 rounded-xl border border-border/20 bg-muted/10 p-5 shadow-sm flex flex-col h-full">
										<h4 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80 mb-2 border-b border-border/10 pb-2">System Prompt</h4>
										{#if isEditMode}
											<TextareaComponent
												id="edit-system-prompt"
												bind:value={editedSystemPrompt}
												placeholder="System-level instructions..."
												rows={4}
												class="resize-y bg-background/50 focus:bg-background transition-colors flex-grow"
											/>
										{:else}
											<div class="prose prose-sm dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground flex-grow">
												{#if containsHtml(persona.system_prompt)}
													<!-- eslint-disable-next-line svelte/no-at-html-tags -->
													{@html sanitizeHtml(persona.system_prompt)}
												{:else}
													<MarkdownRenderer md={persona.system_prompt || ''} />
												{/if}
											</div>
										{/if}
									</div>
								{/if}

								{#if isEditMode || persona.first_mes}
									<div class="space-y-2 md:col-span-2 rounded-xl border border-border/20 border-l-4 border-l-primary/50 bg-muted/10 p-5 shadow-sm flex flex-col h-full">
										<h4 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80 mb-2 border-b border-border/10 pb-2">First Message</h4>
										{#if isEditMode}
											<TextareaComponent
												id="edit-first-mes"
												bind:value={editedFirstMes}
												placeholder="The first message sent by the persona..."
												rows={4}
												class="resize-y bg-background/50 focus:bg-background transition-colors font-serif italic text-base flex-grow"
											/>
										{:else}
											<div class="prose prose-sm dark:prose-invert max-w-none text-base font-serif italic [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground flex-grow">
												{#if containsHtml(persona.first_mes)}
													<!-- eslint-disable-next-line svelte/no-at-html-tags -->
													{@html sanitizeHtml(persona.first_mes)}
												{:else}
													<MarkdownRenderer md={persona.first_mes || ''} />
												{/if}
											</div>
										{/if}
									</div>
								{/if}

								{#if isEditMode || persona.mes_example}
									<div class="space-y-2 rounded-xl border border-border/20 bg-muted/10 p-5 shadow-sm flex flex-col h-full">
										<h4 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80 mb-2 border-b border-border/10 pb-2">Message Examples</h4>
										{#if isEditMode}
											<TextareaComponent
												id="edit-mes-example"
												bind:value={editedMesExample}
												placeholder="Example dialogue..."
												rows={4}
												class="resize-y bg-background/50 focus:bg-background transition-colors font-mono text-xs flex-grow"
											/>
										{:else}
											<div class="prose prose-sm dark:prose-invert max-w-none text-xs font-mono bg-background/40 p-3 rounded overflow-x-auto whitespace-pre-wrap [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground flex-grow">
												{#if containsHtml(persona.mes_example)}
													<!-- eslint-disable-next-line svelte/no-at-html-tags -->
													{@html sanitizeHtml(persona.mes_example)}
												{:else}
													{persona.mes_example}
												{/if}
											</div>
										{/if}
									</div>
								{/if}

								{#if isEditMode || persona.post_history_instructions}
									<div class="space-y-2 rounded-xl border border-border/20 bg-muted/10 p-5 shadow-sm flex flex-col h-full">
										<h4 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80 mb-2 border-b border-border/10 pb-2">Post-History Instructions</h4>
										{#if isEditMode}
											<TextareaComponent
												id="edit-phi"
												bind:value={editedPostHistoryInstructions}
												placeholder="Instructions for the bottom of the prompt..."
												rows={4}
												class="resize-y bg-background/50 focus:bg-background transition-colors font-mono text-xs flex-grow"
											/>
										{:else}
											<div class="prose prose-sm dark:prose-invert max-w-none text-xs font-mono bg-background/40 p-3 rounded overflow-x-auto whitespace-pre-wrap [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground flex-grow">
												{#if containsHtml(persona.post_history_instructions)}
													<!-- eslint-disable-next-line svelte/no-at-html-tags -->
													{@html sanitizeHtml(persona.post_history_instructions)}
												{:else}
													{persona.post_history_instructions}
												{/if}
											</div>
										{/if}
									</div>
								{/if}
							</CardContent>
						{/if}
					</Card>
				{/if}
			</div>
		</div>
	</div>
</div>

<!-- Delete Confirmation Dialog -->
<AlertDialog bind:open={deleteDialogOpen}>
	<AlertDialogContent>
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Persona</AlertDialogTitle>
			<AlertDialogDescription>
				Are you sure you want to delete this persona? This action cannot be undone.
				{#if persona}
					<br />
					<strong class="mt-2 block">"{persona.name}"</strong>
				{/if}
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel disabled={isDeletingPersona}>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={confirmDelete}
				disabled={isDeletingPersona}
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
			>
				{isDeletingPersona ? 'Deleting...' : 'Delete'}
			</AlertDialogAction>
		</AlertDialogFooter>
	</AlertDialogContent>
</AlertDialog>

<!-- Avatar Image Lightbox -->
{#if persona && persona.avatar}
	<ImageLightbox src={persona.avatar} alt={persona.name} bind:open={avatarLightboxOpen} />
{/if}

<!-- Appearance Settings Dialog -->
<Dialog bind:open={appearanceEditorOpen}>
	<DialogContent class="max-w-md">
		<DialogHeader>
			<DialogTitle>Persona Appearance Settings</DialogTitle>
			<DialogDescription>
				Customize how the persona looks in the dossier interface.
			</DialogDescription>
		</DialogHeader>

		<div class="grid gap-4 py-4">
			<div class="grid gap-2">
				<label for="persona_banner_file" class="text-sm font-medium leading-none">Banner Image</label>
				<Input
					id="persona_banner_file"
					type="file"
					accept="image/png, image/jpeg, image/webp"
					onchange={(e) => {
						const target = e.target as HTMLInputElement;
						if (target.files && target.files.length > 0) {
							editBannerFile = target.files[0];
						} else {
							editBannerFile = null;
						}
					}}
				/>
				<p class="text-[0.8rem] text-muted-foreground">Upload a hero banner image (max 5MB).</p>
			</div>
		</div>

		<DialogFooter>
			<ButtonComponent variant="outline" onclick={() => (appearanceEditorOpen = false)}
				>Cancel</ButtonComponent
			>
			<ButtonComponent onclick={handleSaveAppearance} disabled={isSaving || !editBannerFile}>
				{#if isSaving}
					<span class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
					Saving...
				{:else}
					Save Changes
				{/if}
			</ButtonComponent>
		</DialogFooter>
	</DialogContent>
</Dialog>

<style>
	/* Override inline styles from HTML content to respect theme */
	:global(.prose *[style*='color: #000000']),
	:global(.prose *[style*='color: rgb(0, 0, 0)']),
	:global(.prose *[style*='color:#000000']),
	:global(.prose *[style*='color:rgb(0,0,0)']) {
		color: hsl(var(--foreground)) !important;
	}

	:global(.prose p),
	:global(.prose span),
	:global(.prose strong) {
		color: hsl(var(--foreground)) !important;
	}

	:global(.prose p[style*='text-align: center']) {
		margin-top: 1rem;
		margin-bottom: 1rem;
	}
</style>
