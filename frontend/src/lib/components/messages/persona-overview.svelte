<script lang="ts">
	import { apiClient } from '$lib/api';
	import type { UserPersona } from '$lib/types';
	import { toast } from 'svelte-sonner';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { fly } from 'svelte/transition';
	import { quintOut } from 'svelte/easing';
	import { Button } from '$lib/components/ui/button';
	import { slideAndFade } from '$lib/utils/transitions';
	import {
		Card,
		CardHeader,
		CardTitle,
		CardDescription,
		CardContent
	} from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
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
	import PlusIcon from '../icons/plus.svelte';
	import TrashIcon from '../icons/trash.svelte';
	import PencilEditIcon from '../icons/pencil-edit.svelte';
	import CheckCircleFill from '../icons/check-circle-fill.svelte';
	import MarkdownRenderer from '../markdown/renderer.svelte';

	let {
		personaId,
		onEdit,
		onSetDefault
	}: {
		personaId: string;
		onEdit?: (persona: UserPersona) => void;
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

	const selectedPersonaStore = SelectedPersonaStore.fromContext();

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Basic HTML sanitization to prevent XSS while preserving formatting
	function sanitizeHtml(html: string | null | undefined): string {
		if (!html) return '';

		const temp = document.createElement('div');
		temp.innerHTML = html;

		const scripts = temp.querySelectorAll('script');
		scripts.forEach((script) => script.remove());

		const allElements = temp.querySelectorAll('*');
		allElements.forEach((el) => {
			Array.from(el.attributes).forEach((attr) => {
				if (attr.name.startsWith('on')) {
					el.removeAttribute(attr.name);
				}
			});

			if (el.tagName === 'A' && el.getAttribute('href')?.startsWith('javascript:')) {
				el.removeAttribute('href');
			}
		});

		return temp.innerHTML;
	}

	async function loadPersonaData() {
		if (!personaId) return;

		isLoading = true;
		try {
			const result = await apiClient.getUserPersona(personaId);
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
		} catch (error) {
			console.error('Error loading persona:', error);
			toast.error('An unexpected error occurred');
		} finally {
			isLoading = false;
		}
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
			const updateData: any = {};

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
				const result = await apiClient.updateUserPersona(persona.id, updateData);
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
		} catch (error) {
			toast.error('Error updating persona');
			console.error('Error updating persona:', error);
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
			const result = await apiClient.deleteUserPersona(persona.id);
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
		} catch (error) {
			console.error('Error deleting persona:', error);
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
			const result = await apiClient.setDefaultPersona(persona.id);
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
		} catch (error) {
			console.error('Error setting default persona:', error);
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
</script>

<div
	class="mx-auto max-w-6xl px-4"
	in:slideAndFade={{ y: 20, duration: 300 }}
	out:slideAndFade={{ y: -20, duration: 200 }}
>
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
			<Card class="border-0 shadow-none">
				<CardHeader class="px-0">
					<div class="flex items-start space-x-6">
						<Avatar class="h-24 w-24 border-2 border-muted">
							{#if persona.avatar}
								<AvatarImage src={`${persona.avatar}?width=96&height=96`} alt={persona.name} />
							{/if}
							<AvatarFallback class="text-3xl font-semibold">
								{getInitials(persona.name)}
							</AvatarFallback>
						</Avatar>
						<div class="flex-1 space-y-4">
							<div class="relative">
								{#if !isEditMode}
									<div>
										<h2 class="text-3xl font-bold">{persona.name}</h2>
										{#if persona.description}
											<div
												class="prose prose-sm dark:prose-invert mt-2 max-w-none text-muted-foreground [&_*]:!text-muted-foreground"
											>
												<MarkdownRenderer md={persona.description} />
											</div>
										{/if}
									</div>
								{:else}
									<div class="space-y-3">
										<div>
											<Label for="edit-name" class="text-sm font-medium">Name</Label>
											<Input
												id="edit-name"
												bind:value={editedName}
												class="mt-1"
												placeholder="Persona name"
											/>
										</div>
										<div>
											<Label for="edit-description" class="text-sm font-medium">Description</Label>
											<Textarea
												id="edit-description"
												bind:value={editedDescription}
												class="mt-1"
												placeholder="Persona description"
												rows={3}
											/>
										</div>
									</div>
								{/if}
							</div>
							<div class="flex gap-2">
								{#if !isEditMode}
									<Button onclick={handleEdit} size="lg" class="gap-2">
										<PencilEditIcon class="h-4 w-4" />
										Edit Persona
									</Button>
									<Button
										onclick={handleSetDefault}
										variant="outline"
										size="lg"
										disabled={isSettingDefault}
									>
										{isSettingDefault ? 'Setting...' : 'Set as Default'}
									</Button>
									<Button onclick={handleDeleteClick} variant="destructive" size="lg">
										<TrashIcon class="h-4 w-4" />
									</Button>
								{:else}
									<Button onclick={handleSave} disabled={isSaving} size="lg" class="gap-2">
										{#if isSaving}
											<div
												class="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
											></div>
											Saving...
										{:else}
											<CheckCircleFill class="h-4 w-4" />
											Save Changes
										{/if}
									</Button>
									<Button onclick={handleCancelEdit} variant="outline" size="lg">Cancel</Button>
								{/if}
							</div>
						</div>
					</div>
				</CardHeader>

				{#if persona.scenario || persona.personality || persona.first_mes || persona.system_prompt}
					<CardContent class="space-y-4 px-0">
						{#if persona.scenario}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Scenario</h4>
								<div
									class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold prose-headings:font-bold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									<MarkdownRenderer md={persona.scenario} />
								</div>
							</div>
						{/if}
						{#if persona.personality}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Personality</h4>
								<div
									class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold prose-headings:font-bold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									<MarkdownRenderer md={persona.personality} />
								</div>
							</div>
						{/if}
						{#if persona.first_mes}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">First Message</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm italic [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									<MarkdownRenderer md={persona.first_mes} />
								</div>
							</div>
						{/if}
						{#if persona.system_prompt}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">System Prompt</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									<MarkdownRenderer md={persona.system_prompt} />
								</div>
							</div>
						{/if}
						{#if persona.mes_example}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Message Example</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									<MarkdownRenderer md={persona.mes_example} />
								</div>
							</div>
						{/if}
						{#if persona.post_history_instructions}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">
									Post-History Instructions
								</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									<MarkdownRenderer md={persona.post_history_instructions} />
								</div>
							</div>
						{/if}
					</CardContent>
				{/if}
			</Card>
		{/if}
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
