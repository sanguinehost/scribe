<script lang="ts">
	import { onMount } from 'svelte';
	import { apiClient } from '$lib/api';
	import type { UserPersona } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { scale } from 'svelte/transition';
	import { Button } from '$lib/components/ui/button';
	import {
		Card,
		CardHeader,
		CardTitle,
		CardDescription,
		CardContent
	} from '$lib/components/ui/card';
	import { Avatar, AvatarFallback } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
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
		if (persona && onEdit) {
			onEdit(persona);
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

	onMount(() => {
		loadPersonaData();
	});
</script>

<div class="mx-auto max-w-4xl px-4" transition:scale={{ opacity: 0, start: 0.98 }}>
	<div class="space-y-6">
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
							<AvatarFallback class="text-3xl font-semibold">
								{getInitials(persona.name)}
							</AvatarFallback>
						</Avatar>
						<div class="flex-1 space-y-4">
							<div>
								<h2 class="text-3xl font-bold">{persona.name}</h2>
								{#if persona.description}
									<p class="mt-2 text-muted-foreground">
										{persona.description}
									</p>
								{/if}
							</div>
							<div class="flex gap-2">
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
									{@html sanitizeHtml(persona.scenario)}
								</div>
							</div>
						{/if}
						{#if persona.personality}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Personality</h4>
								<div
									class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold prose-headings:font-bold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									{@html sanitizeHtml(persona.personality)}
								</div>
							</div>
						{/if}
						{#if persona.first_mes}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">First Message</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm italic [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									{@html sanitizeHtml(persona.first_mes)}
								</div>
							</div>
						{/if}
						{#if persona.system_prompt}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">System Prompt</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									{@html sanitizeHtml(persona.system_prompt)}
								</div>
							</div>
						{/if}
						{#if persona.mes_example}
							<div class="rounded-lg bg-muted/50 p-4">
								<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Message Example</h4>
								<div
									class="prose prose-sm dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
								>
									{@html sanitizeHtml(persona.mes_example)}
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
									{@html sanitizeHtml(persona.post_history_instructions)}
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
