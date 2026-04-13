<script lang="ts">
	import { createEventDispatcher, untrack } from 'svelte';
	import { goto as _goto } from '$app/navigation';
	import type { UserPersona } from '$lib/types';
	import { apiClient as _apiClient } from '$lib/api';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { getIsAuthenticated, getIsAuthReady } from '$lib/auth.svelte';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Card, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import PlusIcon from './icons/plus.svelte';
	import { slideAndFade } from '$lib/utils/transitions';

	let personas = $state<UserPersona[]>([]);
	let isLoading = $state(true);
	let error = $state<string | null>(null);
	let selectedPersonaId = $state<string | null>(null);
	let defaultPersonaId = $state<string | null>(null);

	const dispatch = createEventDispatcher();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();

	async function fetchPersonas() {
		isLoading = true;
		error = null;
		try {
			const result = await _apiClient.getUserPersonas();
			if (result.isOk()) {
				personas = result.value;
				error = null;
				// TODO: Get default persona ID from user settings
			} else {
				console.error('[PersonaList] Failed to fetch personas:', result.error);
				error = `Failed to fetch personas: ${result.error.message}`;
			}
		} catch (e: unknown) {
			if (e instanceof Error && e.message.includes('401')) {
				console.error('[PersonaList] Caught 401 during fetch, redirection initiated.');
			} else {
				console.error('[PersonaList] Failed to fetch personas:', e);
				error = 'Failed to load personas. Please try again later.';
				personas = [];
			}
		} finally {
			if (!(error === null && personas.length === 0 && !isLoading)) {
				isLoading = false;
			}
		}
	}

	// Only fetch once when auth is ready
	let hasFetched = $state(false);
	let lastProcessedTrigger = $state(0);

	// SINGLE EFFECT: Handles both initial fetch and refresh triggers
	// This prevents infinite loops by consuming the trigger value
	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();
		const trigger = selectedPersonaStore.refreshTrigger;

		// Initial fetch on auth ready
		const shouldInitialFetch = !hasFetched && authReady && authenticated;

		// Refresh only if trigger value changed (prevents infinite loop)
		const shouldRefresh =
			trigger > lastProcessedTrigger && trigger > 0 && authReady && authenticated;

		if (shouldInitialFetch || shouldRefresh) {
			console.log('[PersonaList] Fetching personas:', {
				initial: shouldInitialFetch,
				refresh: shouldRefresh,
				trigger,
				lastProcessedTrigger
			});

			untrack(() => {
				fetchPersonas();
				hasFetched = true;
				lastProcessedTrigger = trigger; // Consume the trigger to prevent re-processing
			});
		}
	});

	export async function refresh() {
		await fetchPersonas();
	}

	function handleSelect(personaId: string) {
		selectedPersonaId = personaId;
		dispatch('selectPersona', { personaId });
	}

	function handleCreateClick() {
		dispatch('createPersona');
	}

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	function getDescriptionSnippet(description: string | null): string {
		if (!description) return 'No description';
		const maxLength = 60;
		return description.length > maxLength
			? description.substring(0, maxLength) + '...'
			: description;
	}
</script>

<div class="flex h-full flex-col">
	<div class="flex items-center justify-between border-b p-2">
		<h2 class="px-2 text-lg font-semibold">Personas</h2>
		<ButtonComponent
			variant="ghost"
			size="icon"
			onclick={handleCreateClick}
			aria-label="Create Persona"
		>
			<PlusIcon class="h-5 w-5" />
		</ButtonComponent>
	</div>

	<div class="flex-1 space-y-2 overflow-y-auto p-2">
		{#if isLoading}
			{#each Array(3) as _, i (i)}
				<div class="flex items-center space-x-4 p-2">
					<Skeleton class="h-12 w-12 rounded-full" />
					<div class="flex-1 space-y-2">
						<Skeleton class="h-4 w-3/4" />
						<Skeleton class="h-4 w-1/2" />
					</div>
				</div>
			{/each}
		{:else if error}
			<p class="p-4 text-sm text-destructive">{error}</p>
		{:else if personas.length === 0}
			<div class="flex flex-col items-center justify-center gap-4 px-6 py-12 text-center">
				<div class="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
					<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
				</div>
				<div class="space-y-1">
					<p class="text-sm font-medium text-foreground">No personas yet</p>
					<p class="text-xs text-muted-foreground">Create a persona to define who you are in your stories.</p>
				</div>
				<ButtonComponent
					variant="outline"
					size="sm"
					class="rounded-full"
					onclick={handleCreateClick}
				>
					<PlusIcon class="mr-1 h-3.5 w-3.5" />
					Create Persona
				</ButtonComponent>
			</div>
		{:else}
			{#each personas as persona (persona.id)}
				{#key persona.id}
					<div
						in:slideAndFade={{ y: 20, duration: 300 }}
						out:slideAndFade={{ y: -20, duration: 200 }}
					>
						<Card
							class="cursor-pointer border-border/40 bg-muted/50 transition-all hover:border-primary hover:bg-muted/70 hover:shadow-md {selectedPersonaId ===
							persona.id
								? 'border-primary ring-2 ring-primary'
								: ''}"
							onclick={() => handleSelect(persona.id)}
							onkeydown={(e) => e.key === 'Enter' && handleSelect(persona.id)}
							tabindex={0}
							role="button"
							aria-pressed={selectedPersonaId === persona.id}
							aria-label={`Select persona ${persona.name}`}
						>
							<CardHeader class="flex flex-row items-center gap-4 p-4">
								<Avatar class="h-10 w-10">
									<AvatarFallback>{getInitials(persona.name)}</AvatarFallback>
								</Avatar>
								<div class="flex-1 overflow-hidden">
									<div class="flex items-center gap-2">
										<CardTitle class="truncate text-base">{persona.name}</CardTitle>
										{#if persona.id === defaultPersonaId}
											<span
												class="rounded-full bg-primary px-2 py-1 text-xs text-primary-foreground"
											>
												Default
											</span>
										{/if}
									</div>
									<CardDescription class="truncate text-sm">
										{getDescriptionSnippet(persona.description)}
									</CardDescription>
								</div>
							</CardHeader>
						</Card>
					</div>
				{/key}
			{/each}
		{/if}
	</div>
</div>
