<script lang="ts">
	import { onMount, createEventDispatcher } from 'svelte';
	import { goto } from '$app/navigation';
	import type { UserPersona } from '$lib/api';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import PlusIcon from './icons/plus.svelte';

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
			const response = await fetch('/api/personas');
			if (!response.ok) {
				// Check specifically for 401 Unauthorized
				if (response.status === 401) {
					console.log('Unauthorized access to personas, emitting auth:invalidated event.');
					window.dispatchEvent(new CustomEvent('auth:invalidated'));
					return;
				}
				throw new Error(`HTTP error! status: ${response.status}`);
			}
			personas = await response.json();
			error = null;
			// TODO: Get default persona ID from user settings
		} catch (e: any) {
			if (e instanceof Error && e.message.includes('401')) {
				console.error('Caught 401 during fetch, redirection initiated.');
			} else {
				console.error('Failed to fetch personas:', e);
				error = 'Failed to load personas. Please try again later.';
				personas = [];
			}
		} finally {
			if (!(error === null && personas.length === 0 && !isLoading)) {
				isLoading = false;
			}
		}
	}

	onMount(async () => {
		await fetchPersonas();
	});

	// Watch for refresh triggers from the store
	$effect(() => {
		// This will run whenever refreshTrigger changes
		if (selectedPersonaStore.refreshTrigger > 0) {
			fetchPersonas();
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
		<Button variant="ghost" size="icon" onclick={handleCreateClick} aria-label="Create Persona">
			<PlusIcon class="h-5 w-5" />
		</Button>
	</div>

	<div class="flex-1 space-y-2 overflow-y-auto p-2">
		{#if isLoading}
			{#each Array(3) as _}
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
			<p class="p-4 text-sm text-muted-foreground">
				No personas found. Create one to customize your interaction style!
			</p>
		{:else}
			{#each personas as persona (persona.id)}
				<Card
					class="cursor-pointer transition-all hover:border-primary hover:shadow-md {selectedPersonaId ===
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
									<span class="rounded-full bg-primary px-2 py-1 text-xs text-primary-foreground">
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
			{/each}
		{/if}
	</div>
</div>
