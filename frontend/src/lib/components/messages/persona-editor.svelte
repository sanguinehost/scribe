<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-sonner';
	import { scale } from 'svelte/transition';
	import type { CreateUserPersonaRequest } from '$lib/api';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';

	let {
		onCancel,
		onSuccess
	}: {
		onCancel?: () => void;
		onSuccess?: () => void;
	} = $props();

	const dispatch = createEventDispatcher();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();

	let isCreating = $state(false);
	let formData = $state<CreateUserPersonaRequest>({
		name: '',
		description: '',
		personality: '',
		scenario: '',
		first_mes: '',
		mes_example: '',
		system_prompt: '',
		post_history_instructions: '',
		tags: [],
		avatar: null,
		spec: null,
		spec_version: null
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();

		if (!formData.name.trim()) {
			toast.error('Persona name is required');
			return;
		}

		if (!formData.description.trim()) {
			toast.error('Persona description is required');
			return;
		}

		isCreating = true;
		try {
			const response = await fetch('/api/personas', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(formData)
			});

			if (!response.ok) {
				if (response.status === 401) {
					console.log('Unauthorized access during persona creation, redirecting to signin.');
					await goto('/signin');
					return;
				}
				throw new Error(`HTTP error! status: ${response.status}`);
			}

			const createdPersona = await response.json();
			toast.success('Persona created successfully!');

			// Trigger refresh of persona list
			selectedPersonaStore.triggerRefresh();

			// Dispatch event to notify parent components
			dispatch('personaCreated', { persona: createdPersona });

			// Clear the creating state and optionally select the new persona
			selectedPersonaStore.clear();
			onSuccess?.();

			// Navigate back to home to show the default view
			goto('/', { invalidateAll: true });
		} catch (error: any) {
			console.error('Failed to create persona:', error);
			toast.error('Failed to create persona. Please try again.');
		} finally {
			isCreating = false;
		}
	}

	function handleCancel() {
		selectedPersonaStore.clear();
		onCancel?.();
	}
</script>

<div class="mx-auto max-w-3xl md:mt-8" transition:scale={{ opacity: 0, start: 0.98 }}>
	<Card class="mx-4">
		<CardHeader>
			<CardTitle class="flex items-center gap-2">
				<svg
					xmlns="http://www.w3.org/2000/svg"
					width="24"
					height="24"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
				>
					<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
					<circle cx="9" cy="7" r="4" />
					<line x1="19" y1="8" x2="19" y2="14" />
					<line x1="22" y1="11" x2="16" y2="11" />
				</svg>
				Create New Persona
			</CardTitle>
		</CardHeader>
		<CardContent>
			<form onsubmit={handleSubmit} class="space-y-6">
				<!-- Basic Information -->
				<div class="space-y-4">
					<h3 class="text-lg font-medium">Basic Information</h3>

					<div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
						<div class="space-y-2">
							<Label for="name">Name *</Label>
							<Input
								id="name"
								bind:value={formData.name}
								placeholder="Enter persona name..."
								required
							/>
						</div>
					</div>

					<div class="space-y-2">
						<Label for="description">Description *</Label>
						<Textarea
							id="description"
							bind:value={formData.description}
							placeholder="Describe this persona's purpose and characteristics..."
							rows={3}
							required
						/>
					</div>
				</div>

				<!-- Personality & Behavior -->
				<div class="space-y-4">
					<h3 class="text-lg font-medium">Personality & Behavior</h3>

					<div class="space-y-2">
						<Label for="personality">Personality</Label>
						<Textarea
							id="personality"
							bind:value={formData.personality}
							placeholder="Describe the personality traits, speaking style, and character..."
							rows={3}
						/>
					</div>

					<div class="space-y-2">
						<Label for="scenario">Scenario</Label>
						<Textarea
							id="scenario"
							bind:value={formData.scenario}
							placeholder="Describe the context or situation this persona operates in..."
							rows={3}
						/>
					</div>
				</div>

				<!-- Messages & Prompts -->
				<div class="space-y-4">
					<h3 class="text-lg font-medium">Messages & Prompts</h3>

					<div class="space-y-2">
						<Label for="first_mes">First Message</Label>
						<Textarea
							id="first_mes"
							bind:value={formData.first_mes}
							placeholder="The first message this persona will send..."
							rows={2}
						/>
					</div>

					<div class="space-y-2">
						<Label for="system_prompt">System Prompt</Label>
						<Textarea
							id="system_prompt"
							bind:value={formData.system_prompt}
							placeholder="System-level instructions for how this persona should behave..."
							rows={3}
						/>
					</div>

					<div class="space-y-2">
						<Label for="mes_example">Message Examples</Label>
						<Textarea
							id="mes_example"
							bind:value={formData.mes_example}
							placeholder="Example messages to help train the persona's style..."
							rows={3}
						/>
					</div>

					<div class="space-y-2">
						<Label for="post_history_instructions">Post-History Instructions</Label>
						<Textarea
							id="post_history_instructions"
							bind:value={formData.post_history_instructions}
							placeholder="Instructions to apply after the conversation history..."
							rows={2}
						/>
					</div>
				</div>

				<!-- Action Buttons -->
				<div class="flex flex-col gap-3 pt-4 sm:flex-row sm:justify-end">
					<Button type="button" variant="outline" onclick={handleCancel} disabled={isCreating}>
						Cancel
					</Button>
					<Button
						type="submit"
						disabled={isCreating || !formData.name.trim() || !formData.description.trim()}
					>
						{#if isCreating}
							<svg
								class="-ml-1 mr-2 h-4 w-4 animate-spin"
								xmlns="http://www.w3.org/2000/svg"
								fill="none"
								viewBox="0 0 24 24"
							>
								<circle
									class="opacity-25"
									cx="12"
									cy="12"
									r="10"
									stroke="currentColor"
									stroke-width="4"
								></circle>
								<path
									class="opacity-75"
									fill="currentColor"
									d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
								></path>
							</svg>
							Creating...
						{:else}
							Create Persona
						{/if}
					</Button>
				</div>
			</form>
		</CardContent>
	</Card>
</div>
