<script lang="ts">
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogHeader,
		DialogTitle,
		DialogFooter
	} from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import { createEventDispatcher } from 'svelte';

	export let open = false;

	const dispatch = createEventDispatcher();

	let saving = false;

	// Form data for new character (required fields)
	let formData = {
		name: '',
		description: '',
		first_mes: '',
		personality: '',
		scenario: '',
		mes_example: '',
		creator_notes: '',
		system_prompt: '',
		post_history_instructions: '',
		alternate_greetings: [] as string[]
	};

	async function handleCreate() {
		// Validate required fields
		if (!formData.name?.trim()) {
			toast.error('Name is required');
			return;
		}

		if (!formData.description?.trim()) {
			toast.error('Description is required');
			return;
		}

		if (!formData.first_mes?.trim()) {
			toast.error('First message is required');
			return;
		}

		saving = true;
		try {
			// Prepare data for API
			const createData: any = {
				name: formData.name.trim(),
				description: formData.description.trim(),
				first_mes: formData.first_mes.trim()
			};

			// Add optional fields if they have values
			if (formData.personality?.trim()) {
				createData.personality = formData.personality.trim();
			}
			if (formData.scenario?.trim()) {
				createData.scenario = formData.scenario.trim();
			}
			if (formData.mes_example?.trim()) {
				createData.mes_example = formData.mes_example.trim();
			}
			if (formData.creator_notes?.trim()) {
				createData.creator_notes = formData.creator_notes.trim();
			}
			if (formData.system_prompt?.trim()) {
				createData.system_prompt = formData.system_prompt.trim();
			}
			if (formData.post_history_instructions?.trim()) {
				createData.post_history_instructions = formData.post_history_instructions.trim();
			}
			// Add alternate greetings if they exist
			const validAlternateGreetings = formData.alternate_greetings.filter((g) => g.trim() !== '');
			if (validAlternateGreetings.length > 0) {
				createData.alternate_greetings = validAlternateGreetings;
			}

			const result = await apiClient.createCharacter(createData);
			if (result.isOk()) {
				toast.success('Character created successfully');
				dispatch('created', { character: result.value });
				handleCancel(); // Reset and close
			} else {
				toast.error('Failed to create character: ' + result.error.message);
			}
		} catch (error) {
			toast.error('Failed to create character');
		} finally {
			saving = false;
		}
	}

	function handleCancel() {
		open = false;
		// Reset form
		formData = {
			name: '',
			description: '',
			first_mes: '',
			personality: '',
			scenario: '',
			mes_example: '',
			creator_notes: '',
			system_prompt: '',
			post_history_instructions: '',
			alternate_greetings: []
		};
	}
</script>

<Dialog bind:open>
	<DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-[725px]">
		<DialogHeader>
			<DialogTitle>Create New Character</DialogTitle>
			<DialogDescription>
				Create a new character by filling in the details below. Name, description, and first message
				are required.
			</DialogDescription>
		</DialogHeader>

		<div class="grid gap-4 py-4">
			<!-- Basic Information (Required) -->
			<div class="space-y-4">
				<h3 class="text-lg font-semibold">Basic Information (Required)</h3>

				<div class="grid gap-2">
					<Label for="name">Name *</Label>
					<Input id="name" bind:value={formData.name} placeholder="Character name" required />
				</div>

				<div class="grid gap-2">
					<Label for="description">Description *</Label>
					<Textarea
						id="description"
						bind:value={formData.description}
						placeholder="A brief description of the character..."
						rows={3}
						required
					/>
				</div>

				<div class="grid gap-2">
					<Label for="first_mes">First Message *</Label>
					<Textarea
						id="first_mes"
						bind:value={formData.first_mes}
						placeholder="The character's initial greeting or first message..."
						rows={3}
						required
					/>
				</div>

				<!-- Alternate Greetings -->
				<div class="grid gap-2">
					<div class="flex items-center justify-between">
						<Label>Alternate Greetings (Optional)</Label>
						<Button
							type="button"
							variant="outline"
							size="sm"
							onclick={() => {
								formData.alternate_greetings = [...formData.alternate_greetings, ''];
							}}
						>
							Add Greeting
						</Button>
					</div>
					{#if formData.alternate_greetings.length > 0}
						<div class="space-y-2">
							{#each formData.alternate_greetings as greeting, index (index)}
								<div class="flex gap-2">
									<Textarea
										bind:value={formData.alternate_greetings[index]}
										placeholder={`Alternate greeting ${index + 1}...`}
										rows={2}
										class="flex-1"
									/>
									<Button
										type="button"
										variant="outline"
										size="icon"
										onclick={() => {
											formData.alternate_greetings = formData.alternate_greetings.filter(
												(_, i) => i !== index
											);
										}}
									>
										<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M6 18L18 6M6 6l12 12"
											/>
										</svg>
									</Button>
								</div>
							{/each}
						</div>
					{:else}
						<p class="text-sm text-muted-foreground">
							Add alternate greetings to give variety to the character's first message.
						</p>
					{/if}
				</div>
			</div>

			<!-- Personality & Behavior (Optional) -->
			<div class="space-y-4">
				<h3 class="text-lg font-semibold">Personality & Behavior (Optional)</h3>

				<div class="grid gap-2">
					<Label for="personality">Personality</Label>
					<Textarea
						id="personality"
						bind:value={formData.personality}
						placeholder="Character personality traits..."
						rows={3}
					/>
				</div>

				<div class="grid gap-2">
					<Label for="scenario">Scenario</Label>
					<Textarea
						id="scenario"
						bind:value={formData.scenario}
						placeholder="The roleplay scenario or setting..."
						rows={3}
					/>
				</div>
			</div>

			<!-- Advanced Settings (Optional) -->
			<details class="space-y-4">
				<summary class="cursor-pointer text-lg font-semibold">Advanced Settings (Optional)</summary>

				<div class="mt-4 grid gap-2">
					<Label for="system_prompt">System Prompt</Label>
					<Textarea
						id="system_prompt"
						bind:value={formData.system_prompt}
						placeholder="System instructions for the AI..."
						rows={3}
					/>
				</div>

				<div class="grid gap-2">
					<Label for="mes_example">Message Examples</Label>
					<Textarea
						id="mes_example"
						bind:value={formData.mes_example}
						placeholder="Example messages showing how the character speaks..."
						rows={3}
					/>
				</div>

				<div class="grid gap-2">
					<Label for="post_history_instructions">Post History Instructions</Label>
					<Textarea
						id="post_history_instructions"
						bind:value={formData.post_history_instructions}
						placeholder="Instructions that come after the chat history..."
						rows={3}
					/>
				</div>

				<div class="grid gap-2">
					<Label for="creator_notes">Creator Notes</Label>
					<Textarea
						id="creator_notes"
						bind:value={formData.creator_notes}
						placeholder="Notes about the character creation..."
						rows={3}
					/>
				</div>
			</details>
		</div>

		<DialogFooter>
			<Button variant="outline" onclick={handleCancel} disabled={saving}>Cancel</Button>
			<Button onclick={handleCreate} disabled={saving}>
				{#if saving}
					Creating...
				{:else}
					Create Character
				{/if}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
