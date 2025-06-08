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
	import { Expand, X } from 'lucide-svelte';
	import type { Character } from '$lib/types';

	export let characterId: string | null = null;
	export let open = false;

	let loading = false;
	let saving = false;
	let character: Character | null = null;

	// Pop-out editor state
	let popoutEditorOpen = false;
	let popoutFieldName = '';
	let popoutFieldLabel = '';
	let popoutContent = '';
	let popoutFieldKey = '';

	// Form data with proper types
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
		definition: '',
		example_dialogue: '',
		model_prompt: '',
		user_persona: '',
		alternate_greetings: [] as string[]
	};

	// Load character data when dialog opens or characterId changes
	$: if (open && characterId) {
		loadCharacter();
	}

	async function loadCharacter() {
		if (!characterId) return;

		loading = true;
		try {
			const result = await apiClient.getCharacter(characterId);
			if (result.isOk()) {
				character = result.value;
				// Populate form with character data
				formData = {
					name: character.name || '',
					description: character.description ?? '',
					first_mes: character.first_mes ?? '',
					personality: character.personality ?? '',
					scenario: character.scenario ?? '',
					mes_example: character.mes_example ?? '',
					creator_notes: character.creator_notes ?? '',
					system_prompt: character.system_prompt ?? '',
					post_history_instructions: character.post_history_instructions ?? '',
					definition: character.definition ?? '',
					example_dialogue: character.example_dialogue ?? '',
					model_prompt: character.model_prompt ?? '',
					user_persona: character.user_persona ?? '',
					alternate_greetings: character.alternate_greetings || []
				};
			} else {
				toast.error('Failed to load character: ' + result.error.message);
				open = false;
			}
		} catch (error) {
			toast.error('Failed to load character');
			open = false;
		} finally {
			loading = false;
		}
	}

	async function handleSave() {
		if (!characterId) return;

		saving = true;
		try {
			// Filter out empty strings and create update payload
			const updateData: any = {};
			Object.entries(formData).forEach(([key, value]) => {
				if (key === 'alternate_greetings') {
					// Handle array of alternate greetings
					const greetings = (value as string[]).filter((g) => g.trim() !== '');
					if (greetings.length > 0) {
						updateData[key] = greetings;
					}
				} else if (value && typeof value === 'string' && value.trim() !== '') {
					updateData[key] = value.trim();
				}
			});

			const result = await apiClient.updateCharacter(characterId, updateData);
			if (result.isOk()) {
				toast.success('Character updated successfully');
				open = false;
			} else {
				toast.error('Failed to update character: ' + result.error.message);
			}
		} catch (error) {
			toast.error('Failed to update character');
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
			definition: '',
			example_dialogue: '',
			model_prompt: '',
			user_persona: '',
			alternate_greetings: []
		};
		character = null;
	}

	function openPopoutEditor(fieldKey: string, fieldLabel: string, greetingIndex?: number) {
		popoutFieldKey = fieldKey;
		popoutFieldName = fieldKey;
		popoutFieldLabel = fieldLabel;
		
		if (fieldKey === 'alternate_greeting' && greetingIndex !== undefined) {
			// Handle alternate greeting specifically
			popoutContent = formData.alternate_greetings[greetingIndex] || '';
			popoutFieldKey = `alternate_greeting_${greetingIndex}`;
		} else {
			popoutContent = formData[fieldKey as keyof typeof formData] as string || '';
		}
		popoutEditorOpen = true;
	}

	function savePopoutEditor() {
		if (popoutFieldKey) {
			if (popoutFieldKey.startsWith('alternate_greeting_')) {
				// Handle alternate greeting specifically
				const index = parseInt(popoutFieldKey.split('_')[2]);
				formData.alternate_greetings[index] = popoutContent;
			} else {
				(formData as any)[popoutFieldKey] = popoutContent;
			}
			popoutEditorOpen = false;
			popoutFieldKey = '';
			popoutFieldName = '';
			popoutFieldLabel = '';
			popoutContent = '';
		}
	}

	function cancelPopoutEditor() {
		popoutEditorOpen = false;
		popoutFieldKey = '';
		popoutFieldName = '';
		popoutFieldLabel = '';
		popoutContent = '';
	}
</script>

<Dialog bind:open>
	<DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
		<DialogHeader>
			<DialogTitle>Edit Character</DialogTitle>
			<DialogDescription>
				Edit the character's details. Leave fields empty to keep existing values.
			</DialogDescription>
		</DialogHeader>

		{#if loading}
			<div class="flex items-center justify-center py-8">
				<div class="h-8 w-8 animate-spin rounded-full border-b-2 border-primary"></div>
			</div>
		{:else if character}
			<div class="grid gap-4 py-4">
				<!-- Basic Information -->
				<div class="space-y-4">
					<h3 class="text-lg font-semibold">Basic Information</h3>

					<div class="grid gap-2">
						<Label for="name">Name</Label>
						<Input id="name" bind:value={formData.name} placeholder={character.name} />
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="description">Description</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('description', 'Description')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="description"
							bind:value={formData.description}
							placeholder={character.description ?? 'Character description...'}
							rows={6}
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="first_mes">First Message</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('first_mes', 'First Message')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="first_mes"
							bind:value={formData.first_mes}
							placeholder={character.first_mes ?? 'Initial greeting or first message...'}
							rows={5}
						/>
					</div>

					<!-- Alternate Greetings -->
					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label>Alternate Greetings</Label>
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
											rows={4}
											class="flex-1"
										/>
										<div class="flex flex-col gap-1">
											<Button
												type="button"
												variant="outline"
												size="icon"
												onclick={() => {
													formData.alternate_greetings = formData.alternate_greetings.filter(
														(_, i) => i !== index
													);
												}}
												class="h-8 w-8"
											>
												<X class="h-4 w-4" />
											</Button>
											<Button
												type="button"
												variant="outline"
												size="icon"
												onclick={() => openPopoutEditor('alternate_greeting', `Alternate Greeting ${index + 1}`, index)}
												class="h-8 w-8"
											>
												<Expand class="h-4 w-4" />
											</Button>
										</div>
									</div>
								{/each}
							</div>
						{:else}
							<p class="text-sm text-muted-foreground">
								No alternate greetings. Add some to give users variety!
							</p>
						{/if}
					</div>
				</div>

				<!-- Personality & Behavior -->
				<div class="space-y-4">
					<h3 class="text-lg font-semibold">Personality & Behavior</h3>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="personality">Personality</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('personality', 'Personality')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="personality"
							bind:value={formData.personality}
							placeholder={character.personality ?? 'Character personality traits...'}
							rows={6}
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="scenario">Scenario</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('scenario', 'Scenario')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="scenario"
							bind:value={formData.scenario}
							placeholder={character.scenario ?? 'Roleplay scenario...'}
							rows={6}
						/>
					</div>
				</div>

				<!-- Advanced Settings -->
				<details class="space-y-4">
					<summary class="cursor-pointer text-lg font-semibold">Advanced Settings</summary>

					<div class="mt-4 grid gap-2">
						<Label for="system_prompt">System Prompt</Label>
						<Textarea
							id="system_prompt"
							bind:value={formData.system_prompt}
							placeholder={character.system_prompt ?? 'System instructions...'}
							rows={5}
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="mes_example">Message Example</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('mes_example', 'Message Example')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="mes_example"
							bind:value={formData.mes_example}
							placeholder={character.mes_example ?? 'Example messages...'}
							rows={6}
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="definition">Definition</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('definition', 'Definition')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="definition"
							bind:value={formData.definition}
							placeholder={character.definition ?? 'Character definition...'}
							rows={8}
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="example_dialogue">Example Dialogue</Label>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('example_dialogue', 'Example Dialogue')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="example_dialogue"
							bind:value={formData.example_dialogue}
							placeholder={character.example_dialogue ?? 'Example conversations...'}
							rows={10}
						/>
					</div>

					<div class="grid gap-2">
						<Label for="model_prompt">Model Prompt</Label>
						<Textarea
							id="model_prompt"
							bind:value={formData.model_prompt}
							placeholder={character.model_prompt ?? 'Model-specific prompts...'}
							rows={5}
						/>
					</div>

					<div class="grid gap-2">
						<Label for="post_history_instructions">Post History Instructions</Label>
						<Textarea
							id="post_history_instructions"
							bind:value={formData.post_history_instructions}
							placeholder={character.post_history_instructions ??
								'Instructions after chat history...'}
							rows={5}
						/>
					</div>

					<div class="grid gap-2">
						<Label for="user_persona">User Persona</Label>
						<Textarea
							id="user_persona"
							bind:value={formData.user_persona}
							placeholder={character.user_persona ?? 'Default user persona...'}
							rows={5}
						/>
					</div>

					<div class="grid gap-2">
						<Label for="creator_notes">Creator Notes</Label>
						<Textarea
							id="creator_notes"
							bind:value={formData.creator_notes}
							placeholder={character.creator_notes ?? 'Notes from the creator...'}
							rows={4}
						/>
					</div>
				</details>
			</div>
		{/if}

		<DialogFooter>
			<Button variant="outline" onclick={handleCancel} disabled={saving}>Cancel</Button>
			<Button onclick={handleSave} disabled={saving || loading}>
				{#if saving}
					Saving...
				{:else}
					Save Changes
				{/if}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>

<!-- Pop-out Editor Dialog -->
<Dialog bind:open={popoutEditorOpen}>
	<DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-6xl">
		<DialogHeader>
			<DialogTitle>Edit {popoutFieldLabel}</DialogTitle>
			<DialogDescription>
				Edit the {popoutFieldLabel.toLowerCase()} content in a larger editor for better readability.
			</DialogDescription>
		</DialogHeader>

		<div class="py-4">
			<Textarea
				bind:value={popoutContent}
				placeholder={`Enter ${popoutFieldLabel.toLowerCase()} content...`}
				rows={20}
				class="min-h-[400px] resize-none font-mono text-sm"
			/>
		</div>

		<DialogFooter>
			<Button variant="outline" onclick={cancelPopoutEditor}>Cancel</Button>
			<Button onclick={savePopoutEditor}>Save Changes</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
