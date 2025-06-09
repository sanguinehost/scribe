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
	import { Checkbox } from '$lib/components/ui/checkbox';
	import { Separator } from '$lib/components/ui/separator';
	import { Badge } from '$lib/components/ui/badge';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import { Expand, X, Star, Heart, Globe, Plus, Trash2, HelpCircle } from 'lucide-svelte';
	import {
		Tooltip,
		TooltipProvider,
		TooltipTrigger,
		TooltipContent
	} from '$lib/components/ui/tooltip';
	import type { Character, Lorebook } from '$lib/types';
	import { writable } from 'svelte/store';
	import { tick } from 'svelte';

	export let characterId: string | null = null;
	export let open = false;

	let loading = false;
	let saving = false;
	let character: Character | null = null;
	let lorebooks = writable<Lorebook[]>([]);

	async function loadLorebooks() {
		try {
			const result = await apiClient.getLorebooks();
			if (result.isOk()) {
				lorebooks.set(result.value);
			} else {
				toast.error('Failed to load lorebooks: ' + result.error.message);
			}
		} catch (error) {
			toast.error('Failed to load lorebooks');
		}
	}

	// Pop-out editor state
	let popoutEditorOpen = false;
	let popoutFieldName = '';
	let popoutFieldLabel = '';
	let popoutContent = '';
	let popoutFieldKey = ''; // Used to store the actual formData key
	let popoutFieldType: 'text' | 'number' | 'select' = 'text'; // Added to handle different input types

	// Form data with all SillyTavern v3 fields - these SHOULD be used in backend
	let formData = {
		// Core character data (encrypted & actively used)
		name: '',
		description: '',
		first_mes: '',
		personality: '',
		scenario: '',
		mes_example: '',
		system_prompt: '',

		// Core metadata
		creator: '',
		character_version: '',
		tags: [] as string[],
		alternate_greetings: [] as string[],
		nickname: '',
		category: '',

		// SillyTavern v3 extensions
		fav: false,
		world: '', // Backward compatibility - single lorebook
		selectedLorebooks: [] as string[], // Multiple lorebooks support
		depth_prompt: '', // Character's Note content
		depth_prompt_depth: null as number | null, // Character's Note depth
		depth_prompt_role: '', // Character's Note placement role
		talkativeness: 0.5
	};

	const insertionRoles = [
		{
			value: 'system',
			label: 'System',
			description: 'Inserts the note as a system message. Good for high-level instructions.'
		},
		{
			value: 'user',
			label: 'User',
			description: 'Inserts the note as a user message. Good for simulating user replies or steering conversation.'
		},
		{
			value: 'assistant',
			label: 'Assistant',
			description: "Inserts the note as an assistant message. Good for correcting or guiding AI's previous responses."
		}
	];

	// Load character data when dialog opens or characterId changes
	$: if (open && characterId) {
		loadCharacter();
	}

	async function loadCharacter() {
		if (!characterId) return;

		loading = true;
		try {
			// Ensure lorebooks are loaded before character data to populate the dropdown correctly.
			await loadLorebooks();

			const result = await apiClient.getCharacter(characterId);
			if (result.isOk()) {
				character = result.value;
				// Wait for the DOM to update after lorebooks have been loaded.
				await tick();

				// Populate form with all character data including SillyTavern v3 fields
				formData = {
					// Core character data (encrypted & actively used)
					name: character.name || '',
					description: character.description ?? '',
					first_mes: character.first_mes ?? '',
					personality: character.personality ?? '',
					scenario: character.scenario ?? '',
					mes_example: character.mes_example ?? '',
					system_prompt: character.system_prompt ?? '',

					// Core metadata
					creator: character.creator ?? '',
					character_version: character.character_version ?? '',
					tags: character.tags?.filter((tag) => tag !== null) as string[] | [],
					alternate_greetings: character.alternate_greetings || [],
					nickname: character.nickname ?? '',
					category: character.category ?? '',

					// SillyTavern v3 extensions (need backend integration)
					fav: character.fav ?? false,
					world: character.lorebook_id ?? character.world ?? '',
					selectedLorebooks: character.lorebook_ids && character.lorebook_ids.length > 0 
						? character.lorebook_ids 
						: (character.lorebook_id ? [character.lorebook_id] : []),
					depth_prompt: character.depth_prompt ?? '',
					depth_prompt_depth: character.depth_prompt_depth ?? null,
					depth_prompt_role: character.depth_prompt_role ?? '',
					talkativeness: Number(character.talkativeness ?? 0.5)
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
			// Following the pattern from CharacterCreator.svelte to build the payload explicitly.
			const updateData: { [key: string]: any } = {};

			// Core data - only add to payload if it has a value
			if (formData.name) updateData.name = formData.name;
			if (formData.description) updateData.description = formData.description;
			if (formData.first_mes) updateData.first_mes = formData.first_mes;
			if (formData.personality) updateData.personality = formData.personality;
			if (formData.scenario) updateData.scenario = formData.scenario;
			if (formData.mes_example) updateData.mes_example = formData.mes_example;
			if (formData.system_prompt) updateData.system_prompt = formData.system_prompt;

			// Metadata
			if (formData.creator) updateData.creator = formData.creator;
			if (formData.character_version) updateData.character_version = formData.character_version;
			if (formData.nickname) updateData.nickname = formData.nickname;
			if (formData.category) updateData.category = formData.category;

			// Arrays - filter out empty strings
			const validTags = formData.tags.filter((t) => t.trim() !== '');
			if (validTags.length > 0) {
				updateData.tags = validTags;
			}
			const validGreetings = formData.alternate_greetings.filter((g) => g.trim() !== '');
			if (validGreetings.length > 0) {
				updateData.alternate_greetings = validGreetings;
			}

			// SillyTavern extensions
			updateData.fav = formData.fav; // Always send boolean
			// For backward compatibility, send the first selected lorebook as 'world'
			updateData.world = formData.selectedLorebooks.length > 0 ? formData.selectedLorebooks[0] : '';
			if (formData.depth_prompt) updateData.depth_prompt = formData.depth_prompt;
			if (formData.depth_prompt_depth !== null) updateData.depth_prompt_depth = formData.depth_prompt_depth;
			if (formData.depth_prompt_role) updateData.depth_prompt_role = formData.depth_prompt_role;
			updateData.talkativeness = formData.talkativeness; // Always send number

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
			// Core character data (encrypted & actively used)
			name: '',
			description: '',
			first_mes: '',
			personality: '',
			scenario: '',
			mes_example: '',
			system_prompt: '',

			// Core metadata
			creator: '',
			character_version: '',
			tags: [],
			alternate_greetings: [],
			nickname: '',
			category: '',

			// SillyTavern v3 extensions (need backend integration)
			fav: false,
			world: '',
			depth_prompt: '', // Character's Note
			depth_prompt_depth: null,
			depth_prompt_role: '',
			talkativeness: 0.5
		};
		character = null;
	}

	function openPopoutEditor(fieldKey: string, fieldLabel: string, greetingIndex?: number) {
		popoutFieldKey = fieldKey;
		popoutFieldName = fieldKey;
		popoutFieldLabel = fieldLabel;
		popoutFieldType = 'text'; // Default to text
		
		if (fieldKey === 'alternate_greeting' && greetingIndex !== undefined) {
			// Handle alternate greeting specifically
			popoutContent = formData.alternate_greetings[greetingIndex] || '';
			popoutFieldKey = `alternate_greeting_${greetingIndex}`;
		} else if (fieldKey === 'depth_prompt_depth') {
			popoutContent = String(formData.depth_prompt_depth ?? '');
			popoutFieldType = 'number';
		} else if (fieldKey === 'depth_prompt_role') {
			popoutContent = formData.depth_prompt_role ?? '';
			popoutFieldType = 'text'; // Or 'select' if we define options
		}
		else {
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
			} else if (popoutFieldKey === 'depth_prompt_depth') {
				formData.depth_prompt_depth = popoutContent ? Number(popoutContent) : null;
			} else if (popoutFieldKey === 'depth_prompt_role') {
				formData.depth_prompt_role = popoutContent;
			}
			else {
				(formData as any)[popoutFieldKey] = popoutContent;
			}
			popoutEditorOpen = false;
			popoutFieldKey = '';
			popoutFieldName = '';
			popoutFieldLabel = '';
			popoutContent = '';
			popoutFieldType = 'text';
		}
	}

	function cancelPopoutEditor() {
		popoutEditorOpen = false;
		popoutFieldKey = '';
		popoutFieldName = '';
		popoutFieldLabel = '';
		popoutContent = '';
		popoutFieldType = 'text';
	}

	// Tag management functions
	let newTag = '';
	
	function addTag() {
		if (newTag.trim() && !formData.tags.includes(newTag.trim())) {
			formData.tags = [...formData.tags, newTag.trim()];
			newTag = '';
		}
	}
	
	function removeTag(tagToRemove: string) {
		formData.tags = formData.tags.filter(tag => tag !== tagToRemove);
	}
	
	function handleTagKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			event.preventDefault();
			addTag();
		}
	}
</script>

<TooltipProvider>
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
				<div class="space-y-4 border-b pb-4">
					<div class="flex items-center gap-2">
						<h3 class="text-lg font-semibold">Basic Information</h3>
						<div class="flex items-center gap-2 ml-auto">
							<Tooltip>
								<TooltipTrigger>
									<Checkbox id="favorite" bind:checked={formData.fav} />
								</TooltipTrigger>
								<TooltipContent>Toggle to add or remove from favorites</TooltipContent>
							</Tooltip>
							<Label for="favorite" class="flex items-center gap-1 text-sm">
								<Heart class="h-4 w-4" />
								Favorite
							</Label>
						</div>
					</div>

					<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div class="grid gap-2">
							<Label for="name">Name</Label>
							<Input id="name" bind:value={formData.name} placeholder={character.name} />
						</div>
						<div class="grid gap-2">
							<Label for="creator">Creator</Label>
							<Input id="creator" bind:value={formData.creator} placeholder={character.creator ?? 'Anonymous'} />
						</div>
					</div>

					<div class="grid gap-2">
						<Label>Tags</Label>
						<div class="flex flex-wrap gap-2 mb-2">
							{#each formData.tags as tag}
								<Badge variant="secondary" class="flex items-center gap-1">
									{tag}
									<button type="button" onclick={() => removeTag(tag)} class="hover:text-destructive">
										<X class="h-3 w-3" />
									</button>
								</Badge>
							{/each}
						</div>
						<div class="flex gap-2">
							<Input
								bind:value={newTag}
								placeholder="Add a tag..."
								onkeydown={handleTagKeydown}
								class="flex-1"
							/>
							<Button type="button" onclick={addTag} size="sm" variant="outline">
								<Plus class="h-4 w-4" />
							</Button>
						</div>
					</div>

					<div class="grid gap-2">
						<Label for="description">Description</Label>
						<Textarea
							id="description"
							bind:value={formData.description}
							placeholder={character.description ?? 'Character description...'}
							rows={4}
						/>
					</div>

					<div class="grid gap-2">
						<Label for="first_mes">First Message</Label>
						<Textarea
							id="first_mes"
							bind:value={formData.first_mes}
							placeholder={character.first_mes ?? 'Initial greeting or first message...'}
							rows={4}
						/>
					</div>

					<div class="grid gap-2">
						<Label class="flex items-center gap-1">
							<Globe class="h-4 w-4" />
							Lorebooks
						</Label>
						<div class="rounded-md border border-input bg-transparent p-3 space-y-2 max-h-48 overflow-y-auto">
							{#if $lorebooks && $lorebooks.length > 0}
								{#each $lorebooks as lorebook}
									<div class="flex items-center space-x-2">
										<Checkbox 
											id={`lorebook-${lorebook.id}`}
											checked={formData.selectedLorebooks.includes(lorebook.id)}
											onclick={() => {
												if (formData.selectedLorebooks.includes(lorebook.id)) {
													formData.selectedLorebooks = formData.selectedLorebooks.filter(id => id !== lorebook.id);
												} else {
													formData.selectedLorebooks = [...formData.selectedLorebooks, lorebook.id];
												}
											}}
										/>
										<Label for={`lorebook-${lorebook.id}`} class="text-sm font-normal">
											{lorebook.name ?? 'Unnamed Lorebook'}
										</Label>
									</div>
								{/each}
							{:else}
								<p class="text-sm text-muted-foreground">No lorebooks available</p>
							{/if}
						</div>
						<p class="text-sm text-muted-foreground">
							Select multiple lorebooks to provide additional context for this character.
						</p>
					</div>

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

				<!-- Collapsible Sections -->
				<div class="space-y-2">
					<details class="space-y-2 border-b py-2">
						<summary class="cursor-pointer text-lg font-semibold">Definitions</summary>
						<div class="grid gap-4 pt-2">
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
							<div class="grid gap-2">
								<div class="flex items-center justify-between">
									<Label for="mes_example">Message Examples</Label>
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
						</div>
					</details>

					<details class="space-y-2 border-b py-2">
						<summary class="cursor-pointer text-lg font-semibold">Character's Note</summary>
						<div class="space-y-4 pt-2">
							<div class="rounded-md border border-l-4 border-yellow-500 bg-yellow-50 p-3 dark:bg-yellow-950">
								<p class="text-sm font-semibold text-yellow-900 dark:text-yellow-100">
									Feature Not Yet Active
								</p>
								<p class="text-sm text-yellow-800 dark:text-yellow-200">
									The Character's Note is a permanent instruction for the character. The backend logic to apply it during chats is not yet implemented, but your settings will be saved for future use.
								</p>
							</div>
							<p class="text-sm text-muted-foreground">
								Define permanent, underlying instructions for the character that apply to all conversations.
							</p>
							<div class="grid gap-2">
								<div class="flex items-center justify-between">
									<Label for="depth_prompt">Content</Label>
									<Button
										type="button"
										variant="ghost"
										size="sm"
										onclick={() => openPopoutEditor('depth_prompt', 'Character\'s Note Content')}
										class="h-6 px-2 text-xs"
									>
										Expand
									</Button>
								</div>
								<Textarea
									id="depth_prompt"
									bind:value={formData.depth_prompt}
									placeholder={character.depth_prompt ?? 'e.g., "The character is secretly a dragon."'}
									rows={3}
								/>
							</div>
							<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
								<div class="grid gap-2">
									<div class="flex items-center gap-1">
										<Label for="depth_prompt_depth">Insertion Depth</Label>
										<Tooltip>
											<TooltipTrigger class="cursor-help">
												<HelpCircle class="h-4 w-4 text-muted-foreground" />
											</TooltipTrigger>
											<TooltipContent>
												<div class="space-y-2 p-2 max-w-xs">
													<p>
														Insertion depth determines where the Character's Note is injected into the conversation history sent to the AI. It's counted from the end of the chat history.
													</p>
													<p class="font-semibold">Why use a deeper insertion?</p>
													<p>
														It makes the AI's change in behavior feel more natural. Instead of a sudden command, the instruction feels like an established fact or a thought the character has been having for a while.
													</p>
													<p class="font-semibold mt-2">Example:</p>
													<ul class="list-disc pl-4 space-y-1">
														<li>
															<strong>Depth 0:</strong> Inserting "[Character is now angry]" can feel abrupt.
														</li>
														<li>
															<strong>Depth 4:</strong> Inserting the same note 4 messages ago allows the AI to build up to the anger more organically over its next few responses.
														</li>
													</ul>
												</div>
											</TooltipContent>
										</Tooltip>
									</div>
									<Input
										id="depth_prompt_depth"
										type="number"
										bind:value={formData.depth_prompt_depth}
										placeholder={String(character.depth_prompt_depth ?? '0')}
										min="0"
									/>
									<p class="text-sm text-muted-foreground">
										How many messages from the end to insert the note before.
									</p>
								</div>
								<div class="grid gap-2">
								<div class="grid gap-2">
									<div class="flex items-center gap-1">
										<Label for="depth_prompt_role">Insertion Role</Label>
										<Tooltip>
											<TooltipTrigger class="cursor-help">
												<HelpCircle class="h-4 w-4 text-muted-foreground" />
											</TooltipTrigger>
											<TooltipContent>
												<div class="space-y-2 p-2 max-w-xs">
													{#each insertionRoles as role}
														<p><strong>{role.label}:</strong> {role.description}</p>
													{/each}
												</div>
											</TooltipContent>
										</Tooltip>
									</div>
									<select
										id="depth_prompt_role"
										bind:value={formData.depth_prompt_role}
										class="flex h-10 w-full items-center justify-between rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
									>
										<option value="" disabled>Select a role...</option>
										{#each insertionRoles as role}
											<option value={role.value}>{role.label}</option>
										{/each}
									</select>
									<p class="text-sm text-muted-foreground">
										Controls how the note is injected into the prompt.
									</p>
								</div>
							</div>
						</div>
					</details>

					<details class="space-y-2 border-b py-2">
						<summary class="cursor-pointer text-lg font-semibold">Advanced</summary>
						<div class="space-y-4 pt-2">
							<div class="grid gap-2">
								<Label for="system_prompt">System Instructions</Label>
								<Textarea
									id="system_prompt"
									bind:value={formData.system_prompt}
									placeholder={character.system_prompt ?? 'System instructions...'}
									rows={5}
								/>
							</div>
						</div>
					</details>
				</div>
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
</TooltipProvider>

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
			{#if popoutFieldType === 'text'}
				<Textarea
					bind:value={popoutContent}
					placeholder={`Enter ${popoutFieldLabel.toLowerCase()} content...`}
					rows={20}
					class="min-h-[400px] resize-none font-mono text-sm"
				/>
			{:else if popoutFieldType === 'number'}
				<Input
					type="number"
					bind:value={popoutContent}
					placeholder={`Enter ${popoutFieldLabel.toLowerCase()}...`}
					class="font-mono text-sm"
				/>
			{/if}
		</div>

		<DialogFooter>
			<Button variant="outline" onclick={cancelPopoutEditor}>Cancel</Button>
			<Button onclick={savePopoutEditor}>Save Changes</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
