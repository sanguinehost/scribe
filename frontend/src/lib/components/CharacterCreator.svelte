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
	import { Badge } from '$lib/components/ui/badge';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import { Expand, X, Heart, Globe, Plus, HelpCircle } from 'lucide-svelte';
	import AiAssistantWidget from './ai-assistant-widget.svelte';
	import {
		Tooltip,
		TooltipProvider,
		TooltipTrigger,
		TooltipContent
	} from '$lib/components/ui/tooltip';
	import type { CharacterDataForClient, Lorebook } from '$lib/types';
	import { writable } from 'svelte/store';
	import { createEventDispatcher, onMount } from 'svelte';

const depthPromptPlaceholder = 'e.g., "The character is secretly a dragon."';

	export let open = false;

	const dispatch = createEventDispatcher();

	let saving = false;
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

	onMount(() => {
		loadLorebooks();
	});

	// Pop-out editor state
	let popoutEditorOpen = false;
	let popoutFieldName = '';
	let popoutFieldLabel = '';
	let popoutContent = '';
	let popoutFieldKey = ''; // Used to store the actual formData key
	let popoutFieldType: 'text' | 'number' | 'select' = 'text';

	// Form data with all SillyTavern v3 fields
	let formData = {
		// Core character data
		name: '',
		description: '',
		first_mes: '',
		personality: '',
		scenario: '',
		mes_example: '',
		system_prompt: '',

		// Core metadata
		creator: '',
		character_version: '1.0', // Default for new characters
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
			description:
				'Inserts the note as a user message. Good for simulating user replies or steering conversation.'
		},
		{
			value: 'assistant',
			label: 'Assistant',
			description:
				"Inserts the note as an assistant message. Good for correcting or guiding AI's previous responses."
		}
	];

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
			const validTags = formData.tags.filter((t) => t.trim() !== '');
			const validGreetings = formData.alternate_greetings.filter((g) => g.trim() !== '');

			// Construct a type-safe object for the API call.
			// Use Partial because most fields are optional on creation.
			const createData: Partial<CharacterDataForClient> = {
				spec: 'character_card_v2',
				spec_version: '2.0',
				name: formData.name.trim(),
				description: formData.description.trim(),
				first_mes: formData.first_mes.trim(),
				personality: formData.personality.trim() || undefined,
				scenario: formData.scenario.trim() || undefined,
				mes_example: formData.mes_example.trim() || undefined,
				system_prompt: formData.system_prompt.trim() || undefined,
				creator: formData.creator.trim() || undefined,
				character_version: formData.character_version.trim() || undefined,
				tags: validTags,
				alternate_greetings: validGreetings,
				nickname: formData.nickname.trim() || undefined,
				category: formData.category.trim() || undefined,
				fav: formData.fav,
				world: formData.selectedLorebooks.length > 0 ? formData.selectedLorebooks[0] : undefined,
				depth_prompt: formData.depth_prompt.trim() || undefined,
				depth_prompt_depth: formData.depth_prompt_depth,
				depth_prompt_role: formData.depth_prompt_role.trim() || undefined,
				talkativeness: String(formData.talkativeness)
			};

			// The API client expects more fields than are needed for creation.
			// We cast to `any` to bypass the strict client-side type check.
			// The backend will correctly handle the partial data.
			const result = await apiClient.createCharacter(createData as any);
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
			system_prompt: '',
			creator: '',
			character_version: '1.0',
			tags: [],
			alternate_greetings: [],
			nickname: '',
			category: '',
			fav: false,
			world: '',
			selectedLorebooks: [],
			depth_prompt: '',
			depth_prompt_depth: null,
			depth_prompt_role: '',
			talkativeness: 0.5
		};
	}

	// Helper function to build complete character context for AI generation
	function buildCharacterContext(excludeGreetingIndex?: number) {
		return {
			name: formData.name,
			description: formData.description,
			personality: formData.personality,
			scenario: formData.scenario,
			first_mes: formData.first_mes,
			mes_example: formData.mes_example,
			system_prompt: formData.system_prompt,
			depth_prompt: formData.depth_prompt,
			tags: formData.tags,
			alternate_greetings: excludeGreetingIndex !== undefined 
				? formData.alternate_greetings.filter((_, i) => i !== excludeGreetingIndex)
				: formData.alternate_greetings,
			selectedLorebooks: formData.selectedLorebooks // Pass selected lorebook IDs
		};
	}

	function openPopoutEditor(fieldKey: string, fieldLabel: string, greetingIndex?: number) {
		popoutFieldKey = fieldKey;
		popoutFieldName = fieldKey;
		popoutFieldLabel = fieldLabel;
		popoutFieldType = 'text'; // Default to text

		if (fieldKey === 'alternate_greeting' && greetingIndex !== undefined) {
			popoutContent = formData.alternate_greetings[greetingIndex] || '';
			popoutFieldKey = `alternate_greeting_${greetingIndex}`;
		} else if (fieldKey === 'depth_prompt_depth') {
			popoutContent = String(formData.depth_prompt_depth ?? '');
			popoutFieldType = 'number';
		} else if (fieldKey === 'depth_prompt_role') {
			popoutContent = formData.depth_prompt_role ?? '';
			popoutFieldType = 'text';
		} else {
			popoutContent = (formData[fieldKey as keyof typeof formData] as string) || '';
		}
		popoutEditorOpen = true;
	}

	function savePopoutEditor() {
		if (popoutFieldKey) {
			if (popoutFieldKey.startsWith('alternate_greeting_')) {
				const index = parseInt(popoutFieldKey.split('_')[2]);
				formData.alternate_greetings[index] = popoutContent;
			} else if (popoutFieldKey === 'depth_prompt_depth') {
				formData.depth_prompt_depth = popoutContent ? Number(popoutContent) : null;
			} else if (popoutFieldKey === 'depth_prompt_role') {
				formData.depth_prompt_role = popoutContent;
			} else {
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
		formData.tags = formData.tags.filter((tag) => tag !== tagToRemove);
	}

	function handleTagKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			event.preventDefault();
			addTag();
		}
	}
</script>

<Dialog bind:open>
	<TooltipProvider>
		<DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
			<DialogHeader>
				<DialogTitle>Create New Character</DialogTitle>
				<DialogDescription>
					Create a new character by filling in the details below. Name, description, and first
					message are required.
				</DialogDescription>
			</DialogHeader>

			<div class="grid gap-4 py-4">
				<!-- Basic Information -->
				<div class="space-y-4 border-b pb-4">
					<div class="flex items-center gap-2">
						<h3 class="text-lg font-semibold">Basic Information</h3>
						<div class="ml-auto flex items-center gap-2">
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

					<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
						<div class="grid gap-2">
							<Label for="name">Name *</Label>
							<Input id="name" bind:value={formData.name} placeholder="Character Name" required />
						</div>
						<div class="grid gap-2">
							<Label for="creator">Creator</Label>
							<Input id="creator" bind:value={formData.creator} placeholder="Your Name" />
						</div>
					</div>

					<div class="grid gap-2">
						<Label>Tags</Label>
						<div class="mb-2 flex flex-wrap gap-2">
							{#each formData.tags as tag}
								<Badge variant="secondary" class="flex items-center gap-1">
									{tag}
									<button
										type="button"
										onclick={() => removeTag(tag)}
										class="hover:text-destructive"
									>
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
						<div class="flex items-center justify-between">
							<Label for="description">Description *</Label>
							<AiAssistantWidget
								fieldName="description"
								fieldValue={formData.description}
								characterContext={buildCharacterContext()}
								onGenerated={(text) => {
									formData.description = text;
								}}
								variant="compact"
							/>
						</div>
						<Textarea
							id="description"
							bind:value={formData.description}
							placeholder="A brief description of the character..."
							rows={4}
							required
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Label for="first_mes">First Message *</Label>
							<AiAssistantWidget
								fieldName="first_mes"
								fieldValue={formData.first_mes}
								characterContext={buildCharacterContext()}
								onGenerated={(text) => {
									formData.first_mes = text;
								}}
								variant="compact"
							/>
						</div>
						<Textarea
							id="first_mes"
							bind:value={formData.first_mes}
							placeholder="The character's initial greeting or first message..."
							rows={4}
							required
						/>
					</div>

					<div class="grid gap-2">
						<Label class="flex items-center gap-1">
							<Globe class="h-4 w-4" />
							Lorebooks
						</Label>
						<div
							class="max-h-48 space-y-2 overflow-y-auto rounded-md border border-input bg-transparent p-3"
						>
							{#if $lorebooks && $lorebooks.length > 0}
								{#each $lorebooks as lorebook}
									<div class="flex items-center space-x-2">
										<Checkbox
											id={`lorebook-${lorebook.id}`}
											checked={formData.selectedLorebooks.includes(lorebook.id)}
											on:change={(event) => {
												const isChecked = event.detail;
												
												if (isChecked) {
													formData.selectedLorebooks = [...formData.selectedLorebooks, lorebook.id];
												} else {
													formData.selectedLorebooks = formData.selectedLorebooks.filter(
														(id) => id !== lorebook.id
													);
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
										<div class="flex-1 space-y-2">
											<div class="flex items-center justify-between">
												<span class="text-sm font-medium">Greeting {index + 1}</span>
												<AiAssistantWidget
													fieldName={`alternate_greeting_${index + 1}`}
													fieldValue={formData.alternate_greetings[index]}
													characterContext={buildCharacterContext(index)}
													onGenerated={(text) => {
														formData.alternate_greetings[index] = text;
													}}
													variant="compact"
												/>
											</div>
											<Textarea
												bind:value={formData.alternate_greetings[index]}
												placeholder={`Alternate greeting ${index + 1}...`}
												rows={4}
												class="w-full"
											/>
										</div>
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
												onclick={() =>
													openPopoutEditor(
														'alternate_greeting',
														`Alternate Greeting ${index + 1}`,
														index
													)}
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
									<div class="flex items-center gap-1">
										<AiAssistantWidget
											fieldName="personality"
											fieldValue={formData.personality}
											characterContext={buildCharacterContext()}
											onGenerated={(text) => {
												formData.personality = text;
											}}
											variant="compact"
										/>
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
								</div>
								<Textarea
									id="personality"
									bind:value={formData.personality}
									placeholder="Character personality traits..."
									rows={6}
								/>
							</div>
							<div class="grid gap-2">
								<div class="flex items-center justify-between">
									<Label for="scenario">Scenario</Label>
									<div class="flex items-center gap-1">
										<AiAssistantWidget
											fieldName="scenario"
											fieldValue={formData.scenario}
											characterContext={buildCharacterContext()}
											onGenerated={(text) => {
												formData.scenario = text;
											}}
											variant="compact"
										/>
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
								</div>
								<Textarea
									id="scenario"
									bind:value={formData.scenario}
									placeholder="Roleplay scenario..."
									rows={6}
								/>
							</div>
							<div class="grid gap-2">
								<div class="flex items-center justify-between">
									<Label for="mes_example">Message Examples</Label>
									<div class="flex items-center gap-1">
										<AiAssistantWidget
											fieldName="mes_example"
											fieldValue={formData.mes_example}
											characterContext={buildCharacterContext()}
											onGenerated={(text) => {
												formData.mes_example = text;
											}}
											variant="compact"
										/>
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
								</div>
								<Textarea
									id="mes_example"
									bind:value={formData.mes_example}
									placeholder="Example messages..."
									rows={6}
								/>
							</div>
						</div>
					</details>

					<details class="space-y-2 border-b py-2">
						<summary class="cursor-pointer text-lg font-semibold">Character's Note</summary>
						<div class="space-y-4 pt-2">
							<div
								class="rounded-md border border-l-4 border-yellow-500 bg-yellow-50 p-3 dark:bg-yellow-950"
							>
								<p class="text-sm font-semibold text-yellow-900 dark:text-yellow-100">
									Feature Not Yet Active
								</p>
								<p class="text-sm text-yellow-800 dark:text-yellow-200">
									The Character's Note is a permanent instruction for the character. The backend
									logic to apply it during chats is not yet implemented, but your settings will be
									saved for future use.
								</p>
							</div>
							<p class="text-sm text-muted-foreground">
								Define permanent, underlying instructions for the character that apply to all
								conversations.
							</p>
							<div class="grid gap-2">
								<div class="flex items-center justify-between">
									<Label for="depth_prompt">Content</Label>
									<div class="flex items-center gap-1">
										<AiAssistantWidget
											fieldName="depth_prompt"
											fieldValue={formData.depth_prompt}
											characterContext={buildCharacterContext()}
											onGenerated={(text) => {
												formData.depth_prompt = text;
											}}
											variant="compact"
										/>
										<Button
											type="button"
											variant="ghost"
											size="sm"
											onclick={() => openPopoutEditor('depth_prompt', "Character's Note Content")}
											class="h-6 px-2 text-xs"
										>
											Expand
										</Button>
									</div>
								</div>
								<Textarea
									id="depth_prompt"
									bind:value={formData.depth_prompt}
									placeholder={depthPromptPlaceholder}
									rows={3}
								/>
							</div>
							<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
								<div class="grid gap-2">
									<div class="flex items-center gap-1">
										<Label for="depth_prompt_depth">Insertion Depth</Label>
										<Tooltip>
											<TooltipTrigger class="cursor-help">
												<HelpCircle class="h-4 w-4 text-muted-foreground" />
											</TooltipTrigger>
											<TooltipContent>
												<div class="max-w-xs space-y-2 p-2">
													<p>
														Insertion depth determines where the Character's Note is injected into
														the conversation history sent to the AI. It's counted from the end of
														the chat history.
													</p>
													<p class="font-semibold">Why use a deeper insertion?</p>
													<p>
														It makes the AI's change in behavior feel more natural. Instead of a
														sudden command, the instruction feels like an established fact or a
														thought the character has been having for a while.
													</p>
													<p class="mt-2 font-semibold">Example:</p>
													<ul class="list-disc space-y-1 pl-4">
														<li>
															<strong>Depth 0:</strong> Inserting "[Character is now angry]" can feel
															abrupt.
														</li>
														<li>
															<strong>Depth 4:</strong> Inserting the same note 4 messages ago allows
															the AI to build up to the anger more organically over its next few responses.
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
										placeholder="0"
										min="0"
									/>
									<p class="text-sm text-muted-foreground">
										How many messages from the end to insert the note before.
									</p>
								</div>
								<div class="grid gap-2">
									<div class="flex items-center gap-1">
										<Label for="depth_prompt_role">Insertion Role</Label>
										<Tooltip>
											<TooltipTrigger class="cursor-help">
												<HelpCircle class="h-4 w-4 text-muted-foreground" />
											</TooltipTrigger>
											<TooltipContent>
												<div class="max-w-xs space-y-2 p-2">
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
								<div class="flex items-center justify-between">
									<Label for="system_prompt">System Instructions</Label>
									<AiAssistantWidget
										fieldName="system_prompt"
										fieldValue={formData.system_prompt}
										characterContext={buildCharacterContext()}
										onGenerated={(text) => {
											formData.system_prompt = text;
										}}
										variant="compact"
									/>
								</div>
								<Textarea
									id="system_prompt"
									bind:value={formData.system_prompt}
									placeholder="System instructions..."
									rows={5}
								/>
							</div>
						</div>
					</details>
				</div>
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
	</TooltipProvider>
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
