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
	import * as Select from '$lib/components/ui/select';
	import { Separator } from '$lib/components/ui/separator';
	import { Badge } from '$lib/components/ui/badge';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import { Expand, X, Star, Heart, Globe, MessageSquare, Plus, Trash2 } from 'lucide-svelte';
	import {
		Tooltip,
		TooltipTrigger,
		TooltipContent,
	} from '$lib/components/ui/tooltip';
	import type { Character, Lorebook } from '$lib/types';
	import { writable } from 'svelte/store';

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
	let popoutFieldKey = '';

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
		world: '', // Lorebook reference/name
		creator_comment: '', // OOC metadata for users
		talkativeness: 0.5
	};

	// Load character data when dialog opens or characterId changes
	$: if (open && characterId) {
		loadCharacter();
		loadLorebooks();
	}

	async function loadCharacter() {
		if (!characterId) return;

		loading = true;
		try {
			const result = await apiClient.getCharacter(characterId);
			if (result.isOk()) {
				character = result.value;
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
					world: character.world ?? '',
					creator_comment: character.creator_notes ?? '',
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
			// Filter out empty strings and create update payload
			const updateData: any = {};
			Object.entries(formData).forEach(([key, value]) => {
				if (key === 'alternate_greetings') {
					// Handle array of alternate greetings
					const greetings = (value as string[]).filter((g) => g.trim() !== '');
					if (greetings.length > 0) {
						updateData[key] = greetings;
					}
				} else if (key === 'tags') {
					// Handle array of tags
					const tags = (value as string[]).filter((t) => t.trim() !== '');
					if (tags.length > 0) {
						updateData[key] = tags;
					}
				} else if (key === 'fav') {
					// Handle boolean favorite field
					updateData[key] = value;
				} else if (key === 'depth_prompt_depth' || key === 'talkativeness') {
					// Handle numeric depth field
					if (value && value !== 0) {
						updateData[key] = Number(value);
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
			creator_comment: '',
			talkativeness: 0.5
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
					<div class="flex items-center gap-2">
						<h3 class="text-lg font-semibold">Basic Information</h3>
						<div class="flex items-center gap-2 ml-auto">
							<Tooltip>
								<TooltipTrigger>
									<Checkbox id="favorite" bind:checked={formData.fav} />
								</TooltipTrigger>
								<TooltipContent>
									Toggle to add or remove from favorites
								</TooltipContent>
							</Tooltip>
							<Label for="favorite" class="flex items-center gap-1 text-sm">
								<Heart class="h-4 w-4" />
									Favorite
							</Label>
						</div>
					</div>

					<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div class="grid gap-2">
							<Tooltip>
								<TooltipTrigger>
									<Label for="name">Name</Label>
								</TooltipTrigger>
								<TooltipContent>
									The character's name.
								</TooltipContent>
							</Tooltip>
							<Input id="name" bind:value={formData.name} placeholder={character.name} />
						</div>

						<div class="grid gap-2">
							<Tooltip>
								<TooltipTrigger>
									<Label for="creator">Creator</Label>
								</TooltipTrigger>
								<TooltipContent>
									The character's creator.
								</TooltipContent>
							</Tooltip>
							<Input id="creator" bind:value={formData.creator} placeholder={character.creator ?? 'Anonymous'} />
						</div>
					</div>

					<div class="grid gap-2">
						<Label for="character_version">Version</Label>
						<Input id="character_version" bind:value={formData.character_version} placeholder={character.character_version ?? '1.0'} />
					</div>

					<!-- Tags Section -->
					<div class="grid gap-2">
						<Tooltip>
							<TooltipTrigger>
								<Label>Tags</Label>
							</TooltipTrigger>
							<TooltipContent>
								Tags to categorize the character.
							</TooltipContent>
						</Tooltip>
						<div class="flex flex-wrap gap-2 mb-2">
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
							<Tooltip>
								<TooltipTrigger>
									<Label for="description">Description</Label>
								</TooltipTrigger>
								<TooltipContent>
									A brief description of the character.
								</TooltipContent>
							</Tooltip>
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
							<Tooltip>
								<TooltipTrigger>
									<Label for="first_mes">First Message</Label>
								</TooltipTrigger>
								<TooltipContent>
									The character's initial greeting or first message.
								</TooltipContent>
							</Tooltip>
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
							<Tooltip>
								<TooltipTrigger>
									<Label>Alternate Greetings</Label>
								</TooltipTrigger>
								<TooltipContent>
									Alternate greetings the character can use.
								</TooltipContent>
							</Tooltip>
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
							<Tooltip>
								<TooltipTrigger>
									<Label for="personality">Personality</Label>
								</TooltipTrigger>
								<TooltipContent>
									The character's personality traits.
								</TooltipContent>
							</Tooltip>
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
							<Tooltip>
								<TooltipTrigger>
									<Label for="scenario">Scenario</Label>
								</TooltipTrigger>
								<TooltipContent>
									The roleplay scenario.
								</TooltipContent>
							</Tooltip>
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

				<!-- World & SillyTavern v3 Settings -->
				<div class="space-y-4">
					<h3 class="text-lg font-semibold">World & Context</h3>
					
					<!-- World -->
					<div class="grid gap-2">
						<Tooltip>
							<TooltipTrigger>
								<Label for="world" class="flex items-center gap-1">
									<Globe class="h-4 w-4" />
									World/Lorebook
								</Label>
							</TooltipTrigger>
							<TooltipContent>
								Reference to an associated lorebook for this character
							</TooltipContent>
						</Tooltip>
						<Select.Root
							onValueChange={(v) => {
								if (v) {
									formData.world = v;
								}
							}}
							value={formData.world}
						>
							<Select.Trigger class="w-full">
								<Select.Value placeholder="Select a lorebook" />
							</Select.Trigger>
							<Select.Content>
								{#each $lorebooks as lorebook}
									<Select.Item value={lorebook.id}
										>{lorebook.name ?? 'Unnamed Lorebook'}</Select.Item
									>
								{/each}
							</Select.Content>
						</Select.Root>
						<p class="text-sm text-muted-foreground">
							Reference to an associated lorebook for this character
						</p>
					</div>

					<!-- Creator Comment -->
					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Tooltip>
								<TooltipTrigger>
									<Label for="creator_comment" class="flex items-center gap-1">
										<MessageSquare class="h-4 w-4" />
										Creator Comment
									</Label>
								</TooltipTrigger>
								<TooltipContent>
									Notes from the character creator.
								</TooltipContent>
							</Tooltip>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onclick={() => openPopoutEditor('creator_comment', 'Creator Comment')}
								class="h-6 px-2 text-xs"
							>
								Expand
							</Button>
						</div>
						<Textarea
							id="creator_comment"
							bind:value={formData.creator_comment}
							placeholder={character.creator_comment ?? 'Notes from the character creator...'}
							rows={3}
						/>
					</div>

					<!-- Talkativeness -->
					<div class="grid gap-2">
						<Tooltip>
							<TooltipTrigger>
								<Label for="talkativeness">Talkativeness</Label>
							</TooltipTrigger>
							<TooltipContent>
								Controls how talkative the character is. 0.0 is mute, 1.0 is very talkative.
							</TooltipContent>
						</Tooltip>
						<Input
							id="talkativeness"
							type="number"
							bind:value={formData.talkativeness}
							placeholder={character.talkativeness ?? '0.5'}
							step="0.05"
							min="0"
							max="1"
						/>
						<p class="text-sm text-muted-foreground">
							Controls how talkative the character is. 0.0 is mute, 1.0 is very talkative.
						</p>
					</div>
				</div>

				<!-- Advanced Settings -->
				<details class="space-y-4">
					<summary class="cursor-pointer text-lg font-semibold">Advanced Settings</summary>

					<div class="mt-4 grid gap-2">
						<Tooltip>
							<TooltipTrigger>
								<Label for="system_prompt">System Prompt</Label>
							</TooltipTrigger>
							<TooltipContent>
								System instructions for the AI.
							</TooltipContent>
						</Tooltip>
						<Textarea
							id="system_prompt"
							bind:value={formData.system_prompt}
							placeholder={character.system_prompt ?? 'System instructions...'}
							rows={5}
						/>
					</div>

					<div class="grid gap-2">
						<div class="flex items-center justify-between">
							<Tooltip>
								<TooltipTrigger>
									<Label for="mes_example">Message Example</Label>
								</TooltipTrigger>
								<TooltipContent>
									Example messages the character can use.
								</TooltipContent>
							</Tooltip>
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
