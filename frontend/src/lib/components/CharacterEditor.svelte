<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Card from '$lib/components/ui/card';
	import Button from '$lib/components/ui/button/button.svelte';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';

	import BasicInfoEditor from '$lib/components/character/BasicInfoEditor.svelte';
	import GreetingsEditor from '$lib/components/character/GreetingsEditor.svelte';
	import DefinitionsEditor from '$lib/components/character/DefinitionsEditor.svelte';
	import AssetsEditor from '$lib/components/character/AssetsEditor.svelte';
	import AdvancedEditor from '$lib/components/character/AdvancedEditor.svelte';
	import LorebookEditor from '$lib/components/character/LorebookEditor.svelte';
	import CharacterPreview from '$lib/components/shared/CharacterPreview.svelte';
	import UnsavedChangesDialog from '$lib/components/shared/UnsavedChangesDialog.svelte';
	import NarrativeStyleConfigurator from '$lib/components/settings/NarrativeStyleConfigurator.svelte';
	import type { Character } from '$lib/types';
	import type { CharacterCardV3 } from '$lib/types/character';
	import { createEventDispatcher } from 'svelte';

	// Props
	interface Props {
		open?: boolean;
		character?: Character;
		onOpenChange?: (open: boolean) => void;
	}

	let { open = $bindable(false), character, onOpenChange }: Props = $props();

	const dispatch = createEventDispatcher();

	let isSaving = $state(false);
	let currentTab = $state('basic');
	let showConfirmClose = $state(false);

	// Load character into store when dialog opens or character changes
	$effect(() => {
		if (open && character) {
			// Prepare avatar as an asset if it exists
			const avatarUrl = character.avatar || character.avatar_url;
			const assets = [];

			if (avatarUrl) {
				// Determine extension from URL or data URL
				let ext = 'png'; // default
				if (avatarUrl.startsWith('data:image/')) {
					const match = avatarUrl.match(/data:image\/(\w+);/);
					ext = match ? match[1] : 'png';
				} else {
					const urlMatch = avatarUrl.match(/\.(\w+)(?:\?|$)/);
					ext = urlMatch ? urlMatch[1] : 'png';
				}

				assets.push({
					type: 'icon',
					uri: avatarUrl,
					name: 'main',
					ext: ext
				});
			}

			// Convert scribe's character format to V3 format for editing
			const v3Character: CharacterCardV3 = {
				spec: 'chara_card_v3',
				spec_version: '3.0',
				data: {
					name: character.name || '',
					description: character.description || '',
					personality: character.personality || '',
					scenario: character.scenario || '',
					first_mes: character.first_mes || '',
					mes_example: character.mes_example || '',
					creator_notes: '',
					system_prompt: character.system_prompt || '',
					post_history_instructions: character.post_history_instructions || '',
					alternate_greetings: (character.alternate_greetings || []).filter(
						(g): g is string => g !== null
					),
					tags: (character.tags || []).filter((t): t is string => t !== null),
					creator: character.creator || '',
					character_version: character.character_version || '',
					nickname: character.nickname || undefined,
					group_only_greetings: [],
					extensions:
						(character.extensions as Record<string, unknown>) || ({} as Record<string, unknown>),
					assets: assets.length > 0 ? assets : undefined
				}
			};
			characterStore.load(v3Character);

			// Load avatar if it exists
			if (avatarUrl) {
				characterStore.setBaseImage(avatarUrl);
			}
		}
	});

	function handleClose() {
		// Check for unsaved changes before closing
		if (characterStore.hasChanges) {
			showConfirmClose = true;
			return;
		}
		actuallyClose();
	}

	function actuallyClose() {
		if (onOpenChange) {
			onOpenChange(false);
		} else {
			open = false;
		}
		// Clear store on close
		characterStore.clear();
		showConfirmClose = false;
	}

	function handleConfirmSave() {
		// Trigger the save action
		handleSave();
	}

	function handleConfirmDiscard() {
		actuallyClose();
	}

	function handleConfirmCancel() {
		showConfirmClose = false;
	}

	async function handleSave() {
		if (!characterStore.character || !character) return;

		const editedCharacter = characterStore.character;

		// Validate required fields
		if (!editedCharacter.data.name?.trim()) {
			toast.error('Name is required');
			return;
		}
		if (!editedCharacter.data.description?.trim()) {
			toast.error('Description is required');
			return;
		}
		if (!editedCharacter.data.first_mes?.trim()) {
			toast.error('First message is required');
			return;
		}

		isSaving = true;
		try {
			// Convert V3 format back to scribe's backend format
			const updateData = {
				spec: 'character_card_v2',
				spec_version: '2.0',
				name: editedCharacter.data.name.trim(),
				description: editedCharacter.data.description.trim(),
				first_mes: editedCharacter.data.first_mes.trim(),
				personality: editedCharacter.data.personality?.trim() || undefined,
				scenario: editedCharacter.data.scenario?.trim() || undefined,
				mes_example: editedCharacter.data.mes_example?.trim() || undefined,
				system_prompt: editedCharacter.data.system_prompt?.trim() || undefined,
				creator: editedCharacter.data.creator?.trim() || undefined,
				character_version: editedCharacter.data.character_version?.trim() || undefined,
				tags: editedCharacter.data.tags || [],
				alternate_greetings: editedCharacter.data.alternate_greetings || [],
				nickname: editedCharacter.data.nickname?.trim() || undefined,
				extensions: editedCharacter.data.extensions || {}
			};

			const result = await apiClient.updateCharacter(
				character.id,
				updateData as Partial<Character>
			);
			if (result.isOk()) {
				toast.success('Character updated successfully');
				dispatch('updated', { character: result.value });
				actuallyClose();
			} else {
				toast.error('Failed to update character: ' + result.error.message);
			}
		} catch (error) {
			toast.error('Failed to update character');
			console.error('Character update error:', error);
		} finally {
			isSaving = false;
		}
	}
</script>

<Dialog.Root {open} onOpenChange={(isOpen) => !isOpen && handleClose()}>
	<Dialog.Portal>
		<Dialog.Overlay />
		<Dialog.Content class="flex max-h-[95vh] max-w-[95vw] flex-col overflow-hidden p-0">
			<Dialog.Header class="border-b px-6 pb-4 pt-6">
				<Dialog.Title>Edit Character</Dialog.Title>
				<Dialog.Description>Update your character with the full-featured editor</Dialog.Description>
			</Dialog.Header>

			<div class="flex-1 overflow-y-auto px-6 py-4">
				<div class="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_400px]">
					<!-- Editor Panel -->
					<div>
						<Tabs.Root bind:value={currentTab} class="w-full">
							<Tabs.List class="grid w-full grid-cols-7">
								<Tabs.Trigger value="basic">Basic Info</Tabs.Trigger>
								<Tabs.Trigger value="greetings">Greetings</Tabs.Trigger>
								<Tabs.Trigger value="definitions">Definitions</Tabs.Trigger>
								<Tabs.Trigger value="lorebook">Lorebook</Tabs.Trigger>
								<Tabs.Trigger value="assets">Assets</Tabs.Trigger>
								<Tabs.Trigger value="writingstyle">Writing Style</Tabs.Trigger>
								<Tabs.Trigger value="advanced">Advanced</Tabs.Trigger>
							</Tabs.List>

							<div class="mt-4">
								<Tabs.Content value="basic" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Basic Information</Card.Title>
											<Card.Description>Core character details and metadata</Card.Description>
										</Card.Header>
										<Card.Content>
											<BasicInfoEditor />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>

								<Tabs.Content value="greetings" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Greetings</Card.Title>
											<Card.Description>First message and alternate greetings</Card.Description>
										</Card.Header>
										<Card.Content>
											<GreetingsEditor />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>

								<Tabs.Content value="definitions" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Character Definitions</Card.Title>
											<Card.Description>
												Personality, scenario, and example messages
											</Card.Description>
										</Card.Header>
										<Card.Content>
											<DefinitionsEditor />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>

								<Tabs.Content value="lorebook" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Lorebook</Card.Title>
											<Card.Description>World information and character knowledge</Card.Description>
										</Card.Header>
										<Card.Content>
											<LorebookEditor />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>

								<Tabs.Content value="assets" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Assets</Card.Title>
											<Card.Description>
												Character images and visual assets (V3 feature)
											</Card.Description>
										</Card.Header>
										<Card.Content>
											<AssetsEditor />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>

								<Tabs.Content value="writingstyle" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Writing Style</Card.Title>
											<Card.Description>
												Customize narrative preferences for this character
											</Card.Description>
										</Card.Header>
										<Card.Content>
											<NarrativeStyleConfigurator characterId={character?.id} />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>

								<Tabs.Content value="advanced" class="tab-content">
									<Card.Root>
										<Card.Header>
											<Card.Title>Advanced Settings</Card.Title>
											<Card.Description>Creator notes, metadata, and extensions</Card.Description>
										</Card.Header>
										<Card.Content>
											<AdvancedEditor />
										</Card.Content>
									</Card.Root>
								</Tabs.Content>
							</div>
						</Tabs.Root>
					</div>

					<!-- Preview Panel -->
					<div class="lg:sticky lg:top-0 lg:h-fit">
						<CharacterPreview />
					</div>
				</div>
			</div>

			<Dialog.Footer class="border-t px-6 py-4">
				<Button variant="outline" onclick={handleClose} disabled={isSaving}>Cancel</Button>
				<Button onclick={handleSave} disabled={isSaving}>
					{#if isSaving}
						Saving...
					{:else}
						Save Changes
					{/if}
				</Button>
			</Dialog.Footer>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>

<UnsavedChangesDialog
	open={showConfirmClose}
	characterName={characterStore.character?.data.name}
	{isSaving}
	onSave={handleConfirmSave}
	onDiscard={handleConfirmDiscard}
	onCancel={handleConfirmCancel}
/>
