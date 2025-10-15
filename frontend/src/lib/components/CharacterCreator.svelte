<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Card from '$lib/components/ui/card';
	import Button from '$lib/components/ui/button/button.svelte';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import { X } from 'lucide-svelte';

	import BasicInfoEditor from '$lib/components/character/BasicInfoEditor.svelte';
	import GreetingsEditor from '$lib/components/character/GreetingsEditor.svelte';
	import DefinitionsEditor from '$lib/components/character/DefinitionsEditor.svelte';
	import AssetsEditor from '$lib/components/character/AssetsEditor.svelte';
	import AdvancedEditor from '$lib/components/character/AdvancedEditor.svelte';
	import LorebookEditor from '$lib/components/character/LorebookEditor.svelte';
	import CharacterPreview from '$lib/components/shared/CharacterPreview.svelte';
	import type { Character } from '$lib/types';
	import { createEventDispatcher } from 'svelte';

	// Props
	interface Props {
		open?: boolean;
		onOpenChange?: (open: boolean) => void;
	}

	let { open = $bindable(false), onOpenChange }: Props = $props();

	const dispatch = createEventDispatcher();

	let isSaving = $state(false);
	let currentTab = $state('basic');

	// Initialize character store when dialog opens
	$effect(() => {
		if (open && !characterStore.character) {
			characterStore.createNew();
		}
	});

	function handleClose() {
		if (onOpenChange) {
			onOpenChange(false);
		} else {
			open = false;
		}
		// Clear store on close
		characterStore.clear();
	}

	async function handleCreate() {
		if (!characterStore.character) return;

		const character = characterStore.character;

		// Validate required fields
		if (!character.data.name?.trim()) {
			toast.error('Name is required');
			return;
		}
		if (!character.data.description?.trim()) {
			toast.error('Description is required');
			return;
		}
		if (!character.data.first_mes?.trim()) {
			toast.error('First message is required');
			return;
		}

		isSaving = true;
		try {
			// Convert V3 format to scribe's backend format
			const createData = {
				spec: 'character_card_v2', // Scribe uses V2 spec currently
				spec_version: '2.0',
				name: character.data.name.trim(),
				description: character.data.description.trim(),
				first_mes: character.data.first_mes.trim(),
				personality: character.data.personality?.trim() || undefined,
				scenario: character.data.scenario?.trim() || undefined,
				mes_example: character.data.mes_example?.trim() || undefined,
				system_prompt: character.data.system_prompt?.trim() || undefined,
				creator: character.data.creator?.trim() || undefined,
				character_version: character.data.character_version?.trim() || undefined,
				tags: character.data.tags || [],
				alternate_greetings: character.data.alternate_greetings || [],
				nickname: character.data.nickname?.trim() || undefined,
				extensions: character.data.extensions || {}
			};

			const result = await apiClient.createCharacter(createData as Omit<Character, 'id'>);
			if (result.isOk()) {
				toast.success('Character created successfully');
				dispatch('created', { character: result.value });
				handleClose();
			} else {
				toast.error('Failed to create character: ' + result.error.message);
			}
		} catch (error) {
			toast.error('Failed to create character');
			console.error('Character creation error:', error);
		} finally {
			isSaving = false;
		}
	}
</script>

<Dialog.Root {open} onOpenChange={handleClose}>
	<Dialog.Portal>
		<Dialog.Overlay />
		<Dialog.Content class="flex max-h-[95vh] max-w-[95vw] flex-col overflow-hidden p-0">
			<Dialog.Header class="border-b px-6 pb-4 pt-6">
				<div class="flex items-center justify-between">
					<div>
						<Dialog.Title>Create New Character</Dialog.Title>
						<Dialog.Description>
							Design your character with the full-featured editor
						</Dialog.Description>
					</div>
					<Button variant="ghost" size="icon" class="h-8 w-8" onclick={handleClose}>
						<X class="h-4 w-4" />
					</Button>
				</div>
			</Dialog.Header>

			<div class="flex-1 overflow-y-auto px-6 py-4">
				<div class="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_400px]">
					<!-- Editor Panel -->
					<div>
						<Tabs.Root bind:value={currentTab} class="w-full">
							<Tabs.List class="grid w-full grid-cols-6">
								<Tabs.Trigger value="basic">Basic Info</Tabs.Trigger>
								<Tabs.Trigger value="greetings">Greetings</Tabs.Trigger>
								<Tabs.Trigger value="definitions">Definitions</Tabs.Trigger>
								<Tabs.Trigger value="lorebook">Lorebook</Tabs.Trigger>
								<Tabs.Trigger value="assets">Assets</Tabs.Trigger>
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
				<Button onclick={handleCreate} disabled={isSaving}>
					{#if isSaving}
						Creating...
					{:else}
						Create Character
					{/if}
				</Button>
			</Dialog.Footer>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
