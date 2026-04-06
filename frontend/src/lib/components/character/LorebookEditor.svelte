<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import type { LorebookEntry } from '$lib/types/character';
	import type { Lorebook } from '$lib/types';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import * as Tabs from '$lib/components/ui/tabs';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import LorebookEntryList from './LorebookEntryList.svelte';
	import LorebookEntryForm from './LorebookEntryForm.svelte';
	import LorebookBrowser from './LorebookBrowser.svelte';
	import LorebookAIAssistant from '$lib/components/ai/LorebookAIAssistant.svelte';
	import LorebookAIDialog from '$lib/components/ai/LorebookAIDialog.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import { toast } from 'svelte-sonner';

	const character = $derived(characterStore.character);
	const lorebook = $derived(character?.data.character_book);

	let currentTab = $state('embedded');
	let showEntryForm = $state(false);
	let editingEntry = $state<LorebookEntry | null>(null);
	let editingIndex = $state<number>(-1);
	let showAIDialog = $state(false);

	// Helper function to update lorebook settings
	function updateSettings(
		updates: Partial<{
			name: string;
			description: string;
			scan_depth: number;
			token_budget: number;
			recursive_scanning: boolean;
		}>
	) {
		characterStore.updateLorebookSettings({
			name: lorebook?.name || '',
			description: lorebook?.description || '',
			scan_depth: lorebook?.scan_depth ?? 2,
			token_budget: lorebook?.token_budget ?? 512,
			recursive_scanning: lorebook?.recursive_scanning ?? false,
			...updates
		});
	}

	function handleCreateNew() {
		editingEntry = null;
		editingIndex = -1;
		showEntryForm = true;
	}

	function handleEditEntry(entry: LorebookEntry, index: number) {
		editingEntry = entry;
		editingIndex = index;
		showEntryForm = true;
	}

	function handleDeleteEntry(_entry: LorebookEntry, index: number) {
		if (confirm('Are you sure you want to delete this entry?')) {
			characterStore.deleteLorebookEntry(index);
		}
	}

	function handleToggleEntry(_entry: LorebookEntry, index: number) {
		characterStore.toggleLorebookEntry(index);
	}

	function handleSubmitEntry(data: Partial<LorebookEntry>) {
		if (editingIndex >= 0) {
			// Update existing entry
			characterStore.updateLorebookEntry(editingIndex, data);
		} else {
			// Create new entry
			characterStore.addLorebookEntry(data as LorebookEntry);
		}
		showEntryForm = false;
		editingEntry = null;
		editingIndex = -1;
	}

	function handleCancelEntry() {
		showEntryForm = false;
		editingEntry = null;
		editingIndex = -1;
	}

	async function handleLorebookSelect(lorebook: Lorebook, mode: 'link' | 'import') {
		if (mode === 'link') {
			// Link the lorebook by reference
			characterStore.linkLorebookReference(lorebook.id);
			toast.success(`Linked lorebook: ${lorebook.name}`);
		} else {
			// Import lorebook entries into embedded lorebook
			await characterStore.importLorebookEntries(lorebook.id);
			toast.success(`Imported ${lorebook.name} entries into character`);
			// Switch to embedded tab to see the imported entries
			currentTab = 'embedded';
		}
	}
</script>

<Tabs.Root bind:value={currentTab} class="space-y-6">
	<Tabs.List class="grid w-full grid-cols-2">
		<Tabs.Trigger value="embedded">Create Inline</Tabs.Trigger>
		<Tabs.Trigger value="existing">Link Existing</Tabs.Trigger>
	</Tabs.List>

	<Tabs.Content value="embedded" class="space-y-6">
		<!-- Lorebook Settings -->
		<div class="space-y-4">
			<div class="flex items-center justify-between">
				<h3 class="text-lg font-semibold">Lorebook Settings</h3>
				<div class="flex gap-2">
					<LorebookAIAssistant onclick={() => (showAIDialog = true)} />
					<!-- <ResearchWebButton onclick={() => (showResearchDialog = true)} /> -->
				</div>
			</div>

			<div class="grid gap-4">
				<!-- Name -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="lorebook-name">Name</Label>
						<FieldHelp
							title="Lorebook Name"
							description="Optional identifier for this lorebook. NOT used in prompt engineering - purely for organization."
							examples={['Character World', 'Magic System', 'Historical Context']}
						/>
					</div>
					<Input
						id="lorebook-name"
						value={lorebook?.name || ''}
						oninput={(e) => updateSettings({ name: e.currentTarget.value })}
						placeholder="My Character's Lorebook"
					/>
				</div>

				<!-- Description -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="lorebook-description">Description</Label>
						<FieldHelp
							title="Lorebook Description"
							description="Optional comments about this lorebook. NOT used in prompt engineering - purely for organization."
							examples={[
								'World lore for fantasy setting',
								'Contains spoilers for Act 2',
								'Created 2024-01-15'
							]}
						/>
					</div>
					<Textarea
						id="lorebook-description"
						value={lorebook?.description || ''}
						oninput={(e) => updateSettings({ description: e.currentTarget.value })}
						placeholder="A brief description of this lorebook"
						rows={3}
					/>
				</div>

				<!-- Settings Grid -->
				<div class="grid grid-cols-2 gap-4">
					<!-- Scan Depth -->
					<div class="space-y-2">
						<div class="flex items-center gap-2">
							<Label for="scan-depth">Scan Depth</Label>
							<FieldHelp
								title="Scan Depth"
								description="Checking for keys SHOULD only match if recent [scan_depth] messages contain the keys. If chat-based context isn't possible, application SHOULD ignore this."
								examples={['2: Last 2 messages', '5: Last 5 messages', '0: All messages']}
							/>
						</div>
						<Input
							id="scan-depth"
							type="number"
							value={lorebook?.scan_depth ?? 2}
							oninput={(e) => updateSettings({ scan_depth: parseInt(e.currentTarget.value) || 0 })}
							min={0}
						/>
					</div>

					<!-- Token Budget -->
					<div class="space-y-2">
						<div class="flex items-center gap-2">
							<Label for="token-budget">Token Budget</Label>
							<FieldHelp
								title="Token Budget"
								description="Application SHOULD remove lowest priority entries when total lorebook tokens exceed this limit. If priority/insertion_order absent, removal is up to application."
								examples={['512: Small budget', '1024: Medium budget', '2048: Large budget']}
							/>
						</div>
						<Input
							id="token-budget"
							type="number"
							value={lorebook?.token_budget ?? 512}
							oninput={(e) =>
								updateSettings({ token_budget: parseInt(e.currentTarget.value) || 0 })}
							min={0}
						/>
					</div>
				</div>

				<!-- Recursive Scanning -->
				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="recursive-scanning"
						checked={lorebook?.recursive_scanning ?? false}
						onchange={(e) => updateSettings({ recursive_scanning: e.currentTarget.checked })}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary"
					/>
					<Label for="recursive-scanning" class="cursor-pointer text-sm">Recursive Scanning</Label>
					<FieldHelp
						title="Recursive Scanning"
						description="If true, entries MAY match if other activated lorebook entries' content fields match keys (regardless of scan_depth). If false, MUST NOT match from other entries' content."
						examples={[
							'True: Entry A triggers Entry B triggers Entry C',
							'False: Only scan chat messages'
						]}
						iconSize={14}
					/>
				</div>
			</div>
		</div>

		<!-- Divider -->
		<div class="border-t"></div>

		<!-- Lorebook Entries -->
		<LorebookEntryList
			entries={lorebook?.entries || []}
			onCreateNew={handleCreateNew}
			onEditEntry={handleEditEntry}
			onDeleteEntry={handleDeleteEntry}
			onToggleEntry={handleToggleEntry}
		/>
	</Tabs.Content>

	<Tabs.Content value="existing" class="space-y-6">
		<div class="space-y-4">
			<h3 class="text-lg font-semibold">Link Existing Lorebook</h3>
			<p class="text-sm text-muted-foreground">
				Select an existing standalone lorebook to link or import into this character.
			</p>
		</div>
		<LorebookBrowser onSelect={handleLorebookSelect} />
	</Tabs.Content>
</Tabs.Root>

<!-- Entry Form Dialog -->
<Dialog.Root open={showEntryForm} onOpenChange={(open) => (showEntryForm = open)}>
	<Dialog.Content class="max-h-[90vh] max-w-2xl overflow-y-auto">
		<LorebookEntryForm
			entry={editingEntry}
			onSubmit={handleSubmitEntry}
			onCancel={handleCancelEntry}
		/>
	</Dialog.Content>
</Dialog.Root>

<!-- AI Assistant Dialog -->
<LorebookAIDialog bind:open={showAIDialog} />

<!-- Research Dialog (Disabled temporarily) -->
<!-- <ResearchDialog bind:open={showResearchDialog} /> -->
