<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Button from '$lib/components/ui/button/button.svelte';
	import * as Card from '$lib/components/ui/card';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import AiAssistantWidget from '$lib/components/ai/AiAssistantWidget.svelte';
	import AiAssistantDialog from '$lib/components/ai/AiAssistantDialog.svelte';
	import { Plus, Trash2 } from '@lucide/svelte';
	import { buildCharacterContext } from '$lib/utils/character-context';
	import type { CharacterCardV3 } from '$lib/types/character';

	const { character } = $derived(characterStore);

	// AI dialog state
	let aiDialogOpen = $state(false);
	let aiFieldName = $state<string>('');
	let aiGreetingIndex = $state<number | null>(null);
	let aiGreetingType = $state<'alternate' | 'group' | null>(null);

	// Help tooltip examples with template placeholders
	const firstMessageExamples = [
		"*looks up from book* Oh, hello there. I didn't hear you come in.",
		'Welcome to the tavern, stranger. What brings you to these parts?',
		'{{user}}! Perfect timing. I need your help with something...'
	];

	const groupGreetingExamples = [
		'*glances at {{user}} and the other characters* Well, this is an interesting group.',
		'Team, we have a problem. *spreads out a map on the table*',
		'{{char}} addresses the assembled group: "Thank you all for coming."'
	];

	function updateField<K extends keyof CharacterCardV3['data']>(
		field: K,
		value: CharacterCardV3['data'][K]
	) {
		characterStore.updateField(field, value);
	}

	function addAlternateGreeting() {
		const current = character?.data.alternate_greetings || [];
		updateField('alternate_greetings', [...current, '']);
	}

	function updateAlternateGreeting(index: number, value: string) {
		const current = character?.data.alternate_greetings || [];
		const updated = [...current];
		updated[index] = value;
		updateField('alternate_greetings', updated);
	}

	function removeAlternateGreeting(index: number) {
		const current = character?.data.alternate_greetings || [];
		const updated = current.filter((_, i) => i !== index);
		updateField('alternate_greetings', updated);
	}

	function addGroupGreeting() {
		const current = character?.data.group_only_greetings || [];
		updateField('group_only_greetings', [...current, '']);
	}

	function updateGroupGreeting(index: number, value: string) {
		const current = character?.data.group_only_greetings || [];
		const updated = [...current];
		updated[index] = value;
		updateField('group_only_greetings', updated);
	}

	function removeGroupGreeting(index: number) {
		const current = character?.data.group_only_greetings || [];
		const updated = current.filter((_, i) => i !== index);
		updateField('group_only_greetings', updated);
	}

	// AI assistant functions
	function openAiForFirstMessage() {
		aiFieldName = 'first_mes';
		aiGreetingIndex = null;
		aiGreetingType = null;
		aiDialogOpen = true;
	}

	function openAiForAlternateGreeting(index: number) {
		aiFieldName = 'alternate_greeting';
		aiGreetingIndex = index;
		aiGreetingType = 'alternate';
		aiDialogOpen = true;
	}

	function openAiForGroupGreeting(index: number) {
		aiFieldName = 'alternate_greeting'; // Use same field type
		aiGreetingIndex = index;
		aiGreetingType = 'group';
		aiDialogOpen = true;
	}

	function handleAiGenerated(content: string) {
		if (aiFieldName === 'first_mes') {
			updateField('first_mes', content);
		} else if (aiGreetingType === 'alternate' && aiGreetingIndex !== null) {
			updateAlternateGreeting(aiGreetingIndex, content);
		} else if (aiGreetingType === 'group' && aiGreetingIndex !== null) {
			updateGroupGreeting(aiGreetingIndex, content);
		}
	}

	// Build character context (exclude current greeting being generated)
	const characterContext = $derived(buildCharacterContext(character, aiFieldName));

	// Get current field value based on what's being generated
	const currentFieldValue = $derived.by(() => {
		if (aiFieldName === 'first_mes') {
			return character?.data.first_mes || '';
		} else if (aiGreetingType === 'alternate' && aiGreetingIndex !== null) {
			return character?.data.alternate_greetings?.[aiGreetingIndex] || '';
		} else if (aiGreetingType === 'group' && aiGreetingIndex !== null) {
			return character?.data.group_only_greetings?.[aiGreetingIndex] || '';
		}
		return '';
	});
</script>

<div class="space-y-6">
	<!-- First Message -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="first_mes">First Message</Label>
				<FieldHelp
					title="First Message"
					description="The opening message when starting a conversation with this character. This is the first thing users will see."
					examples={firstMessageExamples}
					aiTip="AI can create engaging, character-appropriate opening messages with actions in *asterisks*"
				/>
			</div>
			<AiAssistantWidget onclick={openAiForFirstMessage} />
		</div>
		<Textarea
			id="first_mes"
			placeholder="The character's opening message"
			value={character?.data.first_mes || ''}
			oninput={(e) => updateField('first_mes', e.currentTarget.value)}
			rows={4}
			class="resize-y"
		/>
		<p class="text-xs text-muted-foreground">
			The default greeting message when starting a conversation
		</p>
	</div>

	<!-- Alternate Greetings -->
	<div class="space-y-3">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label>Alternate Greetings</Label>
				<FieldHelp
					title="Alternate Greetings"
					description="Additional opening messages that provide variety. Users can choose which greeting to start with or randomize them."
					examples={[
						'Multiple scenarios: arrival, leaving, confrontation, casual meeting',
						'Different moods: happy, sad, angry, thoughtful',
						'Various times: morning, afternoon, evening'
					]}
					aiTip="Create diverse greetings for different scenarios and moods"
				/>
			</div>
			<Button size="sm" variant="outline" onclick={addAlternateGreeting}>
				<Plus class="mr-1 h-4 w-4" />
				Add Alternate
			</Button>
		</div>

		{#if character?.data.alternate_greetings && character.data.alternate_greetings.length > 0}
			<div class="space-y-3">
				{#each character.data.alternate_greetings as greeting, index (index)}
					<Card.Root>
						<Card.Content class="pt-4">
							<div class="mb-2 flex items-center justify-between">
								<span class="text-sm font-medium">Greeting {index + 1}</span>
								<AiAssistantWidget onclick={() => openAiForAlternateGreeting(index)} />
							</div>
							<div class="flex gap-2">
								<Textarea
									placeholder="Alternate greeting {index + 1}"
									value={greeting}
									oninput={(e) => updateAlternateGreeting(index, e.currentTarget.value)}
									rows={3}
									class="flex-1 resize-y"
								/>
								<Button size="icon" variant="ghost" onclick={() => removeAlternateGreeting(index)}>
									<Trash2 class="h-4 w-4" />
								</Button>
							</div>
						</Card.Content>
					</Card.Root>
				{/each}
			</div>
		{:else}
			<p class="text-sm text-muted-foreground">No alternate greetings yet</p>
		{/if}
	</div>

	<!-- Group-Only Greetings (V3) -->
	<div class="space-y-3">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<div>
					<div class="flex items-center gap-2">
						<Label>Group-Only Greetings (V3)</Label>
						<FieldHelp
							title="Group-Only Greetings"
							description="Special greetings designed for group chat scenarios where multiple characters interact. These only appear in group chats, not solo conversations."
							examples={groupGreetingExamples}
							aiTip="AI can create greetings that acknowledge multiple participants and set up group dynamics"
						/>
					</div>
					<p class="text-xs text-muted-foreground">Greetings that only appear in group chats</p>
				</div>
			</div>
			<Button size="sm" variant="outline" onclick={addGroupGreeting}>
				<Plus class="mr-1 h-4 w-4" />
				Add Group Greeting
			</Button>
		</div>

		{#if character?.data.group_only_greetings && character.data.group_only_greetings.length > 0}
			<div class="space-y-3">
				{#each character.data.group_only_greetings as greeting, index (index)}
					<Card.Root>
						<Card.Content class="pt-4">
							<div class="mb-2 flex items-center justify-between">
								<span class="text-sm font-medium">Group Greeting {index + 1}</span>
								<AiAssistantWidget onclick={() => openAiForGroupGreeting(index)} />
							</div>
							<div class="flex gap-2">
								<Textarea
									placeholder="Group greeting {index + 1}"
									value={greeting}
									oninput={(e) => updateGroupGreeting(index, e.currentTarget.value)}
									rows={3}
									class="flex-1 resize-y"
								/>
								<Button size="icon" variant="ghost" onclick={() => removeGroupGreeting(index)}>
									<Trash2 class="h-4 w-4" />
								</Button>
							</div>
						</Card.Content>
					</Card.Root>
				{/each}
			</div>
		{:else}
			<p class="text-sm text-muted-foreground">No group-only greetings yet</p>
		{/if}
	</div>
</div>

<!-- AI Assistant Dialog -->
<AiAssistantDialog
	bind:open={aiDialogOpen}
	fieldName={aiFieldName}
	fieldValue={currentFieldValue}
	{characterContext}
	onGenerate={handleAiGenerated}
	onOpenChange={(open) => (aiDialogOpen = open)}
/>
