<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import AiAssistantWidget from '$lib/components/ai/AiAssistantWidget.svelte';
	import AiAssistantDialog from '$lib/components/ai/AiAssistantDialog.svelte';
	import { buildCharacterContext } from '$lib/utils/character-context';
	import type { CharacterCardV3 } from '$lib/types/character';

	const { character } = $derived(characterStore);

	// AI dialog state
	let aiDialogOpen = $state(false);
	let aiFieldName = $state<string>('');

	// Help tooltip examples with template placeholders
	const scenarioExamples = [
		'{{char}} is a detective in Victorian London, investigating supernatural crimes',
		'The year is 2157. {{char}} is captain of a colony ship heading to Alpha Centauri',
		'{{char}} runs a cozy bookshop in a small mountain town where {{user}} just arrived'
	];
	const scenarioTip =
		'Use {{char}} and {{user}} placeholders for dynamic character/user references';

	const mesExampleExamples = [
		'<START>\n{{char}}: "Well, this is unexpected." *adjusts glasses*\n{{user}}: "What is?"\n{{char}}: "Everything, darling. Everything."',
		'<START>\n{{char}}: *fires laser* Target eliminated.\n<START>\n{{char}}: Mission parameters updated. Proceeding.'
	];

	const postHistoryExamples = [
		"Remember to include {{char}}'s internal thoughts in *asterisks* after each response.",
		'Always end your response with the current time and location.',
		'Refer to previous conversation context and maintain continuity.'
	];

	function updateField<K extends keyof CharacterCardV3['data']>(
		field: K,
		value: CharacterCardV3['data'][K]
	) {
		characterStore.updateField(field, value);
	}

	function openAiAssistant(fieldName: string) {
		aiFieldName = fieldName;
		aiDialogOpen = true;
	}

	function handleAiGenerated(content: string) {
		if (aiFieldName) {
			characterStore.updateField(
				aiFieldName as keyof CharacterCardV3['data'],
				content as CharacterCardV3['data'][keyof CharacterCardV3['data']]
			);
		}
	}

	const characterContext = $derived(buildCharacterContext(character, aiFieldName));
	const currentFieldValue = $derived(
		character ? character.data[aiFieldName as keyof CharacterCardV3['data']] : undefined
	);
</script>

<div class="space-y-4">
	<!-- Personality -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="personality">Personality</Label>
				<FieldHelp
					title="Personality"
					description="Core personality traits and behavioral patterns that define how your character thinks and acts."
					examples={[
						'Curious and adventurous, tends to act before thinking. Can be reckless but has a good heart.',
						'Analytical, methodical, emotionally reserved. Prefers logic over emotion.',
						'Traits: cheerful, optimistic, energetic, friendly, sometimes naive'
					]}
					aiTip="Use 'traits' style for comma-separated list or 'narrative' for flowing description"
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('personality')} />
		</div>
		<Textarea
			id="personality"
			placeholder="Character's personality traits and behavior patterns"
			value={character?.data.personality || ''}
			oninput={(e) => updateField('personality', e.currentTarget.value)}
			rows={5}
			class="resize-y"
		/>
		<p class="text-xs text-muted-foreground">
			Describe how the character behaves, thinks, and interacts
		</p>
	</div>

	<!-- Scenario -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="scenario">Scenario</Label>
				<FieldHelp
					title="Scenario"
					description="The setting, situation, or context in which the character exists and interactions take place."
					examples={scenarioExamples}
					aiTip={scenarioTip}
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('scenario')} />
		</div>
		<Textarea
			id="scenario"
			placeholder="The situation or context where the character exists"
			value={character?.data.scenario || ''}
			oninput={(e) => updateField('scenario', e.currentTarget.value)}
			rows={4}
			class="resize-y"
		/>
		<p class="text-xs text-muted-foreground">
			The setting, situation, or circumstances surrounding the character
		</p>
	</div>

	<!-- Message Example -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="mes_example">Example Messages</Label>
				<FieldHelp
					title="Example Messages"
					description="Sample dialogue demonstrating the character's speaking style, vocabulary, and mannerisms. Separate multiple examples with <START>."
					examples={mesExampleExamples}
					aiTip="AI can generate character-appropriate dialogue with actions in *asterisks*"
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('mes_example')} />
		</div>
		<Textarea
			id="mes_example"
			placeholder={'<START>\n{' +
				'{char}}: Example message here\n<START>\n{' +
				'{char}}: Another example'}
			value={character?.data.mes_example || ''}
			oninput={(e) => updateField('mes_example', e.currentTarget.value)}
			rows={6}
			class="resize-y font-mono text-sm"
		/>
		<p class="text-xs text-muted-foreground">
			Example dialogue to demonstrate the character's speaking style. Use &lt;START&gt; to separate
			examples.
		</p>
	</div>

	<!-- System Prompt -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="system_prompt">System Prompt</Label>
				<FieldHelp
					title="System Prompt"
					description="System-level instructions that guide the AI's behavior. These appear before all other context."
					examples={[
						'Write responses in a dark, noir style with short, punchy sentences.',
						'Always respond with vivid sensory details and emotional depth.',
						'Maintain character consistency. Never break character or acknowledge being an AI.'
					]}
					aiTip="AI can generate style guides, formatting rules, or behavioral constraints"
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('system_prompt')} />
		</div>
		<Textarea
			id="system_prompt"
			placeholder="Optional system-level instructions for the AI"
			value={character?.data.system_prompt || ''}
			oninput={(e) => updateField('system_prompt', e.currentTarget.value)}
			rows={4}
			class="resize-y"
		/>
		<p class="text-xs text-muted-foreground">
			Instructions that influence the AI's behavior at a system level
		</p>
	</div>

	<!-- Post-History Instructions -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="post_history_instructions">Post-History Instructions</Label>
				<FieldHelp
					title="Post-History Instructions"
					description="Instructions injected after the conversation history. Useful for reminders, formatting rules, or dynamic guidance."
					examples={postHistoryExamples}
					aiTip="These appear AFTER chat history, good for format reminders and context reinforcement"
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('post_history_instructions')} />
		</div>
		<Textarea
			id="post_history_instructions"
			placeholder="Instructions that appear after the chat history"
			value={character?.data.post_history_instructions || ''}
			oninput={(e) => updateField('post_history_instructions', e.currentTarget.value)}
			rows={3}
			class="resize-y"
		/>
		<p class="text-xs text-muted-foreground">
			Additional instructions sent after the conversation history
		</p>
	</div>
</div>

<!-- AI Assistant Dialog -->
<AiAssistantDialog
	bind:open={aiDialogOpen}
	fieldName={aiFieldName}
	fieldValue={typeof currentFieldValue === 'string'
		? currentFieldValue
		: String(currentFieldValue ?? '')}
	{characterContext}
	onGenerate={handleAiGenerated}
	onOpenChange={(open) => (aiDialogOpen = open)}
/>
