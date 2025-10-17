<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import AiAssistantWidget from '$lib/components/ai/AiAssistantWidget.svelte';
	import AiAssistantDialog from '$lib/components/ai/AiAssistantDialog.svelte';
	import { buildCharacterContext } from '$lib/utils/character-context';
	import type { CharacterCardV3 } from '$lib/types/character';

	const { character } = $derived(characterStore);

	// AI dialog state
	let aiDialogOpen = $state(false);
	let aiFieldName = $state<string>('');

	function updateField<K extends keyof CharacterCardV3['data']>(
		field: K,
		value: CharacterCardV3['data'][K]
	) {
		characterStore.updateField(field, value);
	}

	function updateExtensions(value: string) {
		try {
			const parsed = JSON.parse(value);
			updateField('extensions', parsed);
		} catch (_e) {
			// Invalid JSON, don't update
		}
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

	const extensionsJSON = $derived(JSON.stringify(character?.data.extensions || {}, null, 2));

	const characterContext = $derived(buildCharacterContext(character, aiFieldName));
	const currentFieldValue = $derived(
		character ? character.data[aiFieldName as keyof CharacterCardV3['data']] : undefined
	);
</script>

<div class="space-y-4">
	<!-- Creator Notes -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="creator_notes">Creator Notes</Label>
				<FieldHelp
					title="Creator Notes"
					description="Public notes SHOULD be very discoverable for users. Considered as creator note for 'en' language unless creator_notes_multilingual is present."
					examples={[
						'Optimized for creative roleplay',
						'Based on the novel series by...',
						'Use with fantasy lorebook for best results'
					]}
					aiTip="This field should be user-facing and helpful"
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('creator_notes')} />
		</div>
		<Textarea
			id="creator_notes"
			placeholder="Notes for other creators or users"
			value={character?.data.creator_notes || ''}
			oninput={(e) => updateField('creator_notes', e.currentTarget.value)}
			rows={4}
			class="resize-y"
		/>
	</div>

	<!-- Metadata (Read-only) -->
	<div class="space-y-3">
		<Label>Metadata (Read-only)</Label>

		<div class="space-y-2">
			<div class="flex items-center gap-2 text-sm">
				<span class="text-muted-foreground">Spec:</span>
				<Badge variant="secondary">{character?.spec || 'chara_card_v3'}</Badge>
				<Badge variant="outline">{character?.spec_version || '3.0'}</Badge>
			</div>

			{#if character?.data.creation_date}
				<div class="flex items-center gap-2 text-sm">
					<span class="text-muted-foreground">Created:</span>
					<span>{new Date(character.data.creation_date * 1000).toLocaleString()}</span>
				</div>
			{/if}

			{#if character?.data.modification_date}
				<div class="flex items-center gap-2 text-sm">
					<span class="text-muted-foreground">Modified:</span>
					<span>{new Date(character.data.modification_date * 1000).toLocaleString()}</span>
				</div>
			{/if}

			{#if character?.data.source && character.data.source.length > 0}
				<div class="space-y-1">
					<span class="text-sm text-muted-foreground">Sources:</span>
					<div class="flex flex-wrap gap-1">
						{#each character.data.source as source}
							<Badge variant="outline">{source}</Badge>
						{/each}
					</div>
				</div>
			{/if}
		</div>
	</div>

	<!-- Extensions (JSON) -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label for="extensions">Extensions (JSON)</Label>
			<FieldHelp
				title="Extensions"
				description="Application-specific data storage field. Applications MUST follow the spec and not add their own fields to root - use extensions instead."
				examples={[
					'{"myapp_setting": "value"}',
					'{"custom_tags": ["tag1", "tag2"]}',
					'{"platform_data": {...}}'
				]}
				aiTip="Store any custom metadata your application needs here"
			/>
		</div>
		<Textarea
			id="extensions"
			placeholder={'{}'}
			value={extensionsJSON}
			oninput={(e) => updateExtensions(e.currentTarget.value)}
			rows={6}
			class="resize-y font-mono text-sm"
		/>
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
