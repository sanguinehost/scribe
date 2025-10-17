<script lang="ts">
	import type { LorebookEntry } from '$lib/types/character';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import * as Card from '$lib/components/ui/card';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import AiAssistantWidget from '$lib/components/ai/AiAssistantWidget.svelte';
	import AiAssistantDialog from '$lib/components/ai/AiAssistantDialog.svelte';
	import { characterStore } from '$lib/stores/character.svelte';
	import { buildLorebookEntryContext } from '$lib/utils/character-context';

	interface Props {
		entry?: LorebookEntry | null;
		isLoading?: boolean;
		onSubmit?: (data: Partial<LorebookEntry>) => void;
		onCancel?: () => void;
	}

	let { entry = null, isLoading = false, onSubmit, onCancel }: Props = $props();

	let name = $state(entry?.name || '');
	let keys = $state(entry?.keys?.join(', ') || '');
	let secondaryKeys = $state(entry?.secondary_keys?.join(', ') || '');
	let content = $state(entry?.content || '');
	let enabled = $state(entry?.enabled ?? true);
	let insertionOrder = $state(entry?.insertion_order ?? 100);
	let caseSensitive = $state(entry?.case_sensitive ?? false);
	let useRegex = $state(entry?.use_regex ?? false);
	let constant = $state(entry?.constant ?? false);
	let priority = $state(entry?.priority ?? 10);
	let position = $state<'before_char' | 'after_char'>(
		(entry?.position === 'before_char' || entry?.position === 'after_char'
			? entry.position
			: 'after_char') as 'before_char' | 'after_char'
	);
	let comment = $state(entry?.comment || '');
	let selective = $state(entry?.selective ?? true);

	const isEditing = entry !== null;
	const title = isEditing ? 'Edit Entry' : 'Create New Entry';
	const submitLabel = isEditing ? 'Update Entry' : 'Create Entry';

	// AI assistant state
	let aiDialogOpen = $state(false);
	const { character } = $derived(characterStore);

	// Help tooltip examples from Character Card V3 spec
	const keywordsExamples = [
		'dragon, ancient dragon, wyrm',
		'magic academy, school of magic',
		"{{char}}'s past, childhood"
	];

	const secondaryKeysExamples = [
		'ancient wyrm, elder dragon',
		'battle magic, combat spells',
		'old memories, forgotten past'
	];

	const contentExamples = [
		'The ancient library contains forbidden tomes dating back millennia. Only senior mages may enter.',
		"Victoria's cybernetic enhancements were installed after the accident in 2089.",
		'The royal family has ruled for 300 years, though rumors of corruption persist.'
	];

	const contentAiTip =
		'Write clear, concise worldbuilding. Can use {{char}}, {{user}}, and other curly braced syntaxes.';

	// Build context for AI generation
	const entryContext = $derived.by(() => {
		const keyArray = keys
			.split(',')
			.map((k) => k.trim())
			.filter((k) => k.length > 0);

		return buildLorebookEntryContext(character, name || undefined, keyArray, content || undefined);
	});

	function handleSubmit(e: Event) {
		e.preventDefault();

		if (!content.trim()) {
			return;
		}

		const keyArray = keys
			.split(',')
			.map((k) => k.trim())
			.filter((k) => k.length > 0);

		const secondaryKeyArray =
			secondaryKeys
				.split(',')
				.map((k) => k.trim())
				.filter((k) => k.length > 0) || undefined;

		const payload: Partial<LorebookEntry> = {
			keys: keyArray,
			content: content.trim(),
			enabled,
			insertion_order: insertionOrder,
			case_sensitive: caseSensitive,
			use_regex: useRegex
		};

		if (name.trim()) payload.name = name.trim();
		if (constant) payload.constant = constant;
		if (priority !== 10) payload.priority = priority;
		if (comment.trim()) payload.comment = comment.trim();
		if (selective !== true) payload.selective = selective;
		if (secondaryKeyArray && secondaryKeyArray.length > 0)
			payload.secondary_keys = secondaryKeyArray;
		if (position) payload.position = position;

		onSubmit?.(payload);
	}

	function handleCancel() {
		onCancel?.();
	}

	function openAiAssistant() {
		aiDialogOpen = true;
	}

	function handleAiGenerated(generatedContent: string) {
		content = generatedContent;
	}

	// Reset form when entry changes
	$effect(() => {
		name = entry?.name || '';
		keys = entry?.keys?.join(', ') || '';
		secondaryKeys = entry?.secondary_keys?.join(', ') || '';
		content = entry?.content || '';
		enabled = entry?.enabled ?? true;
		insertionOrder = entry?.insertion_order ?? 100;
		caseSensitive = entry?.case_sensitive ?? false;
		useRegex = entry?.use_regex ?? false;
		constant = entry?.constant ?? false;
		priority = entry?.priority ?? 10;
		position = (
			entry?.position === 'before_char' || entry?.position === 'after_char'
				? entry.position
				: 'after_char'
		) as 'before_char' | 'after_char';
		comment = entry?.comment || '';
		selective = entry?.selective ?? true;
	});
</script>

<Card.Root class="w-full">
	<Card.Header>
		<Card.Title>{title}</Card.Title>
	</Card.Header>
	<Card.Content>
		<form onsubmit={handleSubmit} class="space-y-4">
			<!-- Entry Name (optional) -->
			<div class="space-y-2">
				<div class="flex items-center gap-2">
					<Label for="entry-name">Name (optional)</Label>
					<FieldHelp
						title="Entry Name"
						description="Optional label to identify this lorebook entry. Makes it easier to organize and find entries."
						examples={['The Great Library', "Victoria's Cybernetics", 'Kingdom History']}
					/>
				</div>
				<Input
					id="entry-name"
					bind:value={name}
					placeholder="Entry name or title"
					disabled={isLoading}
				/>
			</div>

			<!-- Keywords Grid -->
			<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
				<!-- Primary Keywords -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="entry-keys">Keywords <span class="text-destructive">*</span></Label>
						<FieldHelp
							title="Keywords"
							description="Array of trigger strings. Entry activates when chat log contains one of these keys (unless scan_depth or other conditions prevent it)."
							examples={keywordsExamples}
							aiTip="Include variations and synonyms. Can be treated as regex if 'Use Regex' is enabled."
						/>
					</div>
					<Input
						id="entry-keys"
						bind:value={keys}
						placeholder="dragon, fire, magic"
						disabled={isLoading}
						required
					/>
				</div>

				<!-- Secondary Keywords -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="entry-secondary-keys">Secondary Keywords (optional)</Label>
						<FieldHelp
							title="Secondary Keywords"
							description="When 'Selective' is true, entry won't activate unless chat log ALSO contains one of these secondary keys. Ignored if 'Use Regex' is enabled."
							examples={secondaryKeysExamples}
						/>
					</div>
					<Input
						id="entry-secondary-keys"
						bind:value={secondaryKeys}
						placeholder="red dragon, ancient"
						disabled={isLoading}
					/>
				</div>
			</div>

			<!-- Content -->
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<Label for="entry-content">Content <span class="text-destructive">*</span></Label>
						<FieldHelp
							title="Entry Content"
							description="Text added to the prompt when entry matches. Can contain decorators (@@) for advanced control. Added only once even if matched multiple times."
							examples={contentExamples}
							aiTip={contentAiTip}
						/>
					</div>
					<AiAssistantWidget onclick={openAiAssistant} />
				</div>
				<Textarea
					id="entry-content"
					bind:value={content}
					placeholder="Enter the lorebook entry content"
					rows={8}
					required
					disabled={isLoading}
				/>
			</div>

			<!-- Comment -->
			<div class="space-y-2">
				<div class="flex items-center gap-2">
					<Label for="entry-comment">Comment (optional)</Label>
					<FieldHelp
						title="Comment"
						description="Optional notes about this entry. NOT used in prompt engineering - purely for organization."
						examples={[
							'TODO: Add more details about the war',
							'Source: Chapter 5 of novel',
							'Created for mystery arc'
						]}
					/>
				</div>
				<Input
					id="entry-comment"
					bind:value={comment}
					placeholder="Notes about this entry"
					disabled={isLoading}
				/>
			</div>

			<!-- Settings Grid -->
			<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
				<!-- Insertion Order -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="insertion-order">Insertion Order</Label>
						<FieldHelp
							title="Insertion Order"
							description="Determines order entries are added to prompt. Lower numbers insert first. May affect removal when reaching token_budget if priority field absent."
							examples={['0 - Insert first', '100 - Standard (default)', '200 - Insert later']}
						/>
					</div>
					<Input
						id="insertion-order"
						type="number"
						bind:value={insertionOrder}
						disabled={isLoading}
						required
					/>
				</div>

				<!-- Priority -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="priority">Priority</Label>
						<FieldHelp
							title="Priority"
							description="When reaching token_budget limit, entries with LOWER priority are removed first. If undefined, may follow insertion_order instead."
							examples={[
								'0 - Remove first',
								'10 - Standard (default)',
								'100 - Keep as long as possible'
							]}
						/>
					</div>
					<Input id="priority" type="number" bind:value={priority} disabled={isLoading} />
				</div>

				<!-- Position -->
				<div class="space-y-2">
					<div class="flex items-center gap-2">
						<Label for="position">Position</Label>
						<FieldHelp
							title="Position"
							description="Where to inject this entry: 'before_char' or 'after_char' relative to the character definition. Can be overridden by @@position decorator."
							examples={['before_char - World/setting info', 'after_char - Recent events, updates']}
						/>
					</div>
					<select
						id="position"
						class="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
						bind:value={position}
						disabled={isLoading}
					>
						<option value="before_char">Before Character</option>
						<option value="after_char">After Character</option>
					</select>
				</div>
			</div>

			<!-- Checkboxes Grid -->
			<div class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="is-enabled"
						bind:checked={enabled}
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="is-enabled" class="cursor-pointer text-sm">Enabled</Label>
					<FieldHelp
						title="Enabled"
						description="If false, entry MUST NOT match in any case. Use to temporarily disable entries."
						iconSize={14}
					/>
				</div>

				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="is-constant"
						bind:checked={constant}
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="is-constant" class="cursor-pointer text-sm">Constant</Label>
					<FieldHelp
						title="Constant"
						description="If true, entry MUST match regardless of keys/secondary_keys (decorator conditions still apply). Ignored if use_regex is true."
						iconSize={14}
					/>
				</div>

				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="is-selective"
						bind:checked={selective}
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="is-selective" class="cursor-pointer text-sm">Selective</Label>
					<FieldHelp
						title="Selective"
						description="Used with secondary_keys field. If true and secondary_keys present, entry won't match unless BOTH keys AND secondary_keys match."
						iconSize={14}
					/>
				</div>

				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="case-sensitive"
						bind:checked={caseSensitive}
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="case-sensitive" class="cursor-pointer text-sm">Case Sensitive</Label>
					<FieldHelp
						title="Case Sensitive"
						description="If true, keys SHOULD be case sensitive. If false/undefined, keys SHOULD be case insensitive."
						examples={['When true: "Dragon" ≠ "dragon"', 'When false: "Dragon" = "dragon"']}
						iconSize={14}
					/>
				</div>

				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="use-regex"
						bind:checked={useRegex}
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="use-regex" class="cursor-pointer text-sm">Use Regex</Label>
					<FieldHelp
						title="Use Regex"
						description="If true, keys treated as regex patterns instead of literal strings. Invalid regex = no match. Ignores secondary_keys and constant fields."
						examples={[
							'\\bdragon\\w*\\b → dragon, dragons, dragonkin',
							'^The.*Kingdom$ → starts with The, ends with Kingdom'
						]}
						iconSize={14}
					/>
				</div>
			</div>

			<!-- Submit buttons -->
			<div class="flex gap-2 pt-4">
				<Button type="submit" disabled={isLoading || !content.trim()} class="flex-1">
					{#if isLoading}
						<div
							class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
						></div>
					{/if}
					{submitLabel}
				</Button>
				{#if onCancel}
					<Button type="button" variant="outline" onclick={handleCancel} disabled={isLoading}>
						Cancel
					</Button>
				{/if}
			</div>
		</form>
	</Card.Content>
</Card.Root>

<!-- AI Assistant Dialog -->
<AiAssistantDialog
	bind:open={aiDialogOpen}
	fieldName="entry.content"
	fieldValue={content}
	characterContext={entryContext}
	onGenerate={handleAiGenerated}
	onOpenChange={(open) => (aiDialogOpen = open)}
/>
