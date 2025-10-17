<script lang="ts">
	/**
	 * AI Assistant Dialog
	 *
	 * Full-featured dialog for AI-powered content generation.
	 * Supports all generation modes and description styles.
	 */

	import { Dialog, DialogContent, DialogHeader, DialogTitle } from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Slider } from '$lib/components/ui/slider';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import { Loader2, Sparkles, Copy, Check } from 'lucide-svelte';
	import { generate, generateStream } from '$lib/utils/ai/generation-engine';
	import {
		getRecommendedStyle,
		getRecommendedMaxTokens,
		isModeSupported,
		getAvailableStyles
	} from '$lib/utils/ai/prompts';
	import { sanitizeAIOutput } from '$lib/utils/ai/security';
	import type { GenerationMode, DescriptionStyle, CharacterContext } from '$lib/types/ai';

	interface Props {
		/** Dialog open state */
		open: boolean;
		/** Field name to generate */
		fieldName: string;
		/** Current field value */
		fieldValue?: string;
		/** Character context */
		characterContext?: CharacterContext;
		/** Callback when content is generated */
		onGenerate?: (content: string) => void;
		/** Callback to close dialog */
		onOpenChange?: (open: boolean) => void;
	}

	let {
		open = $bindable(false),
		fieldName,
		fieldValue = '',
		characterContext,
		onGenerate,
		onOpenChange
	}: Props = $props();

	// Generation state
	let mode = $state<GenerationMode>('create');
	let style = $state<DescriptionStyle>('auto');
	let userPrompt = $state('');
	let maxTokens = $state(1000);
	let includeStatusBlock = $state(false);
	let generatedContent = $state('');
	let isGenerating = $state(false);
	let streamedContent = $state('');
	let error = $state<string | null>(null);
	let copied = $state(false);

	// Mode options
	const modeOptions: { value: GenerationMode; label: string; description: string }[] = [
		{ value: 'create', label: 'Create', description: 'Generate new content from scratch' },
		{ value: 'enhance', label: 'Enhance', description: 'Improve existing content' },
		{ value: 'expand', label: 'Expand', description: 'Add more detail' },
		{ value: 'rewrite', label: 'Rewrite', description: 'Rewrite with fresh perspective' }
	];

	// All style options with labels
	const allStyleOptions: { value: DescriptionStyle; label: string }[] = [
		{ value: 'auto', label: 'Auto (recommended)' },
		{ value: 'traits', label: 'Traits (comma-separated)' },
		{ value: 'narrative', label: 'Narrative (flowing prose)' },
		{ value: 'profile', label: 'Profile (structured)' },
		{ value: 'group', label: 'Group (team dynamics)' },
		{ value: 'worldbuilding', label: 'Worldbuilding (setting context)' },
		{ value: 'system', label: 'System (technical)' }
	];

	// Filter modes based on field compatibility
	const availableModes = $derived(modeOptions.filter((m) => isModeSupported(fieldName, m.value)));

	// Filter styles based on field compatibility
	const availableStyles = $derived.by(() => {
		const allowedStyles = getAvailableStyles(fieldName);
		return allStyleOptions.filter((opt) => allowedStyles.includes(opt.value));
	});

	// Status block makes sense for instruction fields AND example messages
	const showStatusBlockOption = $derived(
		fieldName === 'description' ||
			fieldName === 'system_prompt' ||
			fieldName === 'post_history_instructions' ||
			fieldName === 'mes_example'
	);

	// Different handling for mes_example vs instruction fields
	const isExampleField = $derived(fieldName === 'mes_example');

	// Auto-select recommended style and token limit when field changes
	$effect(() => {
		if (fieldName) {
			style = getRecommendedStyle(fieldName);
			maxTokens = getRecommendedMaxTokens(fieldName);
		}
	});

	// Handle generation
	async function handleGenerate(useStreaming: boolean = true) {
		isGenerating = true;
		error = null;
		generatedContent = '';
		streamedContent = '';

		try {
			// Build user prompt with optional status block instructions
			let finalUserPrompt = userPrompt || '';
			if (includeStatusBlock && showStatusBlockOption) {
				if (isExampleField) {
					// For mes_example: generate examples that INCLUDE status blocks
					const statusBlockExampleInstructions = `

IMPORTANT: Each conversation example should end with {{char}} displaying a status block wrapped in triple backticks (\`\`\`).

The status block should:
- Be wrapped in triple backticks (three backtick characters before and after)
- Track relevant game state (health, location, inventory, stats, objectives, etc.)
- Be contextually appropriate for this character/setting
- Update between conversation examples to show state changes

Example format for EACH conversation example:
<START>
{{char}}: "Dialogue..." *Action.*
{{user}}: "Response..."
{{char}}: "Reply..." *Action.*

\`\`\`
[Status fields here - health, location, inventory, stats, etc.]
\`\`\`

Make sure EVERY conversation example ends with a status block in triple backticks.`;
					finalUserPrompt += statusBlockExampleInstructions;
				} else {
					// For instruction fields: generate instructions ABOUT status blocks
					const statusBlockInstructions = `

IMPORTANT: Generate instructions that tell the AI to include a status block at the end of every response.

The instructions you write MUST specify that the status block should be wrapped in triple backticks (three backtick characters: \`\`\`).

Example of what you should generate:
"{{char}} will always end each response with a status block wrapped in triple backticks. The format is:

\`\`\`
[Define specific status fields here - health, location, inventory, stats, objectives, etc.]
\`\`\`

The status block must use triple backticks for proper formatting."

Key requirements:
- Explicitly mention triple backticks in your instructions
- Define specific status fields contextually appropriate to this setting
- Specify that the block updates dynamically based on roleplay events
- The status block should be formatted consistently for easy parsing

NOTE: Since the AI cannot perform true dice rolls, if game mechanics require randomness, specify that outcomes will be narratively simulated based on stats and circumstances.

DO NOT generate an actual status block in your output - only generate the INSTRUCTIONS about how the status block should work.`;
					finalUserPrompt += statusBlockInstructions;
				}
			}

			if (useStreaming) {
				// Streaming generation
				const stream = generateStream({
					fieldName,
					fieldValue: mode === 'create' ? undefined : fieldValue,
					characterContext,
					mode,
					style,
					userPrompt: finalUserPrompt || undefined,
					maxTokens
				});

				for await (const chunk of stream) {
					if (chunk.done) {
						// Final chunk with metadata
						// Sanitize the complete accumulated content
						generatedContent = sanitizeAIOutput(streamedContent);
						console.log('Generation complete:', chunk.metadata);
					} else {
						// Accumulate content (raw, unsanitized)
						streamedContent += chunk.content;
					}
				}
			} else {
				// Non-streaming generation
				const result = await generate({
					fieldName,
					fieldValue: mode === 'create' ? undefined : fieldValue,
					characterContext,
					mode,
					style,
					userPrompt: finalUserPrompt || undefined,
					maxTokens
				});

				generatedContent = result.content;
				console.log('Generation complete:', result.metadata);
			}
		} catch (err) {
			if (err instanceof Error) {
				error = err.message;
			} else {
				error = 'Unknown error occurred';
			}
		} finally {
			isGenerating = false;
		}
	}

	// Copy to clipboard
	async function copyToClipboard() {
		const content = generatedContent || streamedContent;
		if (!content) return;

		try {
			await navigator.clipboard.writeText(content);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	// Accept and apply generation
	function acceptGeneration() {
		const content = generatedContent || streamedContent;
		if (content) {
			onGenerate?.(content);
			open = false;
		}
	}

	// Approximate word count (tokens * 0.75)
	const approximateWords = $derived(Math.round(maxTokens * 0.75));

	// Reset on dialog close
	$effect(() => {
		if (!open) {
			generatedContent = '';
			streamedContent = '';
			error = null;
			userPrompt = '';
		}
	});
</script>

<Dialog bind:open {onOpenChange}>
	<DialogContent class="max-h-[90vh] max-w-3xl overflow-y-auto">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<Sparkles class="h-5 w-5" />
				AI Assistant: {fieldName}
			</DialogTitle>
		</DialogHeader>

		<div class="space-y-4">
			<!-- Mode Selection -->
			<div class="space-y-2">
				<Label>Mode</Label>
				<div class="grid grid-cols-2 gap-2">
					{#each availableModes as modeOption (modeOption.value)}
						<button
							type="button"
							class="rounded-md border-2 p-3 text-left transition-colors {mode === modeOption.value
								? 'border-primary bg-primary/10'
								: 'border-border hover:border-primary/50'}"
							onclick={() => (mode = modeOption.value)}
						>
							<div class="font-semibold">{modeOption.label}</div>
							<div class="text-sm text-muted-foreground">{modeOption.description}</div>
						</button>
					{/each}
				</div>
			</div>

			<!-- Style Selection -->
			<div class="space-y-2">
				<Label for="style">Style</Label>
				<select
					id="style"
					class="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
					bind:value={style}
				>
					{#each availableStyles as styleOption (styleOption.value)}
						<option value={styleOption.value}>{styleOption.label}</option>
					{/each}
				</select>
			</div>

			<!-- Status Block Option -->
			{#if showStatusBlockOption}
				<div class="flex items-center space-x-2">
					<Checkbox id="status-block" bind:checked={includeStatusBlock} />
					<Label
						for="status-block"
						class="cursor-pointer text-sm font-normal leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
					>
						{#if isExampleField}
							Include status blocks in conversation examples (for RPG/system cards)
						{:else}
							Include status block instructions (for RPG/system cards)
						{/if}
					</Label>
				</div>
			{/if}

			<!-- Token Limit -->
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<Label for="token-limit">Generation Length</Label>
					<span class="text-sm text-muted-foreground">
						{maxTokens} tokens (~{approximateWords} words)
					</span>
				</div>
				<Slider
					id="token-limit"
					type="single"
					min={500}
					max={5000}
					step={100}
					value={maxTokens}
					onValueChange={(value: number) => (maxTokens = value)}
					class="w-full"
				/>
				<div class="flex justify-between text-xs text-muted-foreground">
					<span>Short (500)</span>
					<span>Medium (2500)</span>
					<span>Long (5000)</span>
				</div>
			</div>

			<!-- Custom Instructions -->
			<div class="space-y-2">
				<Label for="prompt">Additional Instructions (Optional)</Label>
				<Textarea
					id="prompt"
					bind:value={userPrompt}
					placeholder="Add specific requests or guidance for the AI..."
					rows={3}
				/>
			</div>

			<!-- Current Value (if enhancing/expanding/rewriting) -->
			{#if mode !== 'create' && fieldValue}
				<div class="space-y-2">
					<Label>Current Content</Label>
					<div class="whitespace-pre-wrap rounded-md bg-muted p-3 text-sm">
						{fieldValue}
					</div>
				</div>
			{/if}

			<!-- Generate Button -->
			<Button class="w-full" onclick={() => handleGenerate(true)} disabled={isGenerating}>
				{#if isGenerating}
					<Loader2 class="mr-2 h-4 w-4 animate-spin" />
					Generating...
				{:else}
					<Sparkles class="mr-2 h-4 w-4" />
					Generate
				{/if}
			</Button>

			<!-- Error Display -->
			{#if error}
				<div
					class="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive"
				>
					{error}
				</div>
			{/if}

			<!-- Generated Content -->
			{#if streamedContent || generatedContent}
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label>Generated Content</Label>
						<Button size="sm" variant="ghost" onclick={copyToClipboard}>
							{#if copied}
								<Check class="mr-1 h-4 w-4" />
								Copied
							{:else}
								<Copy class="mr-1 h-4 w-4" />
								Copy
							{/if}
						</Button>
					</div>
					<div
						class="max-h-96 overflow-y-auto whitespace-pre-wrap rounded-md border bg-background p-4 text-sm"
					>
						{streamedContent || generatedContent}
					</div>

					<!-- Accept Button -->
					<div class="flex gap-2">
						<Button class="flex-1" onclick={acceptGeneration}>Accept & Apply</Button>
						<Button
							variant="outline"
							onclick={() => {
								generatedContent = '';
								streamedContent = '';
							}}
						>
							Clear
						</Button>
					</div>
				</div>
			{/if}
		</div>
	</DialogContent>
</Dialog>
