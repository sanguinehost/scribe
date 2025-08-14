<script lang="ts">
	import { Button } from './ui/button';
	import { toast } from 'svelte-sonner';
	import { Sparkles, Wand2, RefreshCw, Plus } from 'lucide-svelte';
	import { apiClient } from '$lib/api';
	import type { GenerationMode, CharacterContext } from '$lib/types';

	type Props = {
		fieldName: string;
		fieldValue: string;
		characterContext?: CharacterContext;
		onGenerated: (generatedText: string) => void;
		disabled?: boolean;
		mode?: 'standalone' | 'inline'; // standalone for character editor, inline for chat
	};

	let { fieldName, fieldValue, characterContext, onGenerated, disabled = false, mode = 'standalone' }: Props = $props();

	let isGenerating = $state(false);

	async function handleGenerate(generationMode: GenerationMode) {
		if (mode === 'inline' && !fieldValue.trim()) {
			toast.error('Please enter some text to enhance');
			return;
		}

		try {
			isGenerating = true;
			
			// Use the character field generation API
			const result = await apiClient.generateCharacterField({
				field_name: fieldName,
				field_context: fieldValue || undefined,
				character_context: characterContext,
				generation_mode: generationMode
			});
			
			if (result.isOk()) {
				const generatedText = result.value.content;
				onGenerated(generatedText);
				
				const modeDescriptions = {
					create: 'generated',
					enhance: 'enhanced',
					rewrite: 'rewritten',
					expand: 'expanded'
				};
				
				toast.success(`${fieldName} ${modeDescriptions[generationMode]} successfully`);
			} else {
				console.error('Failed to generate content:', result.error);
				toast.error(result.error?.message || 'Failed to generate content');
			}
		} catch (error) {
			console.error('Error generating content:', error);
			toast.error('An error occurred while generating content');
		} finally {
			isGenerating = false;
		}
	}

	// Determine available actions based on context
	let hasContent = $derived(fieldValue && fieldValue.trim().length > 0);
	let canCreate = $derived(!hasContent);
	let canEnhance = $derived(hasContent);
	let canRewrite = $derived(hasContent);
	let canExpand = $derived(hasContent);
</script>

<div class="flex items-center gap-1">
	{#if mode === 'inline'}
		<!-- Inline mode: similar to expand button in chat -->
		{#if hasContent}
			<Button
				variant="ghost"
				size="sm"
				class="h-7 w-7 p-1.5"
				onclick={() => handleGenerate('enhance')}
				disabled={disabled || isGenerating}
				title="Enhance - Improve the current {fieldName}"
			>
				{#if isGenerating}
					<svg
						class="h-3.5 w-3.5 animate-spin"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
				{:else}
					<Sparkles size={14} />
				{/if}
			</Button>
		{/if}
	{:else}
		<!-- Standalone mode: full generation options for character editor -->
		{#if canCreate}
			<Button
				variant="ghost"
				size="sm"
				class="h-7 px-2 text-xs"
				onclick={() => handleGenerate('create')}
				disabled={disabled || isGenerating}
				title="Generate {fieldName} from scratch"
			>
				{#if isGenerating}
					<svg
						class="h-3.5 w-3.5 animate-spin mr-1"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Generating...
				{:else}
					<Plus size={14} class="mr-1" />
					Generate
				{/if}
			</Button>
		{/if}

		{#if canEnhance}
			<Button
				variant="ghost"
				size="sm"
				class="h-7 px-2 text-xs"
				onclick={() => handleGenerate('enhance')}
				disabled={disabled || isGenerating}
				title="Enhance the current {fieldName}"
			>
				{#if isGenerating}
					<svg
						class="h-3.5 w-3.5 animate-spin mr-1"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Enhancing...
				{:else}
					<Sparkles size={14} class="mr-1" />
					Enhance
				{/if}
			</Button>
		{/if}

		{#if canExpand}
			<Button
				variant="ghost"
				size="sm"
				class="h-7 px-2 text-xs"
				onclick={() => handleGenerate('expand')}
				disabled={disabled || isGenerating}
				title="Expand the current {fieldName} with more detail"
			>
				{#if isGenerating}
					<svg
						class="h-3.5 w-3.5 animate-spin mr-1"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Expanding...
				{:else}
					<Wand2 size={14} class="mr-1" />
					Expand
				{/if}
			</Button>
		{/if}

		{#if canRewrite}
			<Button
				variant="ghost"
				size="sm"
				class="h-7 px-2 text-xs"
				onclick={() => handleGenerate('rewrite')}
				disabled={disabled || isGenerating}
				title="Rewrite the {fieldName} with a fresh approach"
			>
				{#if isGenerating}
					<svg
						class="h-3.5 w-3.5 animate-spin mr-1"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Rewriting...
				{:else}
					<RefreshCw size={14} class="mr-1" />
					Rewrite
				{/if}
			</Button>
		{/if}
	{/if}
</div>