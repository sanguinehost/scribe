<script lang="ts">
	import { Button } from './ui/button';
	import { Bot } from 'lucide-svelte';
	import AiAssistantDialog from './ai-assistant-dialog-v2.svelte';
	import type { CharacterContext } from '$lib/types';

	type Props = {
		fieldName: string;
		fieldValue: string;
		characterContext?: CharacterContext;
		onGenerated: (generatedText: string) => void;
		disabled?: boolean;
		variant?: 'compact' | 'full'; // UI density
	};

	let { 
		fieldName, 
		fieldValue, 
		characterContext, 
		onGenerated, 
		disabled = false,
		variant = 'full'
	}: Props = $props();

	let dialogOpen = $state(false);
</script>

<!-- AI Assistant Button -->
<Button
	variant="ghost"
	size="sm"
	class={variant === 'compact' ? 'h-7 px-2 text-xs' : 'h-7 w-7 p-1.5'}
	onclick={() => dialogOpen = true}
	disabled={disabled}
	title="AI Assistant - Generate or enhance {fieldName}"
>
	<Bot size={14} class={variant === 'compact' ? 'mr-1' : ''} />
	{#if variant === 'compact'}
		AI
	{/if}
</Button>

<!-- AI Assistant Dialog -->
<AiAssistantDialog
	bind:open={dialogOpen}
	{fieldName}
	{fieldValue}
	{characterContext}
	{onGenerated}
	onOpenChange={(open) => dialogOpen = open}
/>