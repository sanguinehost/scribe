<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
	import { Button } from '../ui/button';
	import PencilEditIcon from '../icons/pencil-edit.svelte';
	import PreviewAttachment from '../preview-attachment.svelte';
	import { Markdown } from '../markdown';
	import MessageReasoning from '../message-reasoning.svelte';
	import RawPromptDebug from './raw-prompt-debug.svelte';
	import { fly } from 'svelte/transition';
	import type { ScribeChatMessage, User, ScribeCharacter } from '$lib/types'; // Import User and ScribeCharacter
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar'; // Import Avatar components

	let {
		message,
		readonly,
		loading,
		user, // Add user prop
		character // Add character prop
	}: {
		message: ScribeChatMessage;
		readonly: boolean;
		loading: boolean;
		user: User | undefined; // Define type for user
		character: ScribeCharacter | null | undefined; // Define type for character
	} = $props();

	// Function to get initials for fallback avatar
	function getInitials(name: string | undefined | null): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Function to detect if a message is the first message from a character
	function isFirstMessage(message: ScribeChatMessage): boolean {
		// Check if it's an Assistant message and has the expected first-message ID pattern
		// Note: We're being more conservative here and only checking the ID pattern
		// since this component doesn't have access to message position context
		return message.message_type === 'Assistant' && message.id.startsWith('first-message-');
	}

	// Debug logging removed for production

	// NOTE: Edit mode was removed as it depended on the Vercel SDK's message.parts structure.
	// let mode = $state<'view' | 'edit'>('view');
</script>

<div
	class="group/message mx-auto w-full max-w-3xl px-4"
	data-role={message.message_type.toLowerCase()}
	in:fly|global={{ opacity: 0, y: 5 }}
>
	<div
		class={cn(
			'flex w-full gap-4 group-data-[role=user]/message:ml-auto group-data-[role=user]/message:max-w-2xl'
			// Removed mode === 'edit' check as edit mode is removed
			// {
			// 	'w-full': mode === 'edit',
			// 	'group-data-[role=user]/message:w-fit': mode !== 'edit'
			// }
		)}
	>
		{#if message.message_type === 'Assistant'}
			<Avatar class="size-8 shrink-0">
				{#if character?.avatar}
					<AvatarImage src={character.avatar} alt={character.name} />
				{/if}
				<AvatarFallback>
					{getInitials(character?.name)}
				</AvatarFallback>
			</Avatar>
		{:else if message.message_type === 'User'}
			<Avatar class="size-8 shrink-0">
				{#if user?.avatar}
					<!-- Assuming user.avatar will be a URL -->
					<AvatarImage src={user.avatar} alt={user.username} />
				{/if}
				<AvatarFallback>
					{getInitials(user?.username)}
				</AvatarFallback>
			</Avatar>
		{:else}
			<!-- Default icon for System messages or other types -->
			<div
				class="flex size-8 shrink-0 items-center justify-center rounded-full bg-background ring-1 ring-border"
			>
				<div class="translate-y-px">
					<SparklesIcon size={14} />
				</div>
			</div>
		{/if}

		<div class="flex w-full flex-col gap-4">
			<!-- TODO: Re-evaluate attachment handling based on Scribe backend -->
			<!-- {#if message.experimental_attachments && message.experimental_attachments.length > 0} ... {/if} -->

			<!-- Render message content directly -->
			<div
				class={cn(
					'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words rounded-md border bg-background px-3 py-2',
					{
						'border-primary/10 bg-primary/10': message.message_type === 'User'
					}
				)}
			>
				<Markdown md={message.content} />
				{#if message.message_type === 'Assistant' && message.loading}
					<span class="ml-1 inline-block h-4 w-0.5 animate-pulse bg-foreground"></span>
				{/if}
			</div>

			<!-- Raw Prompt Debug for Assistant messages (excluding first messages) -->
			{#if message.message_type === 'Assistant' && !message.loading && !isFirstMessage(message)}
				{#if message.raw_prompt}
					<RawPromptDebug rawPrompt={message.raw_prompt} />
				{:else}
					<!-- Debug: Show when raw_prompt is missing (but not for first messages) -->
					<div class="w-full">
						<div
							class="rounded border bg-yellow-50 p-2 text-xs text-muted-foreground dark:bg-yellow-900/20"
						>
							Debug: No raw_prompt data available for this message
						</div>
					</div>
				{/if}
			{/if}

			<!-- TODO: Re-implement message actions if needed -->
			<!-- {#if message.message_type === 'Assistant' && !readonly}
				<div class="flex w-full items-center justify-end gap-2">
					<Button variant="ghost" size="icon" class="size-8 text-muted-foreground">
						<CopyIcon size={14} />
					</Button>
				</div>
			{/if} -->
		</div>
	</div>
</div>
