<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
	import { Button } from '../ui/button';
	import { Textarea } from '../ui/textarea';
	import PencilEditIcon from '../icons/pencil-edit.svelte';
	import PreviewAttachment from '../preview-attachment.svelte';
	import { Markdown } from '../markdown';
	import MessageReasoning from '../message-reasoning.svelte';
	import MessageActions from './message-actions.svelte';
	import { fly } from 'svelte/transition';
	import type { ScribeChatMessage, User, ScribeCharacter } from '$lib/types'; // Import User and ScribeCharacter
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar'; // Import Avatar components
	import { env } from '$env/dynamic/public';

	let {
		message,
		readonly,
		loading,
		user, // Add user prop
		character, // Add character prop
		onRetryMessage,
		onEditMessage,
		onSaveEditedMessage,
		onPreviousVariant,
		onNextVariant,
		hasVariants = false,
		variantInfo = null
	}: {
		message: ScribeChatMessage;
		readonly: boolean;
		loading: boolean;
		user: User | undefined; // Define type for user
		character: ScribeCharacter | null | undefined; // Define type for character
		onRetryMessage?: (messageId: string) => void;
		onEditMessage?: (messageId: string) => void;
		onSaveEditedMessage?: (messageId: string, newContent: string) => void;
		onPreviousVariant?: (messageId: string) => void;
		onNextVariant?: (messageId: string) => void;
		hasVariants?: boolean;
		variantInfo?: { current: number; total: number } | null;
	} = $props();

	// Edit mode state
	let isEditing = $state(false);
	let editedContent = $state('');

	// Function to get initials for fallback avatar
	function getInitials(name: string | undefined | null): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Edit mode functions
	function startEditing() {
		isEditing = true;
		editedContent = message.content;
	}

	function cancelEditing() {
		isEditing = false;
		editedContent = '';
	}

	function saveEdit() {
		if (editedContent.trim() && editedContent.trim() !== message.content) {
			onSaveEditedMessage?.(message.id, editedContent.trim());
		}
		isEditing = false;
		editedContent = '';
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
			event.preventDefault();
			saveEdit();
		} else if (event.key === 'Escape') {
			event.preventDefault();
			cancelEditing();
		}
	}

	// Create properly formatted avatar URL for character
	const characterAvatarSrc = $derived.by(() => {
		if (!character?.avatar) return null;
		
		// If avatar already has a full URL, use it as-is
		if (character.avatar.startsWith('http://') || character.avatar.startsWith('https://')) {
			return character.avatar;
		}
		
		// Otherwise, prepend the API URL
		const apiBaseUrl = (env.PUBLIC_API_URL || '').trim();
		return `${apiBaseUrl}${character.avatar}`;
	});

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
				{#if characterAvatarSrc}
					<AvatarImage src={characterAvatarSrc} alt={character.name} />
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
			<div class="relative group">
				{#if isEditing && message.message_type === 'User'}
					<!-- Edit mode for user messages -->
					<div class="space-y-3">
						<Textarea
							bind:value={editedContent}
							onkeydown={handleKeydown}
							placeholder="Edit your message..."
							class="min-h-[80px] resize-none focus:ring-2 focus:ring-primary"
							autofocus
						/>
						<div class="flex gap-2 justify-end">
							<Button
								variant="outline"
								size="sm"
								onclick={cancelEditing}
							>
								Cancel
							</Button>
							<Button
								size="sm"
								onclick={saveEdit}
								disabled={!editedContent.trim() || editedContent.trim() === message.content}
							>
								Save & Send
							</Button>
						</div>
					</div>
				{:else}
					<!-- Normal message display -->
					<div
						class={cn(
							'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words rounded-md border bg-background px-3 py-2 pb-8',
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
				{/if}

				<!-- Modern message actions - positioned at bottom-right -->
				{#if !isEditing}
					<div class="absolute bottom-2 right-2 transition-opacity duration-200" 
						 class:opacity-0={message.loading || readonly}
						 class:opacity-100={!message.loading && !readonly}
						 class:pointer-events-none={message.loading || readonly}>
						<MessageActions 
							{message} 
							{readonly}
							loading={message.loading}
							{hasVariants}
							{variantInfo}
							onRetry={() => onRetryMessage?.(message.id)}
							onEdit={() => {
								if (message.message_type === 'User') {
									startEditing();
								} else {
									onEditMessage?.(message.id);
								}
							}}
							onPreviousVariant={() => onPreviousVariant?.(message.id)}
							onNextVariant={() => onNextVariant?.(message.id)}
						/>
					</div>
				{/if}
			</div>
		</div>
	</div>
</div>
