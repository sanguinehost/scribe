<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { Button } from '../ui/button';
	import { Textarea } from '../ui/textarea';
	import PencilEditIcon from '../icons/pencil-edit.svelte';
	import PreviewAttachment from '../preview-attachment.svelte';
	import { Markdown } from '../markdown';
	import MessageReasoning from '../message-reasoning.svelte';
	import MessageActions from './message-actions.svelte';
	import TokenUsageDisplay from '../token-usage-display.svelte';
	import { fly } from 'svelte/transition';
	import type {
		ScribeChatMessage,
		User,
		ScribeCharacter,
		ScribeChatSession
	} from '$lib/types'; // Import User and ScribeCharacter
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar'; // Import Avatar components
	import { env } from '$env/dynamic/public';
	import { getLock } from '$lib/hooks/lock';

	let {
		message,
		readonly,
		loading,
		user, // Add user prop
		character, // Add character prop
		chat,
		onRetryMessage,
		onRetryFailedMessage,
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
		chat: ScribeChatSession | undefined;
		onRetryMessage?: (messageId: string) => void;
		onRetryFailedMessage?: (messageId: string) => void;
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
	
	// Get scroll lock during component initialization
	const scrollLock = getLock('messages-scroll');

	// Function to get initials for fallback avatar
	function getInitials(name: string | undefined | null): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Edit mode functions
	function startEditing() {
		// Lock scrolling before making DOM changes
		scrollLock.locked = true;
		
		isEditing = true;
		editedContent = message.content;
		
		// Unlock after DOM has settled
		setTimeout(() => {
			scrollLock.locked = false;
		}, 200);
	}

	function cancelEditing() {
		// Lock scrolling before making DOM changes
		scrollLock.locked = true;
		
		isEditing = false;
		editedContent = '';
		
		// Unlock after DOM has settled
		setTimeout(() => {
			scrollLock.locked = false;
		}, 200);
	}

	function saveEdit() {
		if (editedContent.trim() && editedContent.trim() !== message.content) {
			onSaveEditedMessage?.(message.id, editedContent.trim());
		}
		
		// Lock scrolling before making DOM changes
		scrollLock.locked = true;
		
		isEditing = false;
		editedContent = '';
		
		// Unlock after DOM has settled
		setTimeout(() => {
			scrollLock.locked = false;
		}, 200);
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
		<!-- Avatar container (simplified) -->
		<div class="size-8 shrink-0">
			{#if message.message_type === 'Assistant'}
				<Avatar class="size-8">
					{#if characterAvatarSrc && character}
						<AvatarImage src={characterAvatarSrc} alt={character.name} />
					{/if}
					<AvatarFallback>
						{getInitials(character?.name)}
					</AvatarFallback>
				</Avatar>
			{:else if message.message_type === 'User'}
				<Avatar class="size-8">
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
					class="flex size-8 items-center justify-center rounded-full bg-background ring-1 ring-border"
				>
					<div class="translate-y-px">
						<SparklesIcon size={14} />
					</div>
				</div>
			{/if}
		</div>

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
							'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words rounded-md border bg-background px-3 py-2 pb-8 relative group',
							{
								'border-primary/10 bg-primary/10': message.message_type === 'User',
								'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950/20': message.error
							}
						)}
					>
						{#if message.error}
							<!-- Error state display -->
							<div class="flex items-start gap-3 mb-3">
								<div class="flex-shrink-0 text-red-500 mt-1">
									<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
										<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
									</svg>
								</div>
								<div class="flex-1">
									<p class="text-red-700 dark:text-red-300 font-medium text-sm">
										Generation failed
									</p>
									<p class="text-red-600 dark:text-red-400 text-sm mt-1">
										{message.error}
									</p>
									{#if message.retryable && onRetryFailedMessage}
										<Button
											variant="outline"
											size="sm"
											class="mt-2 border-red-300 text-red-700 hover:bg-red-50 dark:border-red-700 dark:text-red-300 dark:hover:bg-red-950/30"
											onclick={() => onRetryFailedMessage?.(message.id)}
										>
											<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
												<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
											</svg>
											Retry
										</Button>
									{/if}
								</div>
							</div>
							{#if message.content}
								<!-- Show partial content if any was generated before the error -->
								<div class="border-t border-red-200 dark:border-red-800 pt-3 mt-3">
									<p class="text-xs text-red-600 dark:text-red-400 mb-2">Partial response:</p>
									<Markdown md={message.content} />
								</div>
							{/if}
						{:else}
							<!-- Normal content display -->
							<Markdown md={message.content} />
							{#if message.message_type === 'Assistant' && message.loading}
								<span class="ml-1 inline-block h-4 w-0.5 animate-pulse bg-foreground"></span>
							{/if}
						{/if}
					</div>
				{/if}

				<!-- Per-message token indicator on hover with cost (only for Assistant messages) -->
				{#if !message.loading && message.message_type === 'Assistant' && (message.prompt_tokens || message.completion_tokens)}
					{@const model = message.model_name || chat?.model_name || 'gemini-2.5-pro'}
					{@const pricing = {
						'gemini-2.5-flash': { input: 0.30, output: 2.50 },
						'gemini-2.5-pro': { input: 1.25, output: 10.00 },
						'gemini-2.5-flash-lite-preview': { input: 0.10, output: 0.40 }
					}[model] || { input: 1.25, output: 10.00 }}
					{@const inputCost = (message.prompt_tokens || 0) / 1_000_000 * pricing.input}
					{@const outputCost = (message.completion_tokens || 0) / 1_000_000 * pricing.output}
					{@const totalCost = inputCost + outputCost}
					{@const formatCost = (cost: number) => cost < 0.0001 ? '<$0.0001' : `$${cost.toFixed(4)}`}
					
					<div 
						class="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
						title={`Model: ${model}${'\n'}Input: ${message.prompt_tokens || 0} tokens (${formatCost(inputCost)})${'\n'}Output: ${message.completion_tokens || 0} tokens (${formatCost(outputCost)})${'\n'}Total cost: ${formatCost(totalCost)}`}
					>
						<div class="flex items-center gap-1 px-2 py-1 bg-background/90 backdrop-blur-sm border border-border rounded-md text-xs text-muted-foreground shadow-sm">
							{#if message.prompt_tokens && message.prompt_tokens > 0}
								<span class="text-blue-600 dark:text-blue-400">
									↑{message.prompt_tokens >= 1000 ? `${(message.prompt_tokens / 1000).toFixed(1)}k` : message.prompt_tokens}
								</span>
							{/if}
							{#if message.completion_tokens && message.completion_tokens > 0}
								<span class="text-green-600 dark:text-green-400">
									↓{message.completion_tokens >= 1000 ? `${(message.completion_tokens / 1000).toFixed(1)}k` : message.completion_tokens}
								</span>
							{/if}
							<span class="text-amber-600 dark:text-amber-400 font-mono text-[10px]">
								{formatCost(totalCost)}
							</span>
						</div>
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
