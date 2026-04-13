<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { Button as ButtonComponent } from '../ui/button';
	import { Textarea as TextareaComponent } from '../ui/textarea';
	import { Markdown } from '../markdown';
	import MessageActions from './message-actions.svelte';
	import TypewriterMessage from '../TypewriterMessage.svelte';
	import { segmentMessageContent, type ContentSegment } from '$lib/utils/parsers/widget-parser';
	import StatsWidget from '../widgets/StatsWidget.svelte';
	import { fly, fade, slide } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';
	import type { ScribeChatMessage, User, ScribeCharacter, ScribeChatSession } from '$lib/types';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar'; // Import Avatar components
	import ImageLightbox from '$lib/components/ui/image-lightbox.svelte';
	import { env } from '$env/dynamic/public';
	import { getLock } from '$lib/hooks/lock';
	import { streamingService, type StreamingMessage } from '$lib/services/StreamingService.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';

	// Make reactive to streaming service state
	let _streamingState = $derived(streamingService.getState());

	// Read message alignment preference
	let settingsStore: SettingsStore | null = null;
	try {
		settingsStore = SettingsStore.fromContext();
	} catch {
		// Settings store not available in this context, default to left
	}
	const isRightAligned = $derived(settingsStore?.messageAlignment === 'right');

	// Helper function to convert ScribeChatMessage to StreamingMessage
	function toStreamingMessage(msg: ScribeChatMessage): StreamingMessage {
		return {
			id: msg.id,
			content: msg.content,
			displayedContent: msg.content,
			sender: msg.message_type === 'User' ? 'user' : 'assistant',
			created_at: msg.created_at || new Date().toISOString(),
			isAnimating: false,
			shouldAnimate: msg.shouldAnimate ?? (msg.message_type === 'Assistant' && msg.loading), // Use defensive default
			isRegenerating: msg.isRegenerating ?? msg.loading,
			error: msg.error || undefined,
			retryable: msg.retryable,
			prompt_tokens: msg.prompt_tokens || undefined,
			completion_tokens: msg.completion_tokens || undefined,
			model_name: msg.model_name || undefined,
			backend_id: msg.backend_id,
			status: msg.status,
			contentVersion: msg.contentVersion ?? 0, // Preserve from source message for reactivity tracking
			reasoningContent: msg.reasoning_content || undefined,
			isThinking: msg.isThinking ?? msg.is_thinking ?? (msg.loading && !msg.content)
		};
	}

	let {
		message,
		readonly,
		loading: _loading,
		user, // Add user prop
		character, // Add character prop
		chat,
		onRetryMessage,
		onRetryFailedMessage,
		onEditMessage,
		onSaveEditedMessage,
		onDeleteMessage,
		onPreviousVariant,
		onNextVariant,
		onRepairFormat,
		hasVariants = false,
		variantInfo = null,
		substituteTemplateVariables = undefined,
		userPersonaName: _userPersonaName = 'User'
	}: {
		message: ScribeChatMessage;
		readonly?: boolean;
		loading?: boolean;
		user?: User; // Add user prop
		character?: ScribeCharacter | null; // Add character prop
		chat?: ScribeChatSession;
		hasVariants?: boolean;
		variantInfo?: { current: number; total: number } | null;
		onRetryMessage?: (messageId: string) => void;
		onRetryFailedMessage?: (messageId: string) => void;
		onEditMessage?: (messageId: string) => void;
		onSaveEditedMessage?: (messageId: string, newContent: string) => void;
		onDeleteMessage?: (messageId: string) => void;
		onPreviousVariant?: (messageId: string) => void;
		onNextVariant?: (messageId: string) => void;
		onRepairFormat?: (messageId: string) => void;
		substituteTemplateVariables?: (text: string, characterName: string) => string;
		userPersonaName?: string;
	} = $props();

	// Component lifecycle tracking (reduced logging)
	const componentId = $derived(`preview-${message?.id || 'unknown'}-${Math.random().toString(36).substr(2, 9)}`);

	$effect(() => {
		if (message) {
			console.log(
				`🆕 COMPONENT MOUNT: ${componentId} - Message ${message.id.slice(-8)} (${message.message_type}) loading: ${message.loading}`
			);
		}
	});

	// Track component destruction to catch unnecessary unmounting
	$effect(() => {
		return () => {
			if (message) {
				console.log(
					`❌ COMPONENT UNMOUNT: ${componentId} - Message ${message.id.slice(-8)} destroyed`
				);
			}
		};
	});

	// Edit mode state
	let isEditing = $state(false);
	let editedContent = $state('');

	// Apply template substitution to message content, following character-overview.svelte pattern
	const processedContent = $derived.by(() => {
		if (substituteTemplateVariables && character?.name) {
			return substituteTemplateVariables(message.content, character.name);
		}
		return message.content;
	});

	// Parse custom widgets out of the content
	const contentSegments = $derived.by(() => {
		return segmentMessageContent(processedContent);
	});

	// Avatar lightbox state
	let avatarLightboxOpen = $state(false);
	let avatarLightboxSrc = $state('');
	let avatarLightboxAlt = $state('');

	// Get scroll lock during component initialization
	const scrollLock = getLock('messages-scroll');

	// Get streaming state to check for typewriter animation - using the one defined at top

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
	function _isFirstMessage(_message: ScribeChatMessage): boolean {
		// Check if it's an Assistant message and has the expected first-message ID pattern
		// Note: We're being more conservative here and only checking the ID pattern
		// since this component doesn't have access to message position context
		return _message.message_type === 'Assistant' && _message.id.startsWith('first-message-');
	}

	// Debug logging removed for production

	// NOTE: Edit mode was removed as it depended on the Vercel SDK's message.parts structure.
	// let mode = $state<'view' | 'edit'>('view');
</script>

<div
	class="group/message mx-auto w-full max-w-3xl px-4"
	data-role={message.message_type.toLowerCase()}
	in:fly|global={{ opacity: 0, y: 20, duration: 400, easing: cubicOut }}
>
	<div
		class={cn(
			'flex w-full gap-4',
			{
				// Right-aligned user messages (ChatGPT-style)
				'ml-auto max-w-2xl flex-row-reverse': isRightAligned && message.message_type === 'User',
				// Left-aligned user messages (default/symmetric)
				'ml-auto max-w-2xl': !isRightAligned && message.message_type === 'User'
			}
		)}
	>
		<!-- Avatar container (hidden for right-aligned user messages) -->
		{#if !(isRightAligned && message.message_type === 'User')}
		<div class="size-8 shrink-0">
			{#if message.message_type === 'Assistant'}
				<Avatar
					class="size-8 transition-transform hover:scale-105 {characterAvatarSrc
						? 'cursor-pointer'
						: ''}"
					onclick={() => {
						if (characterAvatarSrc && character) {
							avatarLightboxSrc = characterAvatarSrc;
							avatarLightboxAlt = character.name;
							avatarLightboxOpen = true;
						}
					}}
				>
					{#if characterAvatarSrc && character}
						<AvatarImage src={characterAvatarSrc} alt={character?.name || 'Character'} />
					{/if}
					<AvatarFallback>
						{getInitials(character?.name)}
					</AvatarFallback>
				</Avatar>
			{:else if message.message_type === 'User'}
				<Avatar
					class="size-8 transition-transform hover:scale-105 {user?.avatar ? 'cursor-pointer' : ''}"
					onclick={() => {
						if (user?.avatar) {
							avatarLightboxSrc = user.avatar;
							avatarLightboxAlt = user.username || 'User';
							avatarLightboxOpen = true;
						}
					}}
				>
					{#if user?.avatar}
						<!-- Assuming user.avatar will be a URL -->
						<AvatarImage src={user.avatar} alt={user?.username || 'User'} />
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
		{/if}

		<div class="flex w-full flex-col gap-4">
			<!-- TODO: Re-evaluate attachment handling based on Scribe backend -->
			<!-- {#if message.experimental_attachments && message.experimental_attachments.length > 0} ... {/if} -->

			<!-- Render message content directly -->
			<div class="group relative">
				{#if isEditing}
					<!-- Edit mode for messages -->
					<div class="space-y-3">
						<TextareaComponent
							bind:value={editedContent}
							onkeydown={handleKeydown}
							placeholder="Edit message..."
							class="min-h-[80px] resize-none focus:ring-2 focus:ring-primary"
							autofocus
						/>
						<div class="flex justify-end gap-2">
							<ButtonComponent variant="outline" size="sm" onclick={cancelEditing}
								>Cancel</ButtonComponent
							>
							<ButtonComponent
								size="sm"
								onclick={saveEdit}
								disabled={!editedContent.trim() || editedContent.trim() === message.content}
							>
								Save Edit
							</ButtonComponent>
						</div>
					</div>
				{:else}
					<!-- Normal message display -->
					<div
						class={cn(
							'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 group relative w-full max-w-none break-words rounded-xl px-3 py-2 transition-colors duration-200',
							{
								'pb-5': !message.loading,
								'pb-4': message.loading,
								// User messages: tinted primary bubble
								'msg-user-bubble': message.message_type === 'User' && !message.error,
								// Assistant messages: card with left accent
								'msg-assistant-bubble shadow-sm': message.message_type === 'Assistant' && !message.error,
								// Right-aligned user bubbles get more rounded
								'rounded-2xl rounded-br-md': isRightAligned && message.message_type === 'User',
								// Error state
								'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950/20': message.error
							}
						)}
					>
						{#if message.reasoning_content}
							{@const isReasoningOpen = message.isThinking || message.is_thinking || (message.loading && !message.content)}
							<div
								class="mb-4 overflow-hidden rounded-lg border-l-2 bg-background/50 {isReasoningOpen ? 'animate-shimmer border-purple-500' : 'border-purple-400/60'}"
								transition:slide={{ duration: 300 }}
							>
								<div class="group/reasoning">
									<button
										type="button"
										class="flex w-full cursor-pointer items-center gap-2 px-3 py-2 text-left text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
										onclick={(e) => {
											// Allow manual toggle for historical messages, but keep auto-open for active thinking
											const target = e.currentTarget.nextElementSibling;
											if (target) {
												target.classList.toggle('hidden');
											}
										}}
									>
										<div class="flex items-center gap-2">
											{#if (message.isThinking || message.is_thinking || (message.loading && !message.content))}
												<div class="flex items-center gap-2" in:fade={{ duration: 200 }}>
													<span class="relative flex h-2 w-2">
														<span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-purple-500 opacity-75"></span>
														<span class="relative inline-flex h-2 w-2 rounded-full bg-purple-500"></span>
													</span>
													{#key 'thinking'}
														<span class="text-purple-600 dark:text-purple-400" in:fade={{ duration: 300 }}>Thinking...</span>
													{/key}
												</div>
											{:else}
												<div class="flex items-center gap-2" in:fade={{ duration: 200 }}>
													<svg class="h-3 w-3 transition-transform" class:rotate-90={isReasoningOpen} fill="none" viewBox="0 0 24 24" stroke="currentColor">
														<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
													</svg>
													{#key 'processed'}
														<span in:fade={{ duration: 300 }}>Thought Process</span>
													{/key}
												</div>
											{/if}
										</div>
									</button>

									{#if isReasoningOpen}
										<div
											class="max-h-60 overflow-y-auto border-t border-border/50 bg-muted/30 px-3 py-3 text-sm text-muted-foreground"
											transition:slide={{ duration: 300 }}
										>
											<div class="prose prose-sm prose-invert max-w-none dark:prose-invert">
												<p class="whitespace-pre-wrap text-xs leading-relaxed">{message.reasoning_content}</p>
											</div>
										</div>
									{:else}
										<!-- For non-thinking messages that still have content, allow manual collapse/expand via hidden class (simplest for now) -->
										<div class="hidden max-h-60 overflow-y-auto border-t border-border/50 bg-muted/30 px-3 py-3 text-sm text-muted-foreground">
											<div class="prose prose-sm prose-invert max-w-none dark:prose-invert">
												<p class="whitespace-pre-wrap text-xs leading-relaxed">{message.reasoning_content}</p>
											</div>
										</div>
									{/if}
								</div>
							</div>
						{/if}

						{#if message.error}
							<!-- Error state display -->
							<div class="mb-3 flex items-start gap-3">
								<div class="mt-1 flex-shrink-0 text-red-500">
									<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
										<path
											fill-rule="evenodd"
											d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z"
											clip-rule="evenodd"
										/>
									</svg>
								</div>
								<div class="flex-1">
									<p class="text-sm font-medium text-red-700 dark:text-red-300">
										Generation failed
									</p>
									<p class="mt-1 text-sm text-red-600 dark:text-red-400">
										{message.error}
									</p>
									{#if message.retryable && onRetryFailedMessage}
										<ButtonComponent
											variant="outline"
											size="sm"
											class="mt-2 border-red-300 text-red-700 hover:bg-red-50 dark:border-red-700 dark:text-red-300 dark:hover:bg-red-950/30"
											onclick={() => onRetryFailedMessage?.(message.id)}
										>
											<svg
												class="mr-2 h-4 w-4"
												fill="none"
												stroke="currentColor"
												viewBox="0 0 24 24"
											>
												<path
													stroke-linecap="round"
													stroke-linejoin="round"
													stroke-width="2"
													d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
												/>
											</svg>
											Retry
										</ButtonComponent>
									{/if}
								</div>
							</div>
							{#if message.content}
								<!-- Show partial content if any was generated before the error -->
								<div class="mt-3 border-t border-red-200 pt-3 dark:border-red-800">
									<p class="mb-2 text-xs text-red-600 dark:text-red-400">Partial response:</p>
									{#key `${message.id}-partial-${message.current_variant_index || 0}`}
										{#each contentSegments as segment}
											{#if segment.type === 'markdown'}
												<Markdown md={segment.content} />
											{:else if segment.type === 'widget' && segment.widgetType === 'stats'}
												<StatsWidget rawData={segment.rawData} messageId={message.id} onRepair={onRepairFormat ? () => onRepairFormat(message.id) : undefined} />
											{/if}
										{/each}
									{/key}
								</div>
							{/if}
						{:else}
							<!-- Normal content display -->
							{#if message.message_type === 'Assistant'}
								<!-- FORCE TypewriterMessage for ALL Assistant messages to prevent transition -->
								<TypewriterMessage
									message={toStreamingMessage(message)}
									className="prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words"
									onRepairFormat={onRepairFormat}
								/>
							{:else}
								<!-- All other messages (including User messages) use regular markdown -->
								<div
									class="prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words"
								>
									{#key `${message.id}-${message.current_variant_index || 0}`}
										{#each contentSegments as segment}
											{#if segment.type === 'markdown'}
												<Markdown md={segment.content} />
											{:else if segment.type === 'widget' && segment.widgetType === 'stats'}
												<StatsWidget rawData={segment.rawData} messageId={message.id} />
											{/if}
										{/each}
									{/key}
								</div>
							{/if}
						{/if}
					</div>
				{/if}

				<!-- Per-message token indicator - always reserve space for Assistant messages -->
				{#if message.message_type === 'Assistant'}
					{@const model = message.model_name || chat?.model_name || 'gemini-2.5-pro'}
					{@const pricing = {
						// Customer-facing prices with 20% markup over Google API base rates
						'gemini-2.5-flash': { input: 0.36, output: 3.0 }, // Base: $0.30/$2.50, +20% = $0.36/$3.00
						'gemini-2.5-flash-preview-09-2025': { input: 0.36, output: 3.0 }, // Same as flash
						'gemini-2.5-flash-image': { input: 0.36, output: 3.0 }, // Same as flash
						'gemini-2.5-pro': { input: 1.5, output: 12.0 }, // Base: $1.25/$10.00, +20% = $1.50/$12.00
						'gemini-2.5-flash-lite-preview-09-2025': { input: 0.12, output: 0.48 } // Base: $0.10/$0.40, +20% = $0.12/$0.48
					}[model] || { input: 1.5, output: 12.0 }}
					{@const inputCost = ((message.prompt_tokens || 0) / 1_000_000) * pricing.input}
					{@const outputCost = ((message.completion_tokens || 0) / 1_000_000) * pricing.output}
					{@const totalCost = inputCost + outputCost}
					{@const formatCost = (cost: number) =>
						cost < 0.0001 ? '<$0.0001' : `$${cost.toFixed(4)}`}
					{@const hasTokens = !!(message.prompt_tokens || message.completion_tokens)}
					{@const isCompleted = !message.loading}

					<!-- Always render container, control visibility with opacity -->
					<div
						class="absolute right-2 top-2 transition-opacity duration-200 {isCompleted && hasTokens
							? 'opacity-0 group-hover:opacity-100'
							: 'opacity-0'}"
						title={isCompleted && hasTokens
							? `Model: ${model}${'\n'}Input: ${message.prompt_tokens || 0} tokens (${formatCost(inputCost)})${'\n'}Output: ${message.completion_tokens || 0} tokens (${formatCost(outputCost)})${'\n'}Total cost: ${formatCost(totalCost)}`
							: message.loading
								? 'Generating...'
								: 'Tokens loading...'}
					>
						<div
							class="flex items-center gap-1 rounded-md border border-border bg-background/90 px-2 py-1 text-xs text-muted-foreground shadow-sm backdrop-blur-sm"
						>
							{#if isCompleted && hasTokens}
								{#if message.prompt_tokens && message.prompt_tokens > 0}
									<span class="text-blue-600 dark:text-blue-400">
										↑{message.prompt_tokens >= 1000
											? `${(message.prompt_tokens / 1000).toFixed(1)}k`
											: message.prompt_tokens}
									</span>
								{/if}
								{#if message.completion_tokens && message.completion_tokens > 0}
									<span class="text-green-600 dark:text-green-400">
										↓{message.completion_tokens >= 1000
											? `${(message.completion_tokens / 1000).toFixed(1)}k`
											: message.completion_tokens}
									</span>
								{/if}
								<span class="font-mono text-[10px] text-amber-600 dark:text-amber-400">
									{formatCost(totalCost)}
								</span>
							{:else}
								<!-- Placeholder content to maintain layout during loading/waiting -->
								<span class="text-[10px] text-muted-foreground/30">
									{message.loading ? '⋯' : '•••'}
								</span>
							{/if}
						</div>
					</div>
				{/if}

				<!-- Modern message actions - always reserve space, show when ready -->
				{#if !isEditing}
					{@const isLoadingOrAnimating = message.loading}
					<div
						class="absolute bottom-2 right-2 transition-opacity duration-200"
						class:opacity-0={isLoadingOrAnimating || readonly}
						class:group-hover:opacity-100={!isLoadingOrAnimating && !readonly}
						class:pointer-events-none={isLoadingOrAnimating || readonly}
					>
						<MessageActions
							{message}
							{readonly}
							loading={isLoadingOrAnimating}
							{hasVariants}
							{variantInfo}
							onRetry={() => onRetryMessage?.(message.id)}
							onEdit={() => {
								startEditing();
							}}
							onDelete={() => onDeleteMessage?.(message.id)}
							onPreviousVariant={() => onPreviousVariant?.(message.id)}
							onNextVariant={() => onNextVariant?.(message.id)}
						/>
					</div>
				{/if}
			</div>
		</div>
	</div>
</div>

<!-- Avatar Lightbox -->
<ImageLightbox
	bind:open={avatarLightboxOpen}
	src={avatarLightboxSrc}
	alt={avatarLightboxAlt}
	onClose={() => {
		avatarLightboxOpen = false;
		avatarLightboxSrc = '';
		avatarLightboxAlt = '';
	}}
/>

<style>
	.loading-spinner {
		width: 16px;
		height: 16px;
		border: 2px solid transparent;
		border-top: 2px solid currentColor;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		0% {
			transform: rotate(0deg);
		}
		100% {
			transform: rotate(360deg);
		}
	}
</style>
