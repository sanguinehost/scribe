<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import {
		ChevronLeft,
		ChevronRight,
		MoreHorizontal,
		Copy,
		Code,
		RotateCcw,
		Edit,
		Trash2,
		Brain
	} from 'lucide-svelte';
	import { clickOutside } from '$lib/utils/click-outside';
	import RawPromptModal from './raw-prompt-modal.svelte';
	import AgentAnalysisModal from './agent-analysis-modal.svelte';
	import type { ScribeChatMessage } from '$lib/types';

	let {
		message,
		readonly = false,
		loading = false,
		onRetry,
		onEdit,
		onDelete,
		onPreviousVariant,
		onNextVariant,
		hasVariants = false,
		variantInfo = null
	}: {
		message: ScribeChatMessage;
		readonly?: boolean;
		loading?: boolean;
		onRetry?: () => void;
		onEdit?: () => void;
		onDelete?: () => void;
		onPreviousVariant?: () => void;
		onNextVariant?: () => void;
		hasVariants?: boolean;
		variantInfo?: { current: number; total: number } | null;
	} = $props();

	let showRawPromptModal = $state(false);
	let showAgentAnalysisModal = $state(false);
	let showDropdown = $state(false);
	let copyClicked = $state(false);

	function isFirstMessage(message: ScribeChatMessage): boolean {
		return message.message_type === 'Assistant' && message.id.startsWith('first-message-');
	}

	async function copyToClipboard() {
		try {
			copyClicked = true;
			await navigator.clipboard.writeText(message.content);
			// Reset the visual state after a brief moment
			setTimeout(() => {
				copyClicked = false;
			}, 150);
		} catch (err) {
			console.error('Failed to copy:', err);
			copyClicked = false;
		}
	}

	function toggleDropdown() {
		showDropdown = !showDropdown;
	}

	function closeDropdown() {
		showDropdown = false;
	}
</script>

<div
	class="flex items-center gap-1 opacity-0 transition-opacity duration-200 group-hover:opacity-100"
>
	{#if message.message_type === 'Assistant' && !readonly && !isFirstMessage(message)}
		<!-- Left/Right chevrons for response variants -->
		<div class="flex items-center gap-1">
			<Button
				variant="ghost"
				size="sm"
				class="h-6 w-6 rounded-md border border-border/40 bg-background/80 p-0 shadow-sm backdrop-blur-sm hover:bg-accent/80"
				onclick={() => onPreviousVariant?.()}
				disabled={loading || !hasVariants || variantInfo?.current === 0}
				title="Previous variant"
			>
				<ChevronLeft size={12} />
			</Button>

			{#if variantInfo}
				<span class="px-1 text-[9px] text-muted-foreground">
					{variantInfo.current + 1}/{variantInfo.total + 1}
				</span>
			{/if}

			<Button
				variant="ghost"
				size="sm"
				class="h-6 w-6 rounded-md border border-border/40 bg-background/80 p-0 shadow-sm backdrop-blur-sm hover:bg-accent/80"
				onclick={() => onNextVariant?.()}
				disabled={loading}
				title={hasVariants && variantInfo && variantInfo.current < variantInfo.total
					? 'Next variant'
					: 'Regenerate response'}
			>
				<ChevronRight size={12} />
			</Button>
		</div>
	{/if}

	<!-- Edit button for user messages -->
	{#if message.message_type === 'User' && !readonly}
		<Button
			variant="ghost"
			size="sm"
			class="h-6 w-6 rounded-md border border-border/40 bg-background/80 p-0 shadow-sm backdrop-blur-sm hover:bg-accent/80"
			onclick={() => onEdit?.()}
			disabled={loading}
			title="Edit message"
		>
			<Edit size={10} />
		</Button>
	{/if}

	<!-- Copy button -->
	<Button
		variant="ghost"
		size="sm"
		class="h-6 w-6 rounded-md border border-border/40 p-0 shadow-sm backdrop-blur-sm transition-colors duration-150 {copyClicked
			? 'bg-white text-black'
			: 'bg-background/80 hover:bg-accent/80'}"
		onclick={copyToClipboard}
		disabled={loading}
		title="Copy message"
	>
		<Copy size={10} />
	</Button>

	<!-- Delete button for user messages -->
	{#if message.message_type === 'User' && !readonly}
		<Button
			variant="ghost"
			size="sm"
			class="h-6 w-6 rounded-md border border-border/40 bg-background/80 p-0 text-destructive shadow-sm backdrop-blur-sm hover:bg-destructive/80"
			onclick={() => onDelete?.()}
			disabled={loading}
			title="Delete message"
		>
			<Trash2 size={10} />
		</Button>
	{/if}

	<!-- More actions dropdown (custom implementation) - only for AI messages -->
	{#if message.message_type === 'Assistant'}
		<div class="relative" use:clickOutside={closeDropdown}>
			<Button
				variant="ghost"
				size="sm"
				class="h-6 w-6 rounded-md border border-border/40 bg-background/80 p-0 shadow-sm backdrop-blur-sm hover:bg-accent/80"
				onclick={toggleDropdown}
				disabled={loading}
				title="More actions"
			>
				<MoreHorizontal size={10} />
			</Button>

			{#if showDropdown}
				<div
					class="absolute bottom-full right-0 z-50 mb-1 w-48 rounded-md border bg-popover text-popover-foreground shadow-md"
				>
					{#if !readonly}
						<button
							class="flex w-full items-center px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground"
							onclick={() => {
								onRetry?.();
								closeDropdown();
							}}
						>
							<RotateCcw size={14} class="mr-2" />
							Retry response
						</button>
						{#if !isFirstMessage(message)}
							<button
								class="flex w-full items-center px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground"
								onclick={() => {
									showRawPromptModal = true;
									closeDropdown();
								}}
							>
								<Code size={14} class="mr-2" />
								Show raw prompt
							</button>
							<button
								class="flex w-full items-center px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground"
								onclick={() => {
									showAgentAnalysisModal = true;
									closeDropdown();
								}}
							>
								<Brain size={14} class="mr-2" />
								Show agent analysis
							</button>
							<button
								class="flex w-full items-center px-3 py-2 text-sm text-destructive hover:bg-destructive/10 hover:text-destructive"
								onclick={() => {
									onDelete?.();
									closeDropdown();
								}}
							>
								<Trash2 size={14} class="mr-2" />
								Delete message
							</button>
						{/if}
					{/if}
				</div>
			{/if}
		</div>
	{/if}
</div>

<!-- Raw Prompt Modal -->
{#if !isFirstMessage(message)}
	<RawPromptModal bind:open={showRawPromptModal} messageId={message.backend_id || message.id} />
{/if}

<!-- Agent Analysis Modal -->
{#if !isFirstMessage(message) && message.message_type === 'Assistant'}
	<AgentAnalysisModal
		bind:open={showAgentAnalysisModal}
		messageId={message.backend_id || message.id}
		sessionId={message.session_id || ''}
	/>
{/if}
