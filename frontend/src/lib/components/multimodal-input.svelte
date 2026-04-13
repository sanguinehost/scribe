<script lang="ts">
	import PreviewAttachment from './preview-attachment.svelte';
	import { Textarea as _TextareaComponent } from './ui/textarea';
	import { cn as _cn } from '$lib/utils/shadcn';
	import { onMount } from 'svelte';
	// import { LocalStorage } from '$lib/hooks/local-storage.svelte'; // Unused? Let's remove for cleanup.
	// import { innerWidth } from 'svelte/reactivity/window'; // Unused? Let's remove for cleanup.
	import { toast } from 'svelte-sonner';
	import { Button as ButtonComponent } from './ui/button';
	import StopIcon from './icons/stop.svelte';
	import ImpersonateWidget from './impersonate-widget.svelte';
	import ContextEnrichmentButton from './context-enrichment-button.svelte';
	import ThinkingLevelSelector from './thinking-level-selector.svelte';
	import type { ScribeChatSession } from '$lib/types';
	// import { replaceState } from '$app/navigation'; // Unused? Let's remove for cleanup.

	// Define attachment interface
	interface AttachmentData {
		name?: string;
		url: string;
		contentType?: string;
	}

	// Props definition
	type Props = {
		attachments?: AttachmentData[]; // Make attachments optional
		value: string;
		isLoading: boolean;
		stopGeneration: () => void;
		chatId?: string; // Add chatId for impersonate/expand features
		onImpersonate?: (response: string) => void; // Callback for impersonate results
		agentMode?: 'disabled' | 'pre_processing' | 'post_processing'; // Context enrichment mode
		onAgentModeChange?: (mode: 'disabled' | 'pre_processing' | 'post_processing') => void; // Callback for mode changes
		chat?: ScribeChatSession; // Add full chat object for thinking level
		supportsReasoning?: boolean; // Flag for reasoning support
		placeholder?: string; // Custom placeholder text
		class?: string;
	};

	let {
		attachments = $bindable([]), // Provide default empty array
		value = $bindable(),
		isLoading = false,
		stopGeneration,
		chatId,
		onImpersonate,
		agentMode = 'disabled',
		onAgentModeChange,
		chat,
		supportsReasoning = false,
		placeholder = 'Send a message...', // Default placeholder
		class: c
	}: Props = $props();

	// State variables
	let _mounted = $state(false);
	let textareaElement = $state<HTMLTextAreaElement | null>(null);
	let fileInputRef = $state<HTMLInputElement | null>(null);
	let uploadQueue = $state<string[]>([]);

	// Lifecycle
	onMount(() => {
		_mounted = true;
		// Initial height adjustment happens in bindTextarea now
		// Focus logic can be added back if needed
	});

	// Effect to adjust textarea height based on value changes
	$effect(() => {
		if (textareaElement && value !== undefined) {
			// Use a small delay to ensure DOM has updated after value change
			requestAnimationFrame(() => {
				adjustHeight();
			});
		}
	});

	// Functions
	const adjustHeight = () => {
		if (textareaElement) {
			textareaElement.style.height = 'auto';
			textareaElement.style.height = `${textareaElement.scrollHeight}px`;
		}
	};

	async function handleFileChange(
		event: Event & {
			currentTarget: EventTarget & HTMLInputElement;
		}
	) {
		toast.error('File upload is not currently supported.');
		// Ensure the file input is cleared
		if (event.currentTarget) {
			event.currentTarget.value = '';
		}
	}

	// Action to bind the textarea element
	function bindTextarea(node: HTMLTextAreaElement) {
		textareaElement = node;
		adjustHeight(); // Adjust height immediately when bound

		// Clean up when component is destroyed
		return {
			destroy() {
				textareaElement = null;
			}
		};
	}

	// Handle text expansion from impersonate widget
	function handleTextExpansion(expandedText: string) {
		value = expandedText;
		// Ensure height is adjusted after setting the value
		// Use requestAnimationFrame to ensure the DOM has updated
		requestAnimationFrame(() => {
			adjustHeight();
			// Focus the textarea after expansion
			if (textareaElement) {
				textareaElement.focus();
			}
		});
	}

	// Handle impersonate results
	function handleImpersonateResults(response: string) {
		if (onImpersonate) {
			onImpersonate(response);
		}
	}
</script>

<div class="relative flex w-full">
	<div class="flex w-full flex-col gap-4">
		<input
			type="file"
			class="pointer-events-none fixed -left-4 -top-4 size-0.5 opacity-0"
			bind:this={fileInputRef}
			multiple
			onchange={handleFileChange}
			tabIndex={-1}
		/>

		{#if (attachments && attachments.length > 0) || uploadQueue.length > 0}
			<div class="flex flex-row items-end gap-2 overflow-x-scroll">
				{#if attachments}
					{#each attachments as attachment (attachment.url)}
						<PreviewAttachment {attachment} />
					{/each}
				{/if}

				{#each uploadQueue as filename, i (i)}
					<PreviewAttachment
						attachment={{
							url: '',
							name: filename,
							contentType: ''
						}}
						uploading
					/>
				{/each}
			</div>
		{/if}

		<!-- Using a native textarea with use directive for element binding -->
		<textarea
			use:bindTextarea
			{placeholder}
			bind:value
			class={_cn(
				'max-h-[calc(37.5dvh)] min-h-[56px] resize-none overflow-y-auto rounded-[24px] border border-border/40 bg-muted/30 pb-12 pl-5 pr-5 pt-4 !text-base shadow-md backdrop-blur-md transition-all duration-300 focus-within:border-primary/50 focus-within:bg-muted/50 focus-within:shadow-lg focus-within:ring-1 focus-within:ring-primary/20 hover:bg-muted/40',
				isLoading ? 'animate-glow-pulse' : '',
				c
			)}
			rows={2}
			oninput={() => {
				// Ensure height adjusts on any input change
				adjustHeight();
			}}
			onkeydown={(_event: KeyboardEvent) => {
				if (_event.key === 'Enter' && !_event.shiftKey && !_event.isComposing) {
					_event.preventDefault();
					// Trigger form submission
					textareaElement?.form?.requestSubmit();
				}
			}}
		></textarea>

		<div class="absolute bottom-0 right-0 flex w-fit flex-row items-center gap-0.5 p-4">
			{#if (chatId && onAgentModeChange) || chatId || (chat && supportsReasoning)}
				<div class="flex items-center gap-0.5 rounded-full bg-muted/30 px-1 py-0.5 backdrop-blur-sm">
					{#if chatId && onAgentModeChange}
						<ContextEnrichmentButton
							value={agentMode}
							onChange={onAgentModeChange}
							disabled={isLoading}
						/>
					{/if}
					{#if chatId}
						<ImpersonateWidget
							{value}
							{chatId}
							onExpand={handleTextExpansion}
							onImpersonate={handleImpersonateResults}
							disabled={isLoading}
						/>
					{/if}
					{#if chat && supportsReasoning}
						<ThinkingLevelSelector {chat} disabled={isLoading} />
					{/if}
				</div>
			{/if}
			{#if isLoading}
				{@render stopButton()}
			{/if}
		</div>
	</div>
</div>

{#snippet stopButton()}
	<ButtonComponent
		variant="ghost"
		class="h-9 w-9 my-auto rounded-full border border-destructive/30 bg-background/50 p-0 text-destructive/80 shadow-sm backdrop-blur-md transition-all hover:bg-destructive/10 hover:border-destructive/50 hover:text-destructive hover:shadow-[0_0_12px_3px] hover:shadow-destructive/20"
		onclick={(_event: MouseEvent) => {
			_event.preventDefault();
			stopGeneration(); // Use stopGeneration prop
		}}
	>
		<StopIcon size={14} />
	</ButtonComponent>
{/snippet}
