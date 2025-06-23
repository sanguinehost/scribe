<script lang="ts">
	import PreviewAttachment from './preview-attachment.svelte';
	import { Textarea } from './ui/textarea';
	import { cn } from '$lib/utils/shadcn';
	import { onMount } from 'svelte';
	// import { LocalStorage } from '$lib/hooks/local-storage.svelte'; // Unused? Let's remove for cleanup.
	// import { innerWidth } from 'svelte/reactivity/window'; // Unused? Let's remove for cleanup.
	import { toast } from 'svelte-sonner';
	import { Button } from './ui/button';
	import StopIcon from './icons/stop.svelte';
	import ImpersonateWidget from './impersonate-widget.svelte';
	// import { replaceState } from '$app/navigation'; // Unused? Let's remove for cleanup.

	// Props definition
	type Props = {
		attachments?: any[]; // Make attachments optional
		value: string;
		isLoading: boolean;
		stopGeneration: () => void;
		chatId?: string; // Add chatId for impersonate/expand features
		onImpersonate?: (response: string) => void; // Callback for impersonate results
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
		placeholder = "Send a message...", // Default placeholder
		class: c
	}: Props = $props();

	// State variables
	let mounted = $state(false);
	let textareaElement = $state<HTMLTextAreaElement | null>(null);
	let fileInputRef = $state<HTMLInputElement | null>(null);
	let uploadQueue = $state<string[]>([]);

	// Lifecycle
	onMount(() => {
		mounted = true;
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

<div class="relative -ml-2 flex w-full gap-4">
	<div class="flex size-8 shrink-0"></div>
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
						<PreviewAttachment attachment={attachment as any} />
						<!-- Cast to any for now, refine later if needed -->
					{/each}
				{/if}

				{#each uploadQueue as filename}
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
			class={cn(
				'max-h-[calc(37.5dvh)] min-h-[24px] resize-none overflow-y-auto rounded-2xl bg-muted pb-10 pl-4 pr-4 !text-base dark:border-zinc-700',
				c
			)}
			rows={2}
			oninput={() => {
				// Ensure height adjusts on any input change
				adjustHeight();
			}}
			onkeydown={(event: KeyboardEvent) => {
				if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
					event.preventDefault();
					// Trigger form submission
					textareaElement?.form?.requestSubmit();
				}
			}}
		></textarea>

		<div class="absolute bottom-0 right-0 flex w-fit flex-row items-center gap-1 p-4">
			{#if chatId}
				<ImpersonateWidget
					{value}
					{chatId}
					onExpand={handleTextExpansion}
					onImpersonate={handleImpersonateResults}
					disabled={isLoading}
				/>
			{/if}
			{#if isLoading}
				{@render stopButton()}
			{/if}
		</div>
	</div>
</div>

{#snippet stopButton()}
	<Button
		class="h-fit rounded-full border p-1.5 dark:border-zinc-600"
		onclick={(event: MouseEvent) => {
			event.preventDefault();
			stopGeneration(); // Use stopGeneration prop
		}}
	>
		<StopIcon size={14} />
	</Button>
{/snippet}
