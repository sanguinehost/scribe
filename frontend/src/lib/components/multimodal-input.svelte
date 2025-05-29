<script lang="ts">
	import PreviewAttachment from './preview-attachment.svelte';
	import { Textarea } from './ui/textarea';
	import { cn } from '$lib/utils/shadcn';
	import { onMount } from 'svelte';
	// import { LocalStorage } from '$lib/hooks/local-storage.svelte'; // Unused? Let's remove for cleanup.
	// import { innerWidth } from 'svelte/reactivity/window'; // Unused? Let's remove for cleanup.
	import { toast } from 'svelte-sonner';
	import { Button } from './ui/button';
	import PaperclipIcon from './icons/paperclip.svelte';
	import StopIcon from './icons/stop.svelte';
	import ArrowUpIcon from './icons/arrow-up.svelte';
	import SuggestedActions from './suggested-actions.svelte';
	// import { replaceState } from '$app/navigation'; // Unused? Let's remove for cleanup.
	import type { User } from '$lib/types';

	// Props definition
	type Props = {
		attachments?: any[]; // Make attachments optional
		user: User | undefined;
		value: string;
		isLoading: boolean;
		sendMessage: (content: string) => Promise<void>;
		stopGeneration: () => void;
		class?: string;
	};

	let {
		attachments = $bindable([]), // Provide default empty array
		user,
		value = $bindable(),
		isLoading = false,
		sendMessage,
		stopGeneration,
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
	$effect.pre(() => {
		if (textareaElement && value !== undefined) {
			adjustHeight();
		}
	});

	// Functions
	const adjustHeight = () => {
		if (textareaElement) {
			textareaElement.style.height = 'auto';
			// Add a small buffer (2px) to prevent scrollbar flicker on single line
			textareaElement.style.height = `${textareaElement.scrollHeight + 2}px`;
		}
	};

	const resetHeight = () => {
		if (textareaElement) {
			textareaElement.style.height = 'auto';
			// Reset to a reasonable default height (e.g., 2 rows equivalent)
			// Let's keep the original 98px for now, but this could be refined.
			textareaElement.style.height = '98px';
		}
	};

	// File handling (currently disabled)
	async function uploadFile(file: File): Promise<undefined> {
		const formData = new FormData();
		formData.append('file', file);
		toast.error('File upload is not currently supported.');
		return undefined;
	}

	async function handleFileChange(
		event: Event & {
			currentTarget: EventTarget & HTMLInputElement;
		}
	) {
		const files = Array.from(event.currentTarget.files || []);
		toast.error('File upload is not currently supported.');
		// Ensure the file input is cleared
		if (event.currentTarget) {
			event.currentTarget.value = '';
		}
	}

	// Action to bind the textarea element and manage its height
	function bindTextarea(node: HTMLTextAreaElement) {
		textareaElement = node;
		adjustHeight(); // Adjust height immediately when bound

		// Clean up when component is destroyed
		return {
			destroy() {
				textareaElement = null;
				// Svelte handles top-level effect cleanup automatically
			}
		};
	}
</script>

<div class="relative flex w-full flex-col gap-4">
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
			{#if attachments} {#each attachments as attachment (attachment.url)}
				<PreviewAttachment attachment={attachment as any} /> <!-- Cast to any for now, refine later if needed -->
			{/each} {/if}

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
		placeholder="Send a message..."
		bind:value
		class={cn(
			'max-h-[calc(75dvh)] min-h-[24px] resize-none overflow-hidden rounded-2xl bg-muted pb-10 pl-2 pr-2 !text-base dark:border-zinc-700',
			c
		)}
		rows={2}
		onkeydown={(event: KeyboardEvent) => {
			if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
				event.preventDefault();
				// Trigger form submission instead of internal submitForm
				textareaElement?.form?.requestSubmit();
			}
		}}
	></textarea>

	<div class="absolute bottom-0 flex w-fit flex-row justify-start p-2">
		{@render attachmentsButton()}
	</div>

	<div class="absolute bottom-0 right-0 flex w-fit flex-row justify-end p-2">
		{#if isLoading}
			{@render stopButton()}
		{:else}
			{@render sendButton()}
		{/if}
	</div>
</div>

{#snippet attachmentsButton()}
	<!-- TODO: Re-enable attachment button when file upload is supported -->
	<Button
		class="h-fit rounded-md rounded-bl-lg p-[7px] hover:bg-zinc-200 dark:border-zinc-700 hover:dark:bg-zinc-900"
		onclick={(event: MouseEvent) => {
			event.preventDefault();
			// fileInputRef?.click();
			toast.error('File upload is not currently supported.');
		}}
		disabled={true}
		variant="ghost"
		title="File attachments not supported"
	>
		<PaperclipIcon size={14} class="text-muted-foreground" />
	</Button>
{/snippet}

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

{#snippet sendButton()}
	<Button
		class="h-fit rounded-full border p-1.5 dark:border-zinc-600"
		onclick={(event: MouseEvent) => {
			event.preventDefault();
			// submitForm(); // Removed, handled by type="submit"
		}}
		type="submit"
		disabled={value.length === 0 || uploadQueue.length > 0 || isLoading}
	>
		<ArrowUpIcon size={14} />
	</Button>
{/snippet}
