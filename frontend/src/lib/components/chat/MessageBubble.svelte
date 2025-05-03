<script lang="ts">
	import type { ChatMessage } from '$lib/stores/chatStore';
	import { cn } from '$lib/utils'; // Assuming shadcn utils setup
    import { AlertCircle } from 'lucide-svelte'; // For error icon

	export let messageContent: string;
	export let sender: 'user' | 'ai';
	export let isStreaming: boolean = false;
	export let error: string | undefined | null = undefined; // Allow undefined/null

    // Reactive classes based on sender
    $: bubbleClasses = cn(
        'p-3 rounded-lg max-w-[75%] break-words shadow-sm', // Common styles
        sender === 'user' ? 'bg-primary text-primary-foreground ml-auto' : 'bg-muted text-muted-foreground mr-auto', // Sender specific styles
        error ? 'border border-destructive bg-destructive/10' : '' // Error styles
    );

    $: showStreamingIndicator = sender === 'ai' && isStreaming && !error;
    $: showErrorIndicator = !!error;

</script>

<div class="mb-2 flex" class:justify-end={sender === 'user'} class:justify-start={sender === 'ai'}>
	<div class={bubbleClasses}>
        {#if showErrorIndicator}
            <div class="flex items-center text-destructive mb-1">
                <AlertCircle class="w-4 h-4 mr-1" />
                <span class="text-xs font-medium">Error: {error}</span>
            </div>
        {/if}
		<p class="whitespace-pre-wrap">{messageContent}{#if showStreamingIndicator}<span class="animate-pulse">▍</span>{/if}</p>
        <!-- Optional: Add timestamp or other metadata here -->
	</div>
</div>