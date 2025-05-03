<script lang="ts">
	import { onMount, afterUpdate } from 'svelte';
	import type { ChatMessage } from '$lib/stores/chatStore';
	import MessageBubble from './MessageBubble.svelte';
	import MessageInput from './MessageInput.svelte';
	import ScrollArea from '$lib/components/ui/scroll-area/scroll-area.svelte'; // Using shadcn ScrollArea
    import { Skeleton } from '$lib/components/ui/skeleton'; // For loading state

	export let messages: ChatMessage[] = [];
	export let isLoadingHistory: boolean = false;
	export let isGeneratingResponse: boolean = false;
    export let error: string | null = null; // Display general chat errors

    // Reference to the scroll area viewport for scrolling control
    let scrollViewport: HTMLElement | null = null;
    let shouldScrollToBottom = false; // Flag to scroll after update

    // Scroll to bottom when new messages are added or component mounts
    function scrollToBottom() {
        if (scrollViewport) {
            scrollViewport.scrollTop = scrollViewport.scrollHeight;
        }
    }

    onMount(() => {
        scrollToBottom();
    });

    // Use afterUpdate to scroll after the DOM has been updated with new messages
    afterUpdate(() => {
        if (shouldScrollToBottom) {
            scrollToBottom();
            shouldScrollToBottom = false; // Reset flag
        }
    });

    // Watch messages length to trigger scroll on next update cycle
    $: {
        if (messages.length) {
            shouldScrollToBottom = true;
        }
    }

</script>

<div class="flex flex-col h-full border rounded-lg overflow-hidden">
	{#if isLoadingHistory}
		<!-- Loading Skeleton -->
		<div class="flex-1 p-4 space-y-4 overflow-y-auto">
            <Skeleton class="h-12 w-3/4" />
            <Skeleton class="h-12 w-3/4 ml-auto" />
            <Skeleton class="h-16 w-1/2" />
            <Skeleton class="h-12 w-3/4 ml-auto" />
        </div>
	{:else if error}
        <!-- Error Display -->
        <div class="flex-1 p-4 flex items-center justify-center text-destructive">
            <p>Error loading chat: {error}</p>
        </div>
    {:else}
		<!-- Message List -->
		<ScrollArea class="flex-1">
			<div class="p-4 space-y-2" bind:this={scrollViewport}>
				{#if messages.length === 0}
					<p class="text-center text-muted-foreground">No messages yet. Start the conversation!</p>
				{:else}
					{#each messages as message (message.id)}
						<MessageBubble
							messageContent={message.content}
							sender={message.sender}
							isStreaming={message.isStreaming}
                            error={message.error}
						/>
					{/each}
				{/if}
			</div>
		</ScrollArea>
	{/if}

	<!-- Message Input Area -->
	<MessageInput disabled={isGeneratingResponse} on:sendMessage />
</div>