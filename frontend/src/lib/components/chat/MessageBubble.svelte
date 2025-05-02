<script lang="ts">
	export let messageContent: string = 'Placeholder message content.';
	export let sender: 'user' | 'ai';
	export let isStreaming: boolean = false; // Now used for streaming indicator
	// export let error: string | null = null; // For future use

	$: bubbleClasses = sender === 'user'
		? 'bg-primary text-primary-foreground self-end'
		: 'bg-secondary text-secondary-foreground self-start';

	$: containerClasses = sender === 'user' ? 'justify-end' : 'justify-start';
</script>

<div class={`flex w-full mb-2 ${containerClasses}`} data-testid="message-bubble">
	<div class={`max-w-[75%] rounded-lg p-3 shadow-md ${bubbleClasses}`}>
		{messageContent}
		{#if sender === 'ai' && isStreaming}
			<!-- Simple blinking cursor indicator -->
			<span class="inline-block animate-pulse">▋</span>
		{/if}
		{#if false /* error */}
			<!-- Placeholder for error display -->
			<!-- <div class="text-destructive text-sm mt-1">{error}</div> -->
		{/if}
	</div>
</div>