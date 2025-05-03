<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import Button from '$lib/components/ui/button/button.svelte';
	import { Send } from 'lucide-svelte';

	export let disabled: boolean = false; // To disable input during AI response

	let messageText: string = '';

	const dispatch = createEventDispatcher<{ sendMessage: string }>();

	function sendMessage() {
		const trimmedMessage = messageText.trim();
		if (trimmedMessage && !disabled) {
			dispatch('sendMessage', trimmedMessage);
			messageText = ''; // Clear input after sending
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		// Optional: Send on Enter, prevent default newline
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault(); // Prevent adding a newline
			sendMessage();
		}
	}
</script>

<div class="flex items-center p-2 border-t gap-2">
	<Textarea
		bind:value={messageText}
		placeholder="Type your message..."
		class="flex-1 resize-none"
		rows={1}
		on:keydown={handleKeydown}
		{disabled}
	/>
	<Button on:click={sendMessage} {disabled} size="icon">
		<Send class="w-4 h-4" />
		<span class="sr-only">Send message</span>
	</Button>
</div>