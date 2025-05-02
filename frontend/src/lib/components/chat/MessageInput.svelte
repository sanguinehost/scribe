<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Textarea } from '$lib/components/ui/textarea';
	import { chatStore } from '$lib/stores/chatStore';

	let messageContent = '';

	// Subscribe to loading state to disable input/button
	$: isLoading = $chatStore.isLoading;

	function handleSend() {
		if (!messageContent.trim() || isLoading) {
			return; // Don't send empty messages or while loading
		}
		console.log('Sending message:', messageContent); // Debug log
		chatStore.sendMessage(messageContent);
		messageContent = ''; // Clear the input field
	}

	// Handle Enter key press (Shift+Enter for newline)
	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault(); // Prevent default newline insertion
			handleSend();
		}
	}
</script>

<div class="flex w-full items-center space-x-2 p-2 border-t" data-testid="message-input">
	<Textarea
		placeholder="Type your message here..."
		class="flex-1 resize-none"
		bind:value={messageContent}
		on:keydown={handleKeydown}
		disabled={isLoading}
		rows={1} 
		data-testid="message-input-textarea" />
	<Button 
		type="submit" 
		on:click={handleSend} 
		disabled={isLoading || !messageContent.trim()}
		data-testid="message-input-button">
		Send
	</Button>
</div>