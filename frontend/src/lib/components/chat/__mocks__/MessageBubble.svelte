<script lang="ts">
  // Basic mock for MessageBubble
  export let message: { id: string; content: string; sender: 'ai' | 'user' };
</script>

<div data-testid="mock-message-bubble" role="listitem">
  Mock Bubble: {message.sender} - {message.content}
</div>