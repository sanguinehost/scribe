<script lang="ts">
  // Basic mock for MessageBubble
  export let messageContent: string = '';
  export let sender: 'ai' | 'user';
  export let isStreaming: boolean = false;
  export let error: string | null = null;
</script>

<div data-testid="mock-message-bubble" role="listitem">
  Mock Bubble: {sender} - {messageContent} {isStreaming ? '(streaming...)' : ''} {error ? `(error: ${error})` : ''}
</div>