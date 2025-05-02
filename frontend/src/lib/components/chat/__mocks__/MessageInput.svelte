<script lang="ts">
  // Basic mock for MessageInput
  import { createEventDispatcher } from 'svelte';
  const dispatch = createEventDispatcher();
</script>

<div data-testid="mock-message-input">
  Mock Message Input
  <button on:click={() => dispatch('sendMessage', 'mock message')}>Send</button>
</div>