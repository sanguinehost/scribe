<script lang="ts">
  import type { StreamingMessage } from '$lib/services/StreamingService.svelte';
  import { Markdown } from '$lib/components/markdown';

  // Props
  let {
  	message = $bindable(),
  	showTypewriter = false,
  	cursorColor = 'orange',
  	animationDuration = '2s',
  	className = ''
  }: {
  	message: StreamingMessage;
  	showTypewriter?: boolean;
  	cursorColor?: string;
  	animationDuration?: string;
  	className?: string;
  } = $props();

  // Reactive character count for CSS animation
  let charCount = $derived(message.content.length);
  
  // Determine if we should show the typewriter effect
  let shouldAnimate = $derived(
    showTypewriter && 
    message.sender === 'assistant' && 
    message.loading && 
    message.content.length > 0
  );
</script>

<div 
  class="message-content {className}"
  class:typewriter={shouldAnimate}
  style="--char-count: {charCount}; --cursor-color: {cursorColor}; --animation-duration: {animationDuration}"
><Markdown md={message.content} /></div>

<style>
  .message-content {
    word-wrap: break-word;
    line-height: 1.5;
  }

  /* Fix paragraph spacing in markdown */
  .message-content :global(p) {
    margin-bottom: 1rem;
  }

  .message-content :global(p:last-child) {
    margin-bottom: 0;
  }

  /* Simplified typewriter effect for markdown content */
  .typewriter {
    position: relative;
  }

  /* Add animated cursor after the content */
  .typewriter::after {
    content: '';
    display: inline-block;
    width: 3px;
    height: 1.2em;
    background-color: var(--cursor-color, orange);
    margin-left: 2px;
    animation: blink 0.75s step-end infinite;
    vertical-align: text-bottom;
  }

  @keyframes blink {
    from, to { 
      opacity: 1;
    }
    50% { 
      opacity: 0;
    }
  }

  /* Remove cursor when not loading */
  .typewriter:not(.loading)::after,
  .message-content:not(.typewriter)::after {
    display: none;
  }

  /* Responsive adjustments */
  @media (max-width: 768px) {
    .typewriter {
      font-size: 0.95rem;
    }
  }

  /* Dark mode support */
  @media (prefers-color-scheme: dark) {
    .typewriter::after {
      background-color: #fbbf24; /* amber-400 */
    }
  }
</style>