<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	import { onMount } from 'svelte';
	import type { Snippet } from 'svelte';
	import { streamingService } from '$lib/services/StreamingService.svelte';
	import { desktopStreamingService } from '$lib/services/DesktopStreamingService.svelte';
	import { isInDesktopMode } from '$lib/api/desktop-auth';

	let { children, ...props }: { children?: Snippet; [key: string]: unknown } = $props();
	let element = $state<HTMLElement | null>(null);

	let hasProcessed = $state(false);

	const activeStreamingService = $derived(
		isInDesktopMode() ? desktopStreamingService : streamingService
	);

	function processNodes() {
		const el = element;
		if (!el) return;

		const currentHtml = el.innerHTML;
		// Regex to match:
		// 1. Code blocks (to skip)
		// 2. Already highlighted dialogue (to skip)
		// 3. Other tags (to skip, including Svelte comments)
		// 4. Quotes (to highlight)
		//    Group 4: Opening quote
		//    Group 5: Content (non-greedy, can include tags)
		//    Group 6: Closing quote
		// Followed by: End of string or non-alphanumeric character
		const regex =
			/(<code[^>]*>.*?<\/code>)|(<span[^>]*class="[^"]*dialogue-text[^"]*"[^>]*>.*?<\/span>)|(<[^>]+>)|([“"])([^“"]+)([”"])(?=[^a-zA-Z0-9]|$)/gs;

		const newHtml = currentHtml.replace(
			regex,
			(match, code, dialogue, tag, open, content, close, offset, fullString) => {
				if (code || dialogue || tag) return match;

				// Check preceder in the original string
				const charBefore = offset > 0 ? fullString[offset - 1] : '';
				// Valid preceders: start of string, whitespace, opening brackets, or end of a tag (like Svelte comments)
				const isValidPreceder = !charBefore || /\s|[(\[{]|>/.test(charBefore);

				if (!isValidPreceder) return match;

				const fullQuote = open + content + close;
				return `<span class="dialogue-text" data-highlighted="true">${fullQuote}</span>`;
			}
		);

		if (newHtml !== currentHtml) {
			el.innerHTML = newHtml;
			hasProcessed = true;
		}
	}

	onMount(() => {
		// Initial processing for historical messages
		// We use a small timeout to ensure Svelte has finished rendering the children
		setTimeout(processNodes, 100);
	});

	// Run robust processing when streaming finishes
	$effect(() => {
		if (!activeStreamingService.isTyping) {
			// Wait for any final animations or Svelte updates to settle
			setTimeout(processNodes, 300);
		}
	});
</script>

<p bind:this={element} {...props}>
	{@render children?.()}
</p>

<style>
	:global(.dialogue-text) {
		color: #ea580c !important;
		font-weight: 500 !important;
	}

	:global(.dark .dialogue-text) {
		color: #a78bfa !important;
	}
</style>
