<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import { onMount } from 'svelte';
	import type { Snippet } from 'svelte';

	let { children, ...props }: { children?: Snippet; [key: string]: unknown } = $props();
	let element = $state<HTMLElement | null>(null);

	let hasProcessed = $state(false);

	onMount(() => {
		const el = element;
		if (!el || hasProcessed) return;

		// Simple escape function
		function escapeHtml(text: string): string {
			const div = document.createElement('div');
			div.textContent = text;
			return div.innerHTML;
		}

		// Process only text nodes to preserve existing elements like <code>
		const nodes = Array.from(el.childNodes);
		let changed = false;

		nodes.forEach((node) => {
			if (node.nodeType === 3) {
				// Node.TEXT_NODE
				const text = node.textContent || '';
				const quoteRegex = /"[^"]+"/g;
				let match;
				let pos = 0;
				const parts: string[] = [];

				while ((match = quoteRegex.exec(text)) !== null) {
					if (match.index > pos) {
						parts.push(escapeHtml(text.slice(pos, match.index)));
					}
					parts.push(`<span class="dialogue-text">${escapeHtml(match[0])}</span>`);
					pos = match.index + match[0].length;
				}

				if (pos < text.length) {
					parts.push(escapeHtml(text.slice(pos)));
				}

				if (parts.length > 1 || (parts.length === 1 && parts[0].includes('span'))) {
					const span = document.createElement('span');
					span.innerHTML = parts.join('');
					// Use a document fragment to avoid extra span if possible,
					// but for simplicity and safety with replaceChild, a span is fine.
					el.replaceChild(span, node);
					changed = true;
				}
			}
		});

		if (changed) {
			hasProcessed = true;
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
