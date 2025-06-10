<script lang="ts">
	import { onMount } from 'svelte';

	let { children, ...props }: { children: any; [key: string]: any } = $props();
	let element = $state<HTMLElement | null>(null);

	let hasProcessed = $state(false);

	onMount(() => {
		if (!element || hasProcessed) return;
		
		// Get just the text content, no HTML
		const text = element.textContent || '';
		
		// Simple escape function
		function escapeHtml(text: string): string {
			const div = document.createElement('div');
			div.textContent = text;
			return div.innerHTML;
		}
		
		// Split text into parts and identify dialogue
		const parts: Array<{text: string, isDialogue: boolean}> = [];
		let remaining = text;
		let pos = 0;
		
		// Find quoted text
		const quoteRegex = /"[^"]+"/g;
		let match;
		
		while ((match = quoteRegex.exec(text)) !== null) {
			// Add text before quote
			if (match.index > pos) {
				parts.push({text: text.slice(pos, match.index), isDialogue: false});
			}
			// Add the quote
			parts.push({text: match[0], isDialogue: true});
			pos = match.index + match[0].length;
		}
		
		// Add remaining text
		if (pos < text.length) {
			parts.push({text: text.slice(pos), isDialogue: false});
		}
		
		// Build new HTML
		const newHTML = parts.map(part => {
			if (part.isDialogue) {
				return `<span class="dialogue-text">${escapeHtml(part.text)}</span>`;
			} else {
				return escapeHtml(part.text);
			}
		}).join('');
		
		if (parts.some(p => p.isDialogue)) {
			element.innerHTML = newHTML;
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