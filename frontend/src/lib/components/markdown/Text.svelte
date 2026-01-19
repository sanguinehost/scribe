<script lang="ts">
	let { text }: { text: string } = $props();

	// Refined regex to handle mixed quotes and avoid inversion
	// Group 1: Preceder (start of string, whitespace, or opening brackets)
	// Group 2: Opening quote
	// Group 3: Content (non-greedy)
	// Group 4: Closing quote
	// Followed by: End of string or non-alphanumeric character
	// Note: We don't include > in preceder here because we are only looking at text nodes
	const quoteRegex = /(^|\s|[([{])([“"])([^“"]+)([”"])(?=[^a-zA-Z0-9]|$)/g;

	function processText(val: string) {
		if (!val) return [{ text: '', isQuote: false }];

		const parts = [];
		let lastIndex = 0;
		let match;

		// Reset regex lastIndex
		quoteRegex.lastIndex = 0;

		while ((match = quoteRegex.exec(val)) !== null) {
			const preceder = match[1];
			const fullQuote = match[2] + match[3] + match[4];

			if (match.index + preceder.length > lastIndex) {
				parts.push({
					text: val.slice(lastIndex, match.index + preceder.length),
					isQuote: false
				});
			}
			parts.push({
				text: fullQuote,
				isQuote: true
			});
			lastIndex = match.index + match[0].length;
		}

		if (lastIndex < val.length) {
			parts.push({
				text: val.slice(lastIndex),
				isQuote: false
			});
		}

		return parts.length > 0 ? parts : [{ text: val, isQuote: false }];
	}

	let processedParts = $derived(processText(text));
</script>

{#each processedParts as part}
	{#if part.isQuote}
		<span class="dialogue-text" data-highlighted="true">{part.text}</span>
	{:else}
		{part.text}
	{/if}
{/each}
