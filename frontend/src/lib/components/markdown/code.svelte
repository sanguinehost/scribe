<script lang="ts">
	import { onMount } from 'svelte';
	import { cn } from '$lib/utils/shadcn';

	let {
		children,
		inline,
		class: c,
		...props
	}: {
		children: any;
		inline?: boolean;
		class?: string;
		[key: string]: any;
	} = $props();

	let element = $state<HTMLElement | null>(null);
	let hasProcessed = $state(false);

	onMount(() => {
		if (!element || hasProcessed || inline) return; // Only process block code, not inline

		const rawText = element.textContent || '';
		// Trim the entire text content to remove leading/trailing whitespace
		const text = rawText.trim();

		// Check if this looks like a status block
		const isStatusBlock =
			/^(CURRENT STATE|INVENTORY|STATUS|STATS|CHARACTER|PARTY|LOCATION|HEALTH|EQUIPMENT)[\s\(].*:/im.test(
				text
			) || /Health:\s*\d+|Location:|Status:|Inventory:|Power Path:|Attainment:|CARRIED/i.test(text);

		if (!isStatusBlock) return;

		function escapeHtml(text: string): string {
			const div = document.createElement('div');
			div.textContent = text;
			return div.innerHTML;
		}

		// Parse and colorize the content
		const lines = text.split('\n');
		const colorizedLines = lines.map((line) => {
			// Skip empty lines
			if (line.trim() === '') {
				return null;
			}

			// Headers (ALL CAPS followed by colon, possibly with parentheses) - trim whitespace
			if (/^[A-Z\s]+(\([^)]*\))?[\s]*:/.test(line.trim())) {
				return `<span class="status-header">${escapeHtml(line.trim())}</span>`;
			}

			// Key-value pairs (Key: Value) - match against trimmed line
			const kvMatch = line.trim().match(/^([^:]+):\s*(.+)$/);
			if (kvMatch) {
				const [, key, value] = kvMatch;
				let coloredValue = escapeHtml(value);

				// Special coloring for certain values
				if (key.toLowerCase().includes('health')) {
					const healthNum = parseInt(value);
					if (healthNum >= 80) {
						coloredValue = `<span class="status-health-high">${escapeHtml(value)}</span>`;
					} else if (healthNum >= 50) {
						coloredValue = `<span class="status-health-medium">${escapeHtml(value)}</span>`;
					} else if (healthNum >= 20) {
						coloredValue = `<span class="status-health-low">${escapeHtml(value)}</span>`;
					} else {
						coloredValue = `<span class="status-health-critical">${escapeHtml(value)}</span>`;
					}
				} else if (key.toLowerCase().includes('location')) {
					coloredValue = `<span class="status-location">${escapeHtml(value)}</span>`;
				} else if (key.toLowerCase().includes('status') || key.toLowerCase().includes('state')) {
					coloredValue = `<span class="status-state">${escapeHtml(value)}</span>`;
				} else if (
					key.toLowerCase().includes('power') ||
					key.toLowerCase().includes('attainment')
				) {
					coloredValue = `<span class="status-power">${escapeHtml(value)}</span>`;
				}

				return `<span class="status-key">${escapeHtml(key.trim())}:</span> ${coloredValue}`;
			}

			// Inventory items (numbered, bulleted, or bracketed lists) - match against trimmed line
			const inventoryMatch = line.trim().match(/^(\d+x|\*|\-|\[)\s*(.+)$/);
			if (inventoryMatch) {
				const [, bullet, item] = inventoryMatch;
				// For brackets, don't add space since it's already part of the text
				if (bullet === '[') {
					return `<span class="status-item">${escapeHtml(bullet + item)}</span>`;
				} else {
					return `<span class="status-bullet">${escapeHtml(bullet)}</span> <span class="status-item">${escapeHtml(item)}</span>`;
				}
			}

			// Default styling for other lines - trim whitespace
			return `<span class="status-default">${escapeHtml(line.trim())}</span>`;
		});

		// Filter out null values and join with newlines
		const filteredLines = colorizedLines.filter((line) => line !== null);

		// Replace the entire content, removing any existing whitespace
		element.innerHTML = filteredLines.join('\n');

		// Remove the whitespace-pre-wrap class to prevent whitespace preservation
		element.classList.remove('whitespace-pre-wrap');
		element.classList.add('whitespace-pre-line');

		hasProcessed = true;
	});
</script>

{#if inline}
	<code bind:this={element} class={cn('whitespace-pre-wrap break-words text-sm', c)} {...props}
		>{@render children?.()}</code
	>
{:else}
	<div class="not-prose mt-4 flex flex-col">
		<pre
			class="w-full overflow-x-auto rounded-xl border border-zinc-200 p-4 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-50"><code
				bind:this={element}
				class="whitespace-pre-wrap break-words"
				{...props}>{@render children?.()}</code
			></pre>
	</div>
{/if}

<style>
	:global(.status-header) {
		color: #3b82f6 !important;
		font-weight: bold !important;
	}

	:global(.dark .status-header) {
		color: #60a5fa !important;
	}

	:global(.status-key) {
		color: #64748b !important;
	}

	:global(.dark .status-key) {
		color: #94a3b8 !important;
	}

	:global(.status-health-high) {
		color: #10b981 !important;
		font-weight: 600 !important;
	}

	:global(.dark .status-health-high) {
		color: #34d399 !important;
	}

	:global(.status-health-medium) {
		color: #f59e0b !important;
		font-weight: 600 !important;
	}

	:global(.dark .status-health-medium) {
		color: #fbbf24 !important;
	}

	:global(.status-health-low) {
		color: #f97316 !important;
		font-weight: 600 !important;
	}

	:global(.dark .status-health-low) {
		color: #fb923c !important;
	}

	:global(.status-health-critical) {
		color: #ef4444 !important;
		font-weight: 600 !important;
	}

	:global(.dark .status-health-critical) {
		color: #f87171 !important;
	}

	:global(.status-location) {
		color: #8b5cf6 !important;
		font-weight: 500 !important;
	}

	:global(.dark .status-location) {
		color: #a78bfa !important;
	}

	:global(.status-state) {
		color: #06b6d4 !important;
		font-weight: 500 !important;
	}

	:global(.dark .status-state) {
		color: #22d3ee !important;
	}

	:global(.status-power) {
		color: #f59e0b !important;
		font-weight: 500 !important;
	}

	:global(.dark .status-power) {
		color: #fbbf24 !important;
	}

	:global(.status-bullet) {
		color: #64748b !important;
	}

	:global(.dark .status-bullet) {
		color: #94a3b8 !important;
	}

	:global(.status-item) {
		color: #10b981 !important;
	}

	:global(.dark .status-item) {
		color: #34d399 !important;
	}

	:global(.status-default) {
		color: #e2e8f0 !important;
	}

	:global(.dark .status-default) {
		color: #cbd5e1 !important;
	}
</style>
