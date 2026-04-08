<script lang="ts">
	import { onDestroy } from 'svelte';
    import { slide } from 'svelte/transition';

	let { rawData, messageId, onRepair }: { rawData: string; messageId?: string; onRepair?: () => void } = $props();

	// Very robust line-based pseudo-XML parser
	const parseResult = $derived.by(() => {
		try {
			const lines = rawData.split('\n').map((l) => l.trim()).filter(Boolean);
			const data: Record<string, string | string[]> = {};

			let currentArrayKey: string | null = null;
			let currentArrayItems: string[] = [];

			for (const line of lines) {
				// e.g. "Physical status: Fine"
				const baseMatch = line.match(/^([^:]+):\s*(.*)$/);

				if (baseMatch) {
					const [_, key, val] = baseMatch;
					const cleanKey = key.trim();
					let cleanVal = val.trim();

					// Did we finish a previous array?
					if (currentArrayKey) {
						data[currentArrayKey] = currentArrayItems;
						currentArrayKey = null;
						currentArrayItems = [];
					}

					// Check if the value is an array syntax
					if (cleanVal.startsWith('[')) {
						try {
							// e.g. '["Sword", "Shield"]'
							const arr = JSON.parse(cleanVal);
							if (Array.isArray(arr)) {
								data[cleanKey] = arr.map((item) => String(item));
							} else {
								data[cleanKey] = String(cleanVal);
							}
						} catch (e) {
							// Very dirty array parser in case JSON.parse fails (e.g. ['Sword', "Shield"])
							// If it starts with [ and ends with ], try to extract elements
							if (cleanVal.endsWith(']')) {
								const inner = cleanVal.slice(1, -1).trim();
								if (inner) {
									// Split by comma, handling potential quotes
									const items = inner.split(',').map(s => {
										s = s.trim();
										// Remove surrounding quotes if they exist
										if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
											s = s.slice(1, -1);
										}
										return s;
									});
									data[cleanKey] = items;
								} else {
									data[cleanKey] = [];
								}
							} else {
								data[cleanKey] = cleanVal;
							}
						}
					} else {
						data[cleanKey] = cleanVal;
					}
				} else if (line.startsWith('-')) {
					// Continuation of a list or items like "- Skill A"
					// If we don't have a current array key, we can try to guess it based on previous lines?
					// But let's assume it belongs to the most recent key if the most recent key had an empty value, or just add it to a generic list
					const item = line.substring(1).trim();
					if (currentArrayKey) {
						currentArrayItems.push(item);
					} else {
						// It's a dangling list item. Let's just create an "Items" list.
						if (!data['Items']) data['Items'] = [];
						(data['Items'] as string[]).push(item);
					}
				} else if (line.endsWith(':')) {
					// Start of a multiline list block e.g. "Skills:\n - Strike\n - Dodge\n"
					if (currentArrayKey) {
						data[currentArrayKey] = currentArrayItems;
					}
					currentArrayKey = line.slice(0, -1).trim();
					currentArrayItems = [];
				} else {
					// Just raw text, append to some generic catch-all
					if (!data['Description']) {
						data['Description'] = line;
					} else {
						data['Description'] = data['Description'] + ' ' + line;
					}
				}
			}

			if (currentArrayKey) {
				data[currentArrayKey] = currentArrayItems;
			}

			// Detect if parsing produced an empty or highly suspect result
			if (Object.keys(data).length === 0 && rawData.length > 20) {
				throw new Error("Failed to extract any structured stats pairs.");
			}

			return { data, error: null };
		} catch (err: any) {
			return { data: { 'Raw Stats': rawData }, error: err };
		}
	});

	const parsedData = $derived(parseResult.data);
	const parseError = $derived(parseResult.error);

    // We strictly use {value} below in the template which naturally escapes HTML -> defending against XSS (A03:2021)
</script>

<div class="my-4 overflow-hidden rounded-xl border border-border/80 bg-background/50 shadow-sm backdrop-blur-sm transition-all hover:border-primary/30" transition:slide>
	<div class="border-b border-border bg-muted/30 px-3 py-2 flex justify-between items-center">
		<h3 class="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-swords"><polyline points="14.5 17.5 3 6 3 3 6 3 17.5 14.5"/><line x1="13" x2="19" y1="19" y2="13"/><line x1="16" x2="20" y1="16" y2="20"/><line x1="19" x2="21" y1="21" y2="19"/><polyline points="14.5 6.5 18 3 21 3 21 6 17.5 9.5"/><line x1="5" x2="9" y1="14" y2="18"/><line x1="7" x2="4" y1="17" y2="20"/><line x1="3" x2="5" y1="19" y2="21"/></svg>
            Status Window
        </h3>

        {#if onRepair && parseError}
            <button
                class="text-[10px] uppercase font-bold tracking-widest text-primary/70 hover:text-primary transition-colors flex items-center gap-1"
                onclick={onRepair}
                aria-label="Repair Formatting"
            >
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-wrench"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                Repair Format
            </button>
        {/if}
	</div>

	<div class="p-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
		{#each Object.entries(parsedData) as [key, value]}
			<div class="space-y-1">
				<div class="text-xs font-medium text-muted-foreground">{key}</div>
				{#if Array.isArray(value)}
					<ul class="list-inside list-disc space-y-1 text-foreground">
						{#each value as item}
							<li>{item}</li>
						{/each}
					</ul>
				{:else}
					<div class="text-foreground">{value}</div>
				{/if}
			</div>
		{/each}
	</div>
</div>
