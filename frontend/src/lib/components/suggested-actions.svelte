<script lang="ts">
	import { Button } from './ui/button';
	import { fly } from 'svelte/transition';
	import { X, PenTool } from 'lucide-svelte';
	// import { replaceState } from '$app/navigation'; // No longer needed here
	import type { User } from '$lib/types';

	// Accept sendMessage function and dynamic actions
	let {
		user,
		sendMessage,
		actions,
		onClear,
		onEdit
	}: {
		user: User | undefined;
		sendMessage: (content: string) => Promise<void>;
		actions: Array<{ action: string }>; // Expecting array of {action: string}
		onClear: () => void;
		onEdit: (content: string) => void;
	} = $props();

	// Removed the static 'suggestedActions' array
</script>

<div class="ml-6 sm:ml-[40px] w-[calc(100%-24px)] sm:w-[calc(100%-50px)]">
	<!-- Header with clear button -->
	<div class="mb-2 flex items-center justify-between">
		<span class="text-xs text-muted-foreground">Suggestions</span>
		<Button
			variant="ghost"
			size="sm"
			onclick={onClear}
			class="h-6 w-6 p-0 hover:bg-muted"
			aria-label="Clear suggestions"
		>
			<X size={12} />
		</Button>
	</div>

	<!-- Suggestions grid -->
	<div class="grid gap-2 grid-cols-1 sm:grid-cols-2">
		{#each actions as suggestedItem, i (suggestedItem.action)}
			<div
				in:fly|global={{ opacity: 0, y: 20, delay: 50 * i, duration: 400 }}
				class={i > 1 ? 'hidden sm:block' : 'block'}
			>
				<!--
					Display logic: Show first two items always.
					Show items 3 and 4 only on 'sm' screens and up.
				-->
				<div class="group relative rounded-xl border">
					<Button
						variant="ghost"
						onclick={async () => {
							await sendMessage(suggestedItem.action);
						}}
						class="h-auto w-full flex-1 items-start justify-start gap-1 rounded-xl border-0 px-3 sm:px-4 py-3 sm:py-3.5 pr-8 sm:pr-10 text-left text-xs sm:text-sm"
						aria-label={`Suggested action: ${suggestedItem.action}`}
					>
						<span class="font-medium break-words">{suggestedItem.action}</span>
					</Button>
					<!-- Edit button overlay -->
					<Button
						variant="ghost"
						size="sm"
						onclick={(e) => {
							e.preventDefault();
							e.stopPropagation();
							onEdit(suggestedItem.action);
						}}
						class="absolute right-1 top-1 h-6 w-6 p-0 opacity-0 hover:bg-muted group-hover:opacity-100"
						aria-label={`Edit suggestion: ${suggestedItem.action}`}
					>
						<PenTool size={12} />
					</Button>
				</div>
			</div>
		{/each}
	</div>
</div>
