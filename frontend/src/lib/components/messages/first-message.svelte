<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { ChevronLeft, ChevronRight } from '@lucide/svelte';
	import { Button } from '../ui/button';
	import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
	import { Markdown } from '../markdown';
	import { fly } from 'svelte/transition';
	import type { ScribeChatMessage } from '$lib/types';
	import { createEventDispatcher } from 'svelte';
	import type { CharacterDataForClient, User } from '$lib/types'; // Import CharacterDataForClient and User

	let {
		message,
		readonly,
		loading,
		alternateGreetings = [],
		currentGreetingIndex = 0,
		character = null,
		user = undefined
	}: {
		message: ScribeChatMessage;
		readonly: boolean;
		loading: boolean;
		alternateGreetings?: string[];
		currentGreetingIndex?: number;
		character?: CharacterDataForClient | null; // Use CharacterDataForClient
		user?: User | undefined; // Use User type
	} = $props();

	const dispatch = createEventDispatcher();

	// Filter out null/empty greetings and combine with first_mes
	const availableGreetings = $derived(
		[
			message.content, // The current first message
			...(alternateGreetings || [])
		].filter(Boolean)
	);

	const hasMultipleGreetings = $derived(availableGreetings.length > 1);
	const canGoPrevious = $derived(currentGreetingIndex > 0);
	const canGoNext = $derived(currentGreetingIndex < availableGreetings.length - 1);
	const currentGreeting = $derived(availableGreetings[currentGreetingIndex] || message.content);

	function handlePreviousGreeting() {
		if (canGoPrevious) {
			const newIndex = currentGreetingIndex - 1;
			dispatch('greetingChanged', {
				index: newIndex,
				content: availableGreetings[newIndex]
			});
		}
	}

	function handleNextGreeting() {
		if (canGoNext) {
			const newIndex = currentGreetingIndex + 1;
			dispatch('greetingChanged', {
				index: newIndex,
				content: availableGreetings[newIndex]
			});
		}
	}
</script>

<div
	class="group/message mx-auto w-full max-w-3xl px-4"
	data-role="assistant"
	in:fly|global={{ opacity: 0, y: 5 }}
>
	<div class="flex w-full gap-4">
		<div
			class="flex size-8 shrink-0 items-center justify-center rounded-full bg-background ring-1 ring-border"
		>
			<div class="translate-y-px">
				<SparklesIcon size={14} />
			</div>
		</div>

		<div class="flex w-full flex-col gap-4">
			<!-- Message content -->
			<div
				class={cn(
					'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words rounded-md border bg-background px-3 py-2'
				)}
			>
				<Markdown md={currentGreeting} />
				{#if loading}
					<span class="ml-1 inline-block h-4 w-0.5 animate-pulse bg-foreground"></span>
				{/if}
			</div>

			<!-- Greeting indicator and navigation controls when multiple are available -->
			{#if hasMultipleGreetings}
				<div class="flex items-center gap-1 text-xs text-muted-foreground">
					{#if currentGreetingIndex === 0}
						Primary greeting
					{:else}
						Alternate greeting {currentGreetingIndex}
					{/if}
					<Tooltip>
						<TooltipTrigger>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 text-foreground"
								onclick={handlePreviousGreeting}
								disabled={!canGoPrevious}
							>
								<ChevronLeft size={12} />
							</Button>
						</TooltipTrigger>
						<TooltipContent>
							<p>Previous greeting</p>
						</TooltipContent>
					</Tooltip>

					<span class="px-1 text-xs text-muted-foreground">
						{currentGreetingIndex + 1}/{availableGreetings.length}
					</span>

					<Tooltip>
						<TooltipTrigger>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 text-foreground"
								onclick={handleNextGreeting}
								disabled={!canGoNext}
							>
								<ChevronRight size={12} />
							</Button>
						</TooltipTrigger>
						<TooltipContent>
							<p>Next greeting</p>
						</TooltipContent>
					</Tooltip>
				</div>
			{/if}
		</div>
	</div>
</div>
