<script lang="ts">
	import { cn as _cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { ChevronLeft, ChevronRight } from '@lucide/svelte';
	import { Button as ButtonComponent } from '../ui/button';
	import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
	import { Markdown } from '../markdown';
	import { fly } from 'svelte/transition';
	import { untrack } from 'svelte';
	import type { ScribeChatMessage } from '$lib/types';
	import { createEventDispatcher } from 'svelte';
	import type { CharacterDataForClient, User } from '$lib/types'; // Import CharacterDataForClient and User

	let {
		message,
		_readonly,
		loading,
		character = null,
		_user = undefined,
		substituteTemplateVariables = undefined,
		userPersonaName = 'User'
	}: {
		message: ScribeChatMessage;
		_readonly: boolean;
		loading: boolean;
		character?: CharacterDataForClient | null; // Use CharacterDataForClient
		_user?: User | undefined; // Use User type
		substituteTemplateVariables?: (text: string, characterName: string) => string;
		userPersonaName?: string;
	} = $props();

	const dispatch = createEventDispatcher();

	// Use message.variants as the source of truth for greetings
	// If variants are missing, fallback to the message content itself
	const availableGreetings = $derived.by(() => {
		const variants = message.variants ? [...message.variants] : [];
		if (variants.length === 0) {
			return [message.content || ''];
		}
		return variants.map((v) => v.content || '');
	});

	const currentGreetingIndex = $derived(message.current_variant_index ?? 0);
	const hasMultipleGreetings = $derived(availableGreetings.length > 1);
	const canGoPrevious = $derived(currentGreetingIndex > 0);
	const canGoNext = $derived(currentGreetingIndex < availableGreetings.length - 1);

	$effect(() => {
		console.log('FirstMessage Debug:', {
			messageId: message.id,
			variants: message.variants,
			availableGreetings,
			currentGreetingIndex,
			hasMultipleGreetings,
			canGoPrevious,
			canGoNext
		});
	});

	// Apply template substitution to the current greeting
	// Note: The backend already applies template substitution to variants,
	// but we apply it here too for consistency and in case of local updates.
	let currentGreeting = $state(message.content);

	$effect(() => {
		const rawGreeting = availableGreetings[currentGreetingIndex] || message.content || '';

		if (substituteTemplateVariables && character?.name) {
			currentGreeting = substituteTemplateVariables(rawGreeting, character.name);
		} else {
			currentGreeting = rawGreeting;
		}
	});

	function handlePreviousGreeting() {
		if (canGoPrevious) {
			const newIndex = currentGreetingIndex - 1;
			dispatch('greetingChanged', {
				index: newIndex,
				content: availableGreetings[newIndex],
				messageId: message.id
			});
		}
	}

	function handleNextGreeting() {
		if (canGoNext) {
			const newIndex = currentGreetingIndex + 1;
			dispatch('greetingChanged', {
				index: newIndex,
				content: availableGreetings[newIndex],
				messageId: message.id
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
				class={_cn(
					'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 w-full max-w-none break-words rounded-md border bg-background px-3 py-2'
				)}
			>
				{#key currentGreeting}
					<Markdown md={currentGreeting} />
				{/key}
				{#if loading}
					<span class="ml-1 inline-block h-4 w-0.5 animate-pulse bg-foreground"></span>
				{/if}
			</div>

			<!-- Greeting indicator and navigation controls when multiple are available -->
			{#if hasMultipleGreetings}
				<div class="flex items-center gap-1 text-xs text-muted-foreground">
					Greeting {currentGreetingIndex + 1}
					<Tooltip>
						<TooltipTrigger>
							<ButtonComponent
								variant="ghost"
								size="icon"
								class="h-6 w-6 text-foreground"
								onclick={handlePreviousGreeting}
								disabled={!canGoPrevious}
							>
								<ChevronLeft size={12} />
							</ButtonComponent>
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
							<ButtonComponent
								variant="ghost"
								size="icon"
								class="h-6 w-6 text-foreground"
								onclick={handleNextGreeting}
								disabled={!canGoNext}
							>
								<ChevronRight size={12} />
							</ButtonComponent>
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
