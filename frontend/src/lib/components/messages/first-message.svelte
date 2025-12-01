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
		alternateGreetings = [],
		currentGreetingIndex = 0,
		character = null,
		_user = undefined,
		substituteTemplateVariables = undefined,
		userPersonaName = 'User'
	}: {
		message: ScribeChatMessage;
		_readonly: boolean;
		loading: boolean;
		alternateGreetings?: string[];
		currentGreetingIndex?: number;
		character?: CharacterDataForClient | null; // Use CharacterDataForClient
		_user?: User | undefined; // Use User type
		substituteTemplateVariables?: (text: string, characterName: string) => string;
		userPersonaName?: string;
	} = $props();

	const dispatch = createEventDispatcher();

	// Filter out null/empty greetings and combine with first_mes
	// Use character.first_mes as the source of truth for the primary greeting
	// This ensures the list doesn't change when we switch greetings (which updates message.content)
	const availableGreetings = $derived(
		[
			character?.first_mes || message.content, // Stable primary greeting
			...(alternateGreetings || [])
		].filter(Boolean)
	);

	const hasMultipleGreetings = $derived(availableGreetings.length > 1);
	const canGoPrevious = $derived(currentGreetingIndex > 0);
	const canGoNext = $derived(currentGreetingIndex < availableGreetings.length - 1);

	// Apply template substitution to the current greeting
	// Use $state + $effect pattern instead of $derived.by to avoid circular reactivity loops
	// during component unmount when substituteTemplateVariables accesses reactive state
	let currentGreeting = $state(message.content);

	$effect(() => {
		const rawGreeting = availableGreetings[currentGreetingIndex] || message.content;

		console.log(
			'🎭 first-message: Computing currentGreeting with userPersonaName =',
			userPersonaName
		);
		console.log('🎭 Raw greeting length:', rawGreeting?.length || 0);

		// Use untrack() to prevent circular reactivity loops during unmount
		// The substituteTemplateVariables function accesses userPersonaName via closure naturally
		untrack(() => {
			if (substituteTemplateVariables && character?.name) {
				const result = substituteTemplateVariables(rawGreeting, character.name);
				console.log('🎭 After substitution, greeting length:', result?.length || 0);
				currentGreeting = result;
			} else {
				console.log('🎭 No substitution (missing substituteTemplateVariables or character.name)');
				currentGreeting = rawGreeting;
			}
		});
	});

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
			class="bg-background ring-border flex size-8 shrink-0 items-center justify-center rounded-full ring-1"
		>
			<div class="translate-y-px">
				<SparklesIcon size={14} />
			</div>
		</div>

		<div class="flex w-full flex-col gap-4">
			<!-- Message content -->
			<div
				class={_cn(
					'prose dark:prose-invert prose-p:leading-relaxed prose-pre:p-0 bg-background w-full max-w-none break-words rounded-md border px-3 py-2'
				)}
			>
				{#key `${message.id}-greeting-${currentGreetingIndex}-${userPersonaName}`}
					<Markdown md={currentGreeting} />
				{/key}
				{#if loading}
					<span class="bg-foreground ml-1 inline-block h-4 w-0.5 animate-pulse"></span>
				{/if}
			</div>

			<!-- Greeting indicator and navigation controls when multiple are available -->
			{#if hasMultipleGreetings}
				<div class="text-muted-foreground flex items-center gap-1 text-xs">
					{#if currentGreetingIndex === 0}
						Primary greeting
					{:else}
						Alternate greeting {currentGreetingIndex}
					{/if}
					<Tooltip>
						<TooltipTrigger>
							<ButtonComponent
								variant="ghost"
								size="icon"
								class="text-foreground h-6 w-6"
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

					<span class="text-muted-foreground px-1 text-xs">
						{currentGreetingIndex + 1}/{availableGreetings.length}
					</span>

					<Tooltip>
						<TooltipTrigger>
							<ButtonComponent
								variant="ghost"
								size="icon"
								class="text-foreground h-6 w-6"
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
