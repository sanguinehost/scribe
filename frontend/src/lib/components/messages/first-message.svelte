<script lang="ts">
	import { cn as _cn } from '$lib/utils/shadcn';
	import SparklesIcon from '../icons/sparkles.svelte';
	import { ChevronLeft, ChevronRight } from '@lucide/svelte';
	import { Button as ButtonComponent } from '../ui/button';
	import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
	import { Markdown } from '../markdown';
	import { fly } from 'svelte/transition';
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
	const availableGreetings = $derived(
		[
			message.content, // The current first message
			...(alternateGreetings || [])
		].filter(Boolean)
	);

	const hasMultipleGreetings = $derived(availableGreetings.length > 1);
	const canGoPrevious = $derived(currentGreetingIndex > 0);
	const canGoNext = $derived(currentGreetingIndex < availableGreetings.length - 1);
	// Apply template substitution to the current greeting, following character-overview.svelte pattern
	// NOTE: We explicitly reference userPersonaName here to create a Svelte dependency,
	// even though substituteTemplateVariables uses it via closure. This ensures the
	// derivation re-computes when userPersonaName changes.
	const currentGreeting = $derived.by(() => {
		const rawGreeting = availableGreetings[currentGreetingIndex] || message.content;

		console.log(
			'🎭 first-message: Computing currentGreeting with userPersonaName =',
			userPersonaName
		);
		console.log('🎭 Raw greeting length:', rawGreeting?.length || 0);

		// Access userPersonaName to create dependency (even though the function uses it via closure)
		const _personaName = userPersonaName;

		if (substituteTemplateVariables && character?.name) {
			const result = substituteTemplateVariables(rawGreeting, character.name);
			console.log('🎭 After substitution, greeting length:', result?.length || 0);
			console.log('🎭 Persona name dependency tracked:', _personaName);
			return result;
		}
		console.log('🎭 No substitution (missing substituteTemplateVariables or character.name)');
		return rawGreeting;
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
				{#key `${message.id}-greeting-${currentGreetingIndex}-${userPersonaName}`}
					<Markdown md={currentGreeting} />
				{/key}
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
