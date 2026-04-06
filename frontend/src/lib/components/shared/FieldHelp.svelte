<script lang="ts">
	/**
	 * FieldHelp Component
	 *
	 * Beautiful tooltip with field descriptions, examples, and AI tips.
	 * Uses shadcn-svelte Tooltip for consistent styling.
	 */

	import * as Tooltip from '$lib/components/ui/tooltip';
	import { Info, Sparkles } from 'lucide-svelte';

	interface Props {
		/** Title of the help tooltip */
		title: string;
		/** Description of what the field is for */
		description: string;
		/** Optional examples to show users */
		examples?: string[];
		/** Optional AI generation tip */
		aiTip?: string;
		/** Icon size (default: 16px) */
		iconSize?: number;
	}

	let { title, description, examples, aiTip, iconSize = 16 }: Props = $props();
</script>

<Tooltip.Provider>
	<Tooltip.Root delayDuration={200}>
		<Tooltip.Trigger
			class="inline-flex items-center justify-center transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
		>
			<Info class="text-muted-foreground" size={iconSize} />
			<span class="sr-only">Help for {title}</span>
		</Tooltip.Trigger>
		<Tooltip.Content
			class="max-w-sm border border-border/50 bg-background/95 p-4 backdrop-blur-sm"
			side="top"
		>
			<div class="space-y-3">
				<!-- Title -->
				<p class="font-semibold text-foreground">{title}</p>

				<!-- Description -->
				<p class="text-sm leading-relaxed text-muted-foreground">
					{description}
				</p>

				<!-- Examples -->
				{#if examples && examples.length > 0}
					<div class="space-y-1.5">
						<p class="text-xs font-medium text-foreground">Examples:</p>
						<ul class="space-y-1 text-xs text-muted-foreground">
							{#each examples as example, i (i)}
								<li class="flex items-start gap-1.5">
									<span class="mt-0.5 text-primary">•</span>
									<span class="flex-1">{example}</span>
								</li>
							{/each}
						</ul>
					</div>
				{/if}

				<!-- AI Tip -->
				{#if aiTip}
					<div
						class="flex items-start gap-2 rounded-md border border-primary/20 bg-primary/5 px-2.5 py-2 text-xs"
					>
						<Sparkles class="mt-0.5 shrink-0 text-primary" size={14} />
						<p class="text-primary-foreground/90">{aiTip}</p>
					</div>
				{/if}
			</div>
		</Tooltip.Content>
	</Tooltip.Root>
</Tooltip.Provider>
