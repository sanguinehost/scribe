<script lang="ts">
	import type { Snippet } from 'svelte';
	import { ChevronUp, Maximize2, X } from 'lucide-svelte';

	interface Props {
		title: string;
		icon?: Snippet;
		defaultCollapsed?: boolean;
		onClose?: () => void;
		onExpand?: () => void;
		children?: Snippet;
	}

	let { title, icon, defaultCollapsed = false, onClose, onExpand, children }: Props = $props();

	let collapsed = $state(defaultCollapsed);

	function toggleCollapse() {
		collapsed = !collapsed;
	}
</script>

<div
	class="border-border bg-card/80 mb-3 overflow-hidden rounded-lg border shadow-sm backdrop-blur-sm transition-all duration-200"
>
	<!-- Widget Header -->
	<div class="border-border flex items-center justify-between border-b px-4 py-3">
		<button
			onclick={toggleCollapse}
			class="hover:text-primary flex flex-1 items-center gap-2 text-left transition-colors"
			aria-label="Toggle {title}"
		>
			{#if icon}
				<div class="text-primary">
					{@render icon()}
				</div>
			{/if}
			<h3 class="text-foreground text-sm font-semibold">{title}</h3>
		</button>

		<div class="flex items-center gap-1">
			<!-- Expand Button (optional) -->
			{#if onExpand}
				<button
					onclick={onExpand}
					class="hover:bg-muted flex h-7 w-7 items-center justify-center rounded transition-colors"
					aria-label="Expand {title}"
				>
					<Maximize2
						class="text-muted-foreground hover:text-primary h-3.5 w-3.5 transition-colors"
					/>
				</button>
			{/if}

			<!-- Collapse/Expand Button -->
			<button
				onclick={toggleCollapse}
				class="hover:bg-muted flex h-7 w-7 items-center justify-center rounded transition-colors"
				aria-label={collapsed ? 'Expand' : 'Collapse'}
			>
				<span
					class="text-muted-foreground transition-transform duration-200"
					class:rotate-180={collapsed}
				>
					<ChevronUp class="h-4 w-4" />
				</span>
			</button>

			<!-- Close Button (optional) -->
			{#if onClose}
				<button
					onclick={onClose}
					class="hover:bg-destructive/10 flex h-7 w-7 items-center justify-center rounded transition-colors"
					aria-label="Close {title}"
				>
					<X class="text-muted-foreground hover:text-destructive h-4 w-4" />
				</button>
			{/if}
		</div>
	</div>

	<!-- Widget Content (collapsible) -->
	{#if !collapsed}
		<div class="animate-fade-in p-4">
			{#if children}
				{@render children()}
			{/if}
		</div>
	{/if}
</div>

<style>
	.rotate-180 {
		transform: rotate(180deg);
	}

	@keyframes fadeIn {
		from {
			opacity: 0;
			transform: translateY(-8px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.animate-fade-in {
		animation: fadeIn 0.15s ease-out;
	}
</style>
