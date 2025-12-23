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
		action?: Snippet;
	}

	let {
		title,
		icon,
		defaultCollapsed = false,
		onClose,
		onExpand,
		children,
		action
	}: Props = $props();

	let collapsed = $state(defaultCollapsed);

	function toggleCollapse() {
		collapsed = !collapsed;
	}
</script>

<div
	class="mb-3 overflow-hidden rounded-lg border border-border bg-card/80 shadow-sm backdrop-blur-sm transition-all duration-200"
>
	<!-- Widget Header -->
	<div class="flex items-center justify-between border-b border-border px-4 py-3">
		<button
			onclick={toggleCollapse}
			class="flex flex-1 items-center gap-2 text-left transition-colors hover:text-primary"
			aria-label="Toggle {title}"
		>
			{#if icon}
				<div class="text-primary">
					{@render icon()}
				</div>
			{/if}
			<h3 class="text-sm font-semibold text-foreground">{title}</h3>
		</button>

		<div class="flex items-center gap-1">
			<!-- Custom Action -->
			{#if action}
				{@render action()}
			{/if}

			<!-- Expand Button (optional) -->
			{#if onExpand}
				<button
					onclick={onExpand}
					class="flex h-7 w-7 items-center justify-center rounded transition-colors hover:bg-muted"
					aria-label="Expand {title}"
				>
					<Maximize2
						class="h-3.5 w-3.5 text-muted-foreground transition-colors hover:text-primary"
					/>
				</button>
			{/if}

			<!-- Collapse/Expand Button -->
			<button
				onclick={toggleCollapse}
				class="flex h-7 w-7 items-center justify-center rounded transition-colors hover:bg-muted"
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
					class="flex h-7 w-7 items-center justify-center rounded transition-colors hover:bg-destructive/10"
					aria-label="Close {title}"
				>
					<X class="h-4 w-4 text-muted-foreground hover:text-destructive" />
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
