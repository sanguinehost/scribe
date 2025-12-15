<script lang="ts">
	import type { Snippet } from 'svelte';

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
	class="mb-3 overflow-hidden rounded-lg border border-purple-500/20 bg-gray-900/80 backdrop-blur-sm transition-all duration-200"
>
	<!-- Widget Header -->
	<div class="flex items-center justify-between border-b border-purple-500/10 px-4 py-3">
		<button
			onclick={toggleCollapse}
			class="flex flex-1 items-center gap-2 text-left transition-colors hover:text-purple-400"
			aria-label="Toggle {title}"
		>
			{#if icon}
				<div class="text-purple-400">
					{@render icon()}
				</div>
			{/if}
			<h3 class="text-sm font-semibold">{title}</h3>
		</button>

		<div class="flex items-center gap-1">
			<!-- Expand Button (optional) -->
			{#if onExpand}
				<button
					onclick={onExpand}
					class="flex h-7 w-7 items-center justify-center rounded transition-colors hover:bg-purple-500/10"
					aria-label="Expand {title}"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						class="h-3.5 w-3.5 text-gray-400 transition-colors hover:text-purple-400"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
					>
						<polyline points="15 3 21 3 21 9"></polyline>
						<polyline points="9 21 3 21 3 15"></polyline>
						<line x1="21" y1="3" x2="14" y2="10"></line>
						<line x1="3" y1="21" x2="10" y2="14"></line>
					</svg>
				</button>
			{/if}

			<!-- Collapse/Expand Button -->
			<button
				onclick={toggleCollapse}
				class="flex h-7 w-7 items-center justify-center rounded transition-colors hover:bg-purple-500/10"
				aria-label={collapsed ? 'Expand' : 'Collapse'}
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-4 w-4 text-gray-400 transition-transform duration-200"
					class:rotate-180={collapsed}
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
				>
					<path d="m18 15-6-6-6 6" />
				</svg>
			</button>

			<!-- Close Button (optional) -->
			{#if onClose}
				<button
					onclick={onClose}
					class="flex h-7 w-7 items-center justify-center rounded transition-colors hover:bg-red-500/10"
					aria-label="Close {title}"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						class="h-4 w-4 text-gray-400 hover:text-red-400"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
					>
						<path d="M18 6L6 18M6 6l12 12" />
					</svg>
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
