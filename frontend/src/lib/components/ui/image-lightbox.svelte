<script lang="ts">
	import { Button } from './button';
	import { onMount } from 'svelte';

	let {
		src,
		alt = '',
		open = $bindable(false),
		onClose
	}: {
		src: string;
		alt?: string;
		open?: boolean;
		onClose?: () => void;
	} = $props();

	let lightboxElement = $state<HTMLDivElement>();
	let imageElement = $state<HTMLImageElement>();
	let isImageLoaded = $state(false);
	let isImageError = $state(false);

	// Handle keyboard events
	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			closeModal();
		}
	}

	// Handle backdrop click
	function handleBackdropClick(event: MouseEvent) {
		if (event.target === event.currentTarget) {
			closeModal();
		}
	}

	function closeModal() {
		open = false;
		onClose?.();
	}

	// Handle image load states
	function handleImageLoad() {
		isImageLoaded = true;
		isImageError = false;
	}

	function handleImageError() {
		isImageLoaded = false;
		isImageError = true;
	}

	// Clean up URL parameters to get full resolution image
	const fullResolutionSrc = $derived.by(() => {
		try {
			const url = new URL(src);
			url.searchParams.delete('width');
			url.searchParams.delete('height');
			return url.toString();
		} catch {
			// If src is not a valid URL, return as is
			return src;
		}
	});

	// Focus management
	onMount(() => {
		if (open && lightboxElement) {
			lightboxElement.focus();
		}
	});

	$effect(() => {
		if (open && lightboxElement) {
			lightboxElement.focus();
		}
	});
</script>

{#if open}
	<div
		bind:this={lightboxElement}
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4 backdrop-blur-sm"
		onclick={handleBackdropClick}
		onkeydown={handleKeydown}
		tabindex="0"
		role="dialog"
		aria-modal="true"
		aria-label="Image lightbox"
	>
		<!-- Close button -->
		<Button
			variant="ghost"
			size="sm"
			onclick={closeModal}
			class="absolute right-4 top-4 z-10 h-8 w-8 p-0 text-white hover:bg-white/20 hover:text-white"
			aria-label="Close lightbox"
		>
			<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path
					stroke-linecap="round"
					stroke-linejoin="round"
					stroke-width="2"
					d="M6 18L18 6M6 6l12 12"
				/>
			</svg>
		</Button>

		<!-- Image container -->
		<div class="relative max-h-[90vh] max-w-[90vw]">
			{#if !isImageLoaded && !isImageError}
				<!-- Loading state -->
				<div class="flex h-64 w-64 items-center justify-center">
					<div
						class="h-8 w-8 animate-spin rounded-full border-4 border-white/20 border-t-white"
					></div>
				</div>
			{/if}

			{#if isImageError}
				<!-- Error state -->
				<div class="flex h-64 w-64 flex-col items-center justify-center text-white">
					<svg class="mb-2 h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
						/>
					</svg>
					<p class="text-sm">Failed to load image</p>
				</div>
			{/if}

			<!-- Main image -->
			<img
				bind:this={imageElement}
				src={fullResolutionSrc}
				{alt}
				class="max-h-[90vh] max-w-[90vw] rounded-lg object-contain shadow-2xl transition-opacity duration-300 {isImageLoaded
					? 'opacity-100'
					: 'opacity-0'}"
				onload={handleImageLoad}
				onerror={handleImageError}
				onclick={(e) => e.stopPropagation()}
			/>

			{#if alt && isImageLoaded}
				<!-- Image caption -->
				<div
					class="absolute bottom-0 left-0 right-0 bg-black/50 p-2 text-center text-sm text-white backdrop-blur-sm"
				>
					{alt}
				</div>
			{/if}
		</div>
	</div>
{/if}

<style>
	/* Smooth entrance animation */
	:global(.lightbox-enter) {
		animation: lightboxFadeIn 0.2s ease-out;
	}

	:global(.lightbox-exit) {
		animation: lightboxFadeOut 0.2s ease-in;
	}

	@keyframes lightboxFadeIn {
		from {
			opacity: 0;
			transform: scale(0.95);
		}
		to {
			opacity: 1;
			transform: scale(1);
		}
	}

	@keyframes lightboxFadeOut {
		from {
			opacity: 1;
			transform: scale(1);
		}
		to {
			opacity: 0;
			transform: scale(0.95);
		}
	}
</style>
