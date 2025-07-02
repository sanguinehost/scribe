import type { Action } from 'svelte/action';

interface InfiniteScrollOptions {
	threshold?: number; // How far from the top to trigger (in pixels)
	debounce?: number; // Debounce time in milliseconds
}

interface InfiniteScrollEvent {
	loadmore: CustomEvent<void>;
}

/**
 * Svelte action for detecting when user scrolls near the top of a container
 * and dispatching a 'loadmore' event to trigger loading of older messages.
 * 
 * Usage:
 * <div use:infiniteScroll={{ threshold: 100 }} on:loadmore={handleLoadMore}>
 *   <!-- messages -->
 * </div>
 */
export const infiniteScroll: Action<HTMLElement, InfiniteScrollOptions, InfiniteScrollEvent> = (
	node: HTMLElement,
	options: InfiniteScrollOptions = {}
) => {
	const { threshold = 100, debounce = 300 } = options;
	let timeoutId: ReturnType<typeof setTimeout> | null = null;
	let isLoading = false;

	const handleScroll = () => {
		// Don't trigger if already loading
		if (isLoading) return;

		// Clear existing timeout
		if (timeoutId) {
			clearTimeout(timeoutId);
		}

		// Debounce the scroll event
		timeoutId = setTimeout(() => {
			// Check if scrolled near the top
			if (node.scrollTop <= threshold) {
				// Set loading flag to prevent multiple triggers
				isLoading = true;

				// Dispatch the loadmore event
				node.dispatchEvent(new CustomEvent('loadmore'));

				// Reset loading flag after a delay
				// This gives the parent component time to update its own loading state
				setTimeout(() => {
					isLoading = false;
				}, 1000);
			}
		}, debounce);
	};

	// Add scroll event listener
	node.addEventListener('scroll', handleScroll, { passive: true });

	// Check initial scroll position in case already at top
	setTimeout(() => {
		if (node.scrollTop <= threshold) {
			node.dispatchEvent(new CustomEvent('loadmore'));
		}
	}, 100);

	return {
		destroy() {
			// Cleanup
			if (timeoutId) {
				clearTimeout(timeoutId);
			}
			node.removeEventListener('scroll', handleScroll);
		},
		update(newOptions: InfiniteScrollOptions = {}) {
			// Update options if needed
			Object.assign(options, newOptions);
		}
	};
};