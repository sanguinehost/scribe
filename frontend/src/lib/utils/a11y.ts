/**
 * Keyboard trap utility for modals and overlays.
 * Used when a dialog requires focus containment.
 */
export function trapFocus(node: HTMLElement) {
	const focusableElements =
		'a[href], area[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), iframe, object, embed, [tabindex="0"], [contenteditable]';

	function handleKeyDown(e: KeyboardEvent) {
		const isTabPressed = e.key === 'Tab' || e.keyCode === 9;

		if (!isTabPressed) {
			return;
		}

		const focusableNodes = Array.from(node.querySelectorAll<HTMLElement>(focusableElements));
		const firstElement = focusableNodes[0];
		const lastElement = focusableNodes[focusableNodes.length - 1];

		if (e.shiftKey) {
			if (document.activeElement === firstElement) {
				lastElement.focus();
				e.preventDefault();
			}
		} else {
			if (document.activeElement === lastElement) {
				firstElement.focus();
				e.preventDefault();
			}
		}
	}

	node.addEventListener('keydown', handleKeyDown);

	return {
		destroy() {
			node.removeEventListener('keydown', handleKeyDown);
		}
	};
}

/**
 * Screen reader announcer utility
 */
export const announcer = {
	announce: (message: string, priority: 'polite' | 'assertive' = 'polite') => {
		let liveRegion = document.getElementById('a11y-announcer');
		if (!liveRegion) {
			liveRegion = document.createElement('div');
			liveRegion.id = 'a11y-announcer';
			liveRegion.className = 'sr-only';
			liveRegion.setAttribute('aria-live', priority);
			liveRegion.setAttribute('aria-atomic', 'true');
			document.body.appendChild(liveRegion);
		}

		// Clear first to ensure screen readers re-read same messages
		liveRegion.textContent = '';
		setTimeout(() => {
			if (liveRegion) liveRegion.textContent = message;
		}, 50);
	}
};
