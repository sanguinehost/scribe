import { quintOut, cubicOut } from 'svelte/easing';
import { crossfade } from 'svelte/transition';

/**
 * Visible slide and fade transition for view changes
 */
export function slideAndFade(
	node: Element,
	params: {
		duration?: number;
		x?: number;
		y?: number;
		delay?: number;
	} = {}
) {
	const { duration = 400, x = 0, y = 20, delay = 0 } = params;

	const style = getComputedStyle(node);
	const existingTransform = style.transform === 'none' ? '' : style.transform;
	const existingOpacity = +style.opacity;

	return {
		duration,
		delay,
		easing: cubicOut,
		css: (t: number) => `
			transform: ${existingTransform} translate(${x * (1 - t)}px, ${y * (1 - t)}px) scale(${0.98 + t * 0.02});
			opacity: ${t * existingOpacity};
			filter: blur(${(1 - t) * 3}px);
		`
	};
}

/**
 * Enhanced fade with scale transition
 */
export function fadeScale(
	node: Element,
	params: {
		duration?: number;
		start?: number;
		delay?: number;
	} = {}
) {
	const { duration = 350, start = 0.96, delay = 0 } = params;

	const style = getComputedStyle(node);
	const existingTransform = style.transform === 'none' ? '' : style.transform;
	const existingOpacity = +style.opacity;

	return {
		duration,
		delay,
		easing: cubicOut,
		css: (t: number) => `
			transform: ${existingTransform} scale(${start + t * (1 - start)});
			opacity: ${t * existingOpacity};
			filter: blur(${(1 - t) * 2}px);
		`
	};
}

/**
 * Smooth slide transition for tab content
 */
export function slideSmooth(
	node: Element,
	params: {
		duration?: number;
		direction?: 'left' | 'right' | 'up' | 'down';
	} = {}
) {
	const { duration = 300, direction = 'up' } = params;

	const style = getComputedStyle(node);
	const existingOpacity = +style.opacity;

	let x = 0,
		y = 0;
	switch (direction) {
		case 'left':
			x = -30;
			break;
		case 'right':
			x = 30;
			break;
		case 'up':
			y = -20;
			break;
		case 'down':
			y = 20;
			break;
	}

	return {
		duration,
		easing: quintOut,
		css: (t: number) => `
			transform: translate(${x * (1 - t)}px, ${y * (1 - t)}px);
			opacity: ${t * existingOpacity};
		`
	};
}

/**
 * Create a crossfade transition for smooth switching between items
 */
export const [crossfadeItems, crossfadeItemsReceive] = crossfade({
	duration: 400,
	easing: cubicOut,
	fallback(node) {
		return slideAndFade(node, { duration: 400, y: 30 });
	}
});
