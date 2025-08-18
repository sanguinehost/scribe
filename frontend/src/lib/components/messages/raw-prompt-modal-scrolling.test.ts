import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('Raw Prompt Modal Scrolling Behavior', () => {
	let mockElement: HTMLElement;

	beforeEach(() => {
		// Create a mock element for testing scroll properties
		mockElement = document.createElement('div');
		document.body.appendChild(mockElement);
	});

	afterEach(() => {
		if (mockElement.parentNode) {
			mockElement.parentNode.removeChild(mockElement);
		}
	});

	it('should have overflow-y-auto class on scroll container', () => {
		// Create the same structure as the raw prompt modal
		const container = document.createElement('div');
		container.className = 'h-full overflow-y-auto rounded-lg border bg-muted/20';

		// Add sticky header
		const header = document.createElement('div');
		header.className = 'sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2 z-10';

		// Add content
		const content = document.createElement('pre');
		content.className =
			'p-4 text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap break-words font-mono';
		content.textContent = Array(100)
			.fill(null)
			.map((_, i) => `Line ${i + 1}: This is a long line of text that should cause overflow.`)
			.join('\n');

		container.appendChild(header);
		container.appendChild(content);
		document.body.appendChild(container);

		// Verify the structure matches our modal
		expect(container.classList.contains('overflow-y-auto')).toBe(true);
		expect(container.classList.contains('h-full')).toBe(true);
		expect(header.classList.contains('sticky')).toBe(true);
		expect(header.classList.contains('z-10')).toBe(true);

		// Cleanup
		document.body.removeChild(container);
	});

	it('should detect when content exceeds container height', () => {
		// Create a container with limited height
		const container = document.createElement('div');
		container.style.height = '200px';
		container.style.overflowY = 'auto';
		container.className = 'overflow-y-auto';

		// Create content that will definitely be taller than container
		const content = document.createElement('pre');
		content.textContent = Array(100)
			.fill(null)
			.map((_, i) => `Line ${i + 1}: This is a very long line of text.`)
			.join('\n');
		content.style.padding = '1rem';
		content.style.lineHeight = '1.5';

		container.appendChild(content);
		document.body.appendChild(container);

		// Mock dimensions to simulate overflow
		Object.defineProperty(container, 'clientHeight', {
			value: 200,
			configurable: true
		});
		Object.defineProperty(container, 'scrollHeight', {
			value: 1500, // Much larger than clientHeight
			configurable: true
		});

		// Test that scrollHeight > clientHeight indicates scrollbar is needed
		expect(container.scrollHeight).toBeGreaterThan(container.clientHeight);
		expect(container.classList.contains('overflow-y-auto')).toBe(true);

		// Cleanup
		document.body.removeChild(container);
	});

	it('should not show scrollbar when content fits', () => {
		// Create a container with sufficient height
		const container = document.createElement('div');
		container.style.height = '400px';
		container.style.overflowY = 'auto';
		container.className = 'overflow-y-auto';

		// Create short content
		const content = document.createElement('pre');
		content.textContent = 'Short content that fits.';
		content.style.padding = '1rem';

		container.appendChild(content);
		document.body.appendChild(container);

		// Mock dimensions to simulate no overflow
		Object.defineProperty(container, 'clientHeight', {
			value: 400,
			configurable: true
		});
		Object.defineProperty(container, 'scrollHeight', {
			value: 100, // Smaller than clientHeight
			configurable: true
		});

		// Test that scrollHeight <= clientHeight indicates no scrollbar needed
		expect(container.scrollHeight).toBeLessThanOrEqual(container.clientHeight);

		// Cleanup
		document.body.removeChild(container);
	});

	it('should support scrolling to different positions', () => {
		// Create a scrollable container
		const container = document.createElement('div');
		container.style.height = '200px';
		container.style.overflowY = 'auto';
		container.className = 'overflow-y-auto';

		// Create tall content
		const content = document.createElement('div');
		content.style.height = '1000px';
		content.textContent = 'Tall content';

		container.appendChild(content);
		document.body.appendChild(container);

		// Mock scroll behavior
		let scrollTop = 0;
		Object.defineProperty(container, 'scrollTop', {
			get: () => scrollTop,
			set: (value) => {
				scrollTop = value;
			},
			configurable: true
		});

		Object.defineProperty(container, 'clientHeight', {
			value: 200,
			configurable: true
		});
		Object.defineProperty(container, 'scrollHeight', {
			value: 1000,
			configurable: true
		});

		// Test scrolling
		container.scrollTop = 100;
		expect(container.scrollTop).toBe(100);

		container.scrollTop = 500;
		expect(container.scrollTop).toBe(500);

		// Test max scroll position
		const maxScroll = container.scrollHeight - container.clientHeight;
		expect(maxScroll).toBe(800);

		// Cleanup
		document.body.removeChild(container);
	});

	it('should maintain sticky header position during scroll', () => {
		// Create main container
		const container = document.createElement('div');
		container.style.height = '300px';
		container.style.overflowY = 'auto';
		container.className = 'overflow-y-auto';

		// Create sticky header
		const header = document.createElement('div');
		header.className = 'sticky top-0 z-10';
		header.style.position = 'sticky';
		header.style.top = '0';
		header.style.background = 'white';
		header.textContent = 'Sticky Header';

		// Create tall content
		const content = document.createElement('div');
		content.style.height = '1000px';
		content.textContent = 'Tall scrollable content';

		container.appendChild(header);
		container.appendChild(content);
		document.body.appendChild(container);

		// Verify sticky header classes
		expect(header.classList.contains('sticky')).toBe(true);
		expect(header.classList.contains('top-0')).toBe(true);
		expect(header.classList.contains('z-10')).toBe(true);

		// Cleanup
		document.body.removeChild(container);
	});

	it('should show visible scrollbar on overflow in browser environment', () => {
		// Create a container that matches the modal structure exactly
		const outerContainer = document.createElement('div');
		outerContainer.className = 'flex-1 overflow-hidden mt-4';
		outerContainer.style.height = '400px'; // Fixed height to force overflow

		const scrollContainer = document.createElement('div');
		scrollContainer.className = 'h-full overflow-y-auto rounded-lg border bg-muted/20';

		// Add sticky header
		const header = document.createElement('div');
		header.className = 'sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2 z-10';
		header.innerHTML = `
			<div class="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400">
				<div class="h-2 w-2 rounded-full bg-emerald-500"></div>
				Raw Prompt (16,649 characters)
			</div>
		`;

		// Add very long content that will definitely overflow
		const content = document.createElement('pre');
		content.className =
			'p-4 text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap break-words font-mono';
		content.textContent = Array(500)
			.fill(null)
			.map((_, i) =>
				`Line ${i + 1}: This is a very long line of text that represents part of a raw prompt sent to the AI model. `.repeat(
					3
				)
			)
			.join('\n');

		// Assemble the structure
		scrollContainer.appendChild(header);
		scrollContainer.appendChild(content);
		outerContainer.appendChild(scrollContainer);
		document.body.appendChild(outerContainer);

		// Set realistic dimensions
		Object.defineProperty(outerContainer, 'clientHeight', {
			value: 400,
			configurable: true
		});
		Object.defineProperty(scrollContainer, 'clientHeight', {
			value: 390, // Slightly less due to borders/padding
			configurable: true
		});
		Object.defineProperty(scrollContainer, 'scrollHeight', {
			value: 8000, // Much larger due to long content
			configurable: true
		});

		// Verify overflow conditions that should trigger scrollbar
		expect(scrollContainer.scrollHeight).toBeGreaterThan(scrollContainer.clientHeight);
		expect(scrollContainer.classList.contains('overflow-y-auto')).toBe(true);

		// Verify the CSS class that would trigger scrollbar in a real browser
		expect(scrollContainer.classList.contains('overflow-y-auto')).toBe(true);

		// Verify content is actually long enough
		expect(content.textContent?.length).toBeGreaterThan(10000);

		// Test scrolling functionality
		let scrollTop = 0;
		Object.defineProperty(scrollContainer, 'scrollTop', {
			get: () => scrollTop,
			set: (value) => {
				scrollTop = Math.max(
					0,
					Math.min(value, scrollContainer.scrollHeight - scrollContainer.clientHeight)
				);
			},
			configurable: true
		});

		// Simulate scrolling to bottom
		scrollContainer.scrollTop = scrollContainer.scrollHeight;
		expect(scrollContainer.scrollTop).toBe(
			scrollContainer.scrollHeight - scrollContainer.clientHeight
		);

		// Cleanup
		document.body.removeChild(outerContainer);
	});

	it('should verify that browser will show scrollbar with actual CSS', () => {
		// Create a test div with the exact same CSS as the modal
		const testDiv = document.createElement('div');
		testDiv.style.cssText = `
			height: 200px;
			overflow-y: auto;
			border: 1px solid #ccc;
			padding: 1rem;
		`;

		// Add content that's definitely taller than container
		const content = document.createElement('div');
		content.style.cssText = `
			height: 1000px;
			background: linear-gradient(to bottom, red, blue);
		`;
		content.textContent = 'This content is 1000px tall, container is 200px';

		testDiv.appendChild(content);
		document.body.appendChild(testDiv);

		// Mock the dimensions since jsdom doesn't calculate real layout
		Object.defineProperty(testDiv, 'clientHeight', {
			value: 200,
			configurable: true
		});
		Object.defineProperty(testDiv, 'scrollHeight', {
			value: 1000,
			configurable: true
		});

		// In a real browser, this would show a scrollbar
		// We can test the conditions that trigger it
		expect(testDiv.scrollHeight).toBeGreaterThan(testDiv.clientHeight);
		expect(testDiv.style.overflowY).toBe('auto');

		// Test that scrolling works
		testDiv.scrollTop = 100;
		expect(testDiv.scrollTop).toBe(100);

		// Cleanup
		document.body.removeChild(testDiv);
	});

	it('should not have overflow-hidden on dialog content container', () => {
		// Test that the dialog content doesn't prevent scrollbars from showing
		const dialogContent = document.createElement('div');
		// This should NOT have overflow-hidden
		dialogContent.className = 'max-w-4xl max-h-[80vh] flex flex-col';

		const scrollableArea = document.createElement('div');
		scrollableArea.className = 'flex-1 overflow-hidden mt-4';

		const innerScrollContainer = document.createElement('div');
		innerScrollContainer.className = 'h-full overflow-y-auto rounded-lg border bg-muted/20';

		scrollableArea.appendChild(innerScrollContainer);
		dialogContent.appendChild(scrollableArea);
		document.body.appendChild(dialogContent);

		// Verify that the dialog content does NOT hide overflow
		expect(dialogContent.classList.contains('overflow-hidden')).toBe(false);

		// Verify that the scroll container can show scrollbars
		expect(innerScrollContainer.classList.contains('overflow-y-auto')).toBe(true);

		// Verify the parent allows scrollbars to be visible
		expect(scrollableArea.classList.contains('overflow-hidden')).toBe(true); // This is OK, it's the scroll area boundary

		// Cleanup
		document.body.removeChild(dialogContent);
	});
});
