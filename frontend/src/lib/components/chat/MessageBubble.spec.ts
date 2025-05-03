import { describe, it, expect, afterEach } from 'vitest'; // Added afterEach
import { render, screen, cleanup } from '@testing-library/svelte';
import MessageBubble from './MessageBubble.svelte';
import { tick } from 'svelte'; // Import tick for async updates

describe('MessageBubble', () => {
	afterEach(() => cleanup()); // Clean up DOM after each test

	it('renders user message correctly', () => {
		const messageContent = 'Hello from user';
		render(MessageBubble, { props: { messageContent, sender: 'user' } });

		const messageElement = screen.getByText(messageContent);
		expect(messageElement).toBeInTheDocument();

		// Check alignment/styling (using parent classes as proxy)
		const container = messageElement.closest('.flex');
		expect(container).toHaveClass('justify-end'); // User messages align right

        // Check background/text color (using bubble classes)
        const bubble = messageElement.closest('div[class*="bg-primary"]');
        expect(bubble).toBeInTheDocument();
        expect(bubble).toHaveClass('text-primary-foreground');
	});

	it('renders AI message correctly', () => {
		const messageContent = 'Hello from AI';
		render(MessageBubble, { props: { messageContent, sender: 'ai' } });

		const messageElement = screen.getByText(messageContent);
		expect(messageElement).toBeInTheDocument();

		// Check alignment/styling
		const container = messageElement.closest('.flex');
		expect(container).toHaveClass('justify-start'); // AI messages align left

        // Check background/text color
        const bubble = messageElement.closest('div[class*="bg-muted"]');
        expect(bubble).toBeInTheDocument();
        expect(bubble).toHaveClass('text-muted-foreground');
	});

	it('updates streaming AI message incrementally', async () => {
		const initialContent = 'AI: ';
		// Get rerender function from render result
		const { rerender } = render(MessageBubble, {
			props: { messageContent: initialContent, sender: 'ai', isStreaming: true }
		});

		      // Adjust regex to not require trailing space if component doesn't render it initially
		let messageElement = screen.getByText(new RegExp(initialContent.trim()));
		expect(messageElement).toBeInTheDocument();
		      // Check for streaming indicator (presence of the pulsing span)
        expect(messageElement.querySelector('.animate-pulse')).toBeInTheDocument();

		// Update props using rerender to simulate streaming chunk 1
		await rerender({ messageContent: initialContent + 'Chunk 1', sender: 'ai', isStreaming: true });
        await tick(); // Wait for Svelte to update the DOM

        messageElement = screen.getByText(/AI: Chunk 1/);
		expect(messageElement).toBeInTheDocument();
        expect(messageElement.querySelector('.animate-pulse')).toBeInTheDocument(); // Still streaming

        // Update props using rerender to simulate streaming chunk 2
  await rerender({ messageContent: initialContent + 'Chunk 1 Chunk 2', sender: 'ai', isStreaming: true });
        await tick();

        messageElement = screen.getByText(/AI: Chunk 1 Chunk 2/);
		expect(messageElement).toBeInTheDocument();
        expect(messageElement.querySelector('.animate-pulse')).toBeInTheDocument(); // Still streaming

        // Update props using rerender to simulate end of streaming
        // Need to pass all relevant props again
        await rerender({ messageContent: initialContent + 'Chunk 1 Chunk 2', sender: 'ai', isStreaming: false });
        await tick();

        messageElement = screen.getByText(/AI: Chunk 1 Chunk 2/); // Full final content
		expect(messageElement).toBeInTheDocument();
        expect(messageElement.querySelector('.animate-pulse')).not.toBeInTheDocument(); // No longer streaming
	});

	it('displays error state correctly', () => {
        const messageContent = "This shouldn't show fully";
        const errorMessage = 'Failed to generate response';
		render(MessageBubble, { props: { messageContent, sender: 'ai', error: errorMessage } });

        // Check for error message display
        const errorElement = screen.getByText(new RegExp(`Error: ${errorMessage}`));
        expect(errorElement).toBeInTheDocument();
        // Check the parent div containing the icon and text for the destructive class
        const errorContainer = errorElement.parentElement;
        expect(errorContainer).toHaveClass('text-destructive');

        // Check bubble styling for error
        const bubble = errorElement.closest('div[class*="border-destructive"]');
        expect(bubble).toBeInTheDocument();
        expect(bubble).toHaveClass('bg-destructive/10');

        // Original content should still be present (or partially, depending on design)
        const contentElement = screen.getByText(new RegExp(messageContent));
        expect(contentElement).toBeInTheDocument();

        // Streaming indicator should not be shown when there's an error
        expect(screen.queryByRole('.animate-pulse')).not.toBeInTheDocument();
	});
});