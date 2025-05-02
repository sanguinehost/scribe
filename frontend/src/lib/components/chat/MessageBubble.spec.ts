import { render, screen, cleanup } from '@testing-library/svelte';
// import { tick } from 'svelte'; // No longer needed with rerender
import type { ComponentProps } from 'svelte';
import { describe, it, expect, afterEach } from 'vitest';
import MessageBubble from './MessageBubble.svelte';

describe('MessageBubble.svelte', () => {
	afterEach(() => cleanup());

	it('renders user message correctly', () => {
		const props: ComponentProps<MessageBubble> = {
			messageContent: 'Hello from user',
			sender: 'user'
		};
		const { container } = render(MessageBubble, { props });
		const messageElement = screen.getByText('Hello from user');
		expect(messageElement).toBeInTheDocument();
		// Check alignment via parent class
		const containerDiv = container.querySelector('.flex.w-full'); // Find the outer container
		expect(containerDiv).toHaveClass('justify-end');
	});

	it('renders AI message correctly', () => {
		const props: ComponentProps<MessageBubble> = {
			messageContent: 'Hello from AI',
			sender: 'ai'
		};
		const { container } = render(MessageBubble, { props });
		const messageElement = screen.getByText('Hello from AI');
		expect(messageElement).toBeInTheDocument();
		// Check alignment via parent class
		const containerDiv = container.querySelector('.flex.w-full'); // Find the outer container
		expect(containerDiv).toHaveClass('justify-start');
	});

	it('updates message content reactively when streaming', async () => {
		const initialProps: ComponentProps<MessageBubble> = {
			messageContent: 'Initial',
			sender: 'ai',
			isStreaming: true
		};
		// Get rerender function from the render result
		const { rerender } = render(MessageBubble, { props: initialProps });
		// const messageBubbleComponent = component as MessageBubble; // No longer needed

		expect(screen.getByText('Initial')).toBeInTheDocument();
		// Check for streaming indicator
		const indicator = screen.getByText('▋'); // Check for the cursor character
		expect(indicator).toBeInTheDocument();
		expect(indicator).toHaveClass('animate-pulse'); // Check its class

		// Simulate prop update using the returned rerender function
		await rerender({ ...initialProps, messageContent: 'Initial streamed content' });

		expect(screen.queryByText('Initial')).not.toBeInTheDocument();
		expect(screen.getByText('Initial streamed content')).toBeInTheDocument();
		// Indicator should still be present
		expect(screen.getByText('▋')).toBeInTheDocument();

		// Simulate further streaming
		await rerender({ ...initialProps, messageContent: 'Initial streamed content final part' });

		expect(screen.queryByText('Initial streamed content')).not.toBeInTheDocument();
		expect(screen.getByText('Initial streamed content final part')).toBeInTheDocument();
		// Indicator should still be present
		expect(screen.getByText('▋')).toBeInTheDocument();

		// Simulate streaming finished
		await rerender({
			...initialProps,
			messageContent: 'Initial streamed content final part',
			isStreaming: false
		});

		// Indicator should be gone
		expect(screen.queryByText('▋')).not.toBeInTheDocument();
	});

    it('does not require isStreaming prop and defaults to false', () => {
  const props: ComponentProps<MessageBubble> = {
   messageContent: 'Non-streaming AI',
  sender: 'ai'
 };
 const { container } = render(MessageBubble, { props });
 const messageElement = screen.getByText('Non-streaming AI');
 expect(messageElement).toBeInTheDocument();
 // Check default alignment
 const containerDiv = container.querySelector('.flex.w-full'); // Find the outer container
 expect(containerDiv).toHaveClass('justify-start');
 // Ensure streaming indicator is not present
 expect(screen.queryByText('▋')).not.toBeInTheDocument();
});

// REMOVED: Tests for 'error' prop as the feature is commented out in the component
// it('displays an error message when error prop is provided', () => { ... });
// it('does not display error message when error prop is null or undefined', () => { ... });

// Add specific tests for streaming indicator presence/absence
it('shows a streaming indicator for AI sender when isStreaming is true', () => {
 render(MessageBubble, {
  props: { messageContent: 'Streaming...', sender: 'ai', isStreaming: true }
 });
 const indicator = screen.getByText('▋');
 expect(indicator).toBeInTheDocument();
 expect(indicator).toHaveClass('animate-pulse');
});

it('hides streaming indicator for AI sender when isStreaming is false', () => {
 render(MessageBubble, {
  props: { messageContent: 'Done streaming', sender: 'ai', isStreaming: false }
 });
 expect(screen.queryByText('▋')).not.toBeInTheDocument();
});

it('hides streaming indicator for user sender even if isStreaming is true', () => {
 // User messages should never show the indicator
 render(MessageBubble, {
  props: { messageContent: 'User message', sender: 'user', isStreaming: true }
 });
 expect(screen.queryByText('▋')).not.toBeInTheDocument();
});

// Optional: Test for streaming indicator if implemented (Now implemented above)
// it('shows a streaming indicator when isStreaming is true', () => {
	// 	render(MessageBubble, {
	// 		props: { messageContent: 'Streaming...', sender: 'ai', isStreaming: true }
	// 	});
    //     expect(screen.getByTestId('streaming-indicator')).toBeInTheDocument();
    // });

    // it('hides streaming indicator when isStreaming is false', () => {
	// 	render(MessageBubble, {
	// 		props: { messageContent: 'Done streaming', sender: 'ai', isStreaming: false }
	// 	});
    //     expect(screen.queryByTestId('streaming-indicator')).not.toBeInTheDocument();
    // });
});