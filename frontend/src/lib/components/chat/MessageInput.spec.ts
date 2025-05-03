import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, fireEvent, screen, cleanup } from '@testing-library/svelte';
import MessageInput from './MessageInput.svelte';

describe('MessageInput', () => {
	afterEach(() => cleanup()); // Clean up DOM after each test

	it('renders the textarea and button', () => {
		render(MessageInput);
		expect(screen.getByPlaceholderText('Type your message...')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /send message/i })).toBeInTheDocument();
	});

	it('updates input value on typing', async () => {
		render(MessageInput);
		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;
		await fireEvent.input(textarea, { target: { value: 'Test message' } });
		expect(textarea.value).toBe('Test message');
	});

	it('emits sendMessage event with trimmed message on button click', async () => {
		const handleMessage = vi.fn();
		render<MessageInput>(MessageInput, { 
			props: {},
			events: {
				sendMessage: (e: CustomEvent<string>) => handleMessage(e.detail)
			}
		});

		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;
		const button = screen.getByRole('button', { name: /send message/i });

		// Test with whitespace
		await fireEvent.input(textarea, { target: { value: '  Hello there!  ' } });
		await fireEvent.click(button);

		expect(handleMessage).toHaveBeenCalledTimes(1);
		expect(handleMessage).toHaveBeenCalledWith('Hello there!');
		// Textarea should be cleared after sending
		expect(textarea.value).toBe('');
	});

    it('does not emit sendMessage event if message is empty or only whitespace on button click', async () => {
		const handleMessage = vi.fn();
		render<MessageInput>(MessageInput, { 
			props: {},
			events: {
				sendMessage: (e: CustomEvent<string>) => handleMessage(e.detail)
			}
		});

		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;
		const button = screen.getByRole('button', { name: /send message/i });

        // Test empty
		await fireEvent.click(button);
        expect(handleMessage).not.toHaveBeenCalled();

        // Test whitespace only
        await fireEvent.input(textarea, { target: { value: '   \n  ' } });
        await fireEvent.click(button);
		expect(handleMessage).not.toHaveBeenCalled();
        expect(textarea.value).toBe('   \n  '); // Value should remain
	});


	it('emits sendMessage event on Enter press (without Shift)', async () => {
		const handleMessage = vi.fn();
		render<MessageInput>(MessageInput, { 
			props: {},
			events: {
				sendMessage: (e: CustomEvent<string>) => handleMessage(e.detail)
			}
		});

		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;

		await fireEvent.input(textarea, { target: { value: 'Send via Enter' } });
		// Simulate Enter key press
		await fireEvent.keyDown(textarea, { key: 'Enter', code: 'Enter' });

		expect(handleMessage).toHaveBeenCalledTimes(1);
		expect(handleMessage).toHaveBeenCalledWith('Send via Enter');
		expect(textarea.value).toBe(''); // Should clear after sending
	});

    it('does not emit sendMessage event on Enter press if message is empty', async () => {
		const handleMessage = vi.fn();
		render<MessageInput>(MessageInput, { 
			props: {},
			events: {
				sendMessage: (e: CustomEvent<string>) => handleMessage(e.detail)
			}
		});

		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;

		// Simulate Enter key press on empty textarea
		await fireEvent.keyDown(textarea, { key: 'Enter', code: 'Enter' });

		expect(handleMessage).not.toHaveBeenCalled();
	});

    it('allows newline with Shift+Enter without sending', async () => {
		const handleMessage = vi.fn();
		render<MessageInput>(MessageInput, { 
			props: {},
			events: {
				sendMessage: (e: CustomEvent<string>) => handleMessage(e.detail)
			}
		});

		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;

        await fireEvent.input(textarea, { target: { value: 'Line 1' } });
        // Simulate Shift+Enter key press
		await fireEvent.keyDown(textarea, { key: 'Enter', code: 'Enter', shiftKey: true });

        // Check if default was prevented (hard to test directly, but check side effects)
        expect(handleMessage).not.toHaveBeenCalled();
        // Value might have newline depending on browser simulation, but shouldn't be cleared
        expect(textarea.value).toContain('Line 1');
    });

	it('disables input and button when disabled prop is true', () => {
		render(MessageInput, { props: { disabled: true } });

		const textarea = screen.getByPlaceholderText('Type your message...');
		const button = screen.getByRole('button', { name: /send message/i });

		expect(textarea).toBeDisabled();
		expect(button).toBeDisabled();
	});

    it('does not emit sendMessage when disabled', async () => {
		const handleMessage = vi.fn();
		render<MessageInput>(MessageInput, { 
			props: { disabled: true },
			events: {
				sendMessage: (e: CustomEvent<string>) => handleMessage(e.detail)
			}
		});

		const textarea = screen.getByPlaceholderText('Type your message...') as HTMLTextAreaElement;
		const button = screen.getByRole('button', { name: /send message/i });

        await fireEvent.input(textarea, { target: { value: 'Cannot send' } });

        // Try clicking button
        await fireEvent.click(button);
        expect(handleMessage).not.toHaveBeenCalled();

        // Try pressing Enter
        await fireEvent.keyDown(textarea, { key: 'Enter', code: 'Enter' });
        expect(handleMessage).not.toHaveBeenCalled();
    });
});