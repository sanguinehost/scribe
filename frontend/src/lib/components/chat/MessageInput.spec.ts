// frontend/src/lib/components/chat/MessageInput.spec.ts
import { render, screen, fireEvent, cleanup } from '@testing-library/svelte';
import { describe, it, expect, afterEach, vi, beforeEach, type Mock } from 'vitest';
import { tick } from 'svelte';
import { writable } from 'svelte/store'; // Import writable for mocking

// Define Message type locally if needed
interface Message {
	id: string;
	sender: 'user' | 'ai';
	content: string;
	timestamp: number;
}

// Mock the chatStore module
vi.mock('$lib/stores/chatStore', () => {
	const mockSendMessage = vi.fn();
	const mockIsLoading = writable(false); // Mock loading state
	const mockError = writable<string | null>(null); // Mock error state
	const mockMessages = writable<Message[]>([]); // Mock messages with correct type
	const mockCurrentSessionId = writable<string | null>(null); // Mock session ID if needed

	// Mock the actual store structure and methods used by the component
	const mockChatStore = {
		subscribe: vi.fn((run) => {
			// Combine mocked states for subscription - Explicitly type state
			const state: { isLoading: boolean; error: string | null; messages: Message[]; currentSessionId: string | null } = {
				isLoading: false,
				error: null,
				messages: [], // Use Message[] type
				currentSessionId: null
			};
			const unsubLoading = mockIsLoading.subscribe(val => { state.isLoading = val; run(state); });
			const unsubError = mockError.subscribe(val => { state.error = val; run(state); });
			const unsubMessages = mockMessages.subscribe(val => { state.messages = val; run(state); });
			const unsubSession = mockCurrentSessionId.subscribe(val => { state.currentSessionId = val; run(state); });
			return () => { unsubLoading(); unsubError(); unsubMessages(); unsubSession(); }; // Unsubscribe function
		}),
		sendMessage: mockSendMessage,
		// Add mocks for other methods if MessageInput uses them
		loadMessages: vi.fn(),
		set: vi.fn(), // Mock set if used directly
		update: vi.fn(), // Mock update if used directly
		// Expose mocks for manipulation in tests
		__mocks: {
			sendMessage: mockSendMessage,
			isLoading: mockIsLoading,
			error: mockError,
			messages: mockMessages,
			currentSessionId: mockCurrentSessionId
		}
	};
	return { chatStore: mockChatStore };
});

// Import component AFTER mocking
import MessageInput from './MessageInput.svelte';

// Get access to the mocks - Use Mock type
const { __mocks: chatStoreMocks } = vi.mocked(
	await import('$lib/stores/chatStore')
).chatStore as unknown as { __mocks: { 
	sendMessage: Mock,
	isLoading: ReturnType<typeof writable<boolean>>,
	error: ReturnType<typeof writable<string | null>>,
	messages: ReturnType<typeof writable<Message[]>>,
	currentSessionId: ReturnType<typeof writable<string | null>> 
}};

describe('MessageInput.svelte', () => {
	beforeEach(() => {
		// Reset mocks before each test
		vi.clearAllMocks();
		chatStoreMocks.sendMessage.mockClear();
		chatStoreMocks.isLoading.set(false); // Reset loading state
	});

	afterEach(() => cleanup());

	it('renders the textarea and send button', () => {
		render(MessageInput);
		expect(screen.getByPlaceholderText('Type your message here...')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /send/i })).toBeInTheDocument();
	});

	it('updates the textarea value on input', async () => {
		render(MessageInput);
		const textarea = screen.getByPlaceholderText('Type your message here...') as HTMLTextAreaElement;
		await fireEvent.input(textarea, { target: { value: 'Test message' } });
		expect(textarea.value).toBe('Test message');
	});

	it('calls chatStore.sendMessage on send button click', async () => {
		render(MessageInput);
		const textarea = screen.getByPlaceholderText('Type your message here...') as HTMLTextAreaElement;
		const sendButton = screen.getByRole('button', { name: /send/i });
		const testMessage = 'Hello AI!';

		// Input text and click send
		await fireEvent.input(textarea, { target: { value: testMessage } });
		await tick(); // Allow component state to update
		await fireEvent.click(sendButton);

		// Check if the mocked store method was called correctly
		expect(chatStoreMocks.sendMessage).toHaveBeenCalledTimes(1);
		expect(chatStoreMocks.sendMessage).toHaveBeenCalledWith(testMessage);
	});

	it('clears the textarea after sending a message', async () => {
		render(MessageInput);
		const textarea = screen.getByPlaceholderText('Type your message here...') as HTMLTextAreaElement;
		const sendButton = screen.getByRole('button', { name: /send/i });

		await fireEvent.input(textarea, { target: { value: 'Message to clear' } });
		await tick(); // Allow state update
		expect(textarea.value).toBe('Message to clear');

		await fireEvent.click(sendButton);
		await tick(); // Allow component to process send and clear

		// Textarea should be cleared after sending
		expect(textarea.value).toBe('');
	});

	it('disables the send button when the input is empty or only whitespace', async () => {
		render(MessageInput);
		const textarea = screen.getByPlaceholderText('Type your message here...') as HTMLTextAreaElement;
		const sendButton = screen.getByRole('button', { name: /send/i });

		// Initially empty, should be disabled
		expect(sendButton).toBeDisabled();

		// Type whitespace, should still be disabled
		await fireEvent.input(textarea, { target: { value: '   \n  ' } });
		await tick(); // Allow state update
		expect(sendButton).toBeDisabled();

		// Type actual text, should be enabled
		await fireEvent.input(textarea, { target: { value: '  Valid text ' } });
		await tick(); // Allow state update
		expect(sendButton).not.toBeDisabled();

		// Clear text, should be disabled again
		await fireEvent.input(textarea, { target: { value: '' } });
		await tick(); // Allow state update
		expect(sendButton).toBeDisabled();
	});

	it('disables send button while message is being sent', async () => {
		render(MessageInput);
		const textarea = screen.getByPlaceholderText('Type your message here...') as HTMLTextAreaElement;
		const sendButton = screen.getByRole('button', { name: /send/i });

		await fireEvent.input(textarea, { target: { value: 'Test during send' } });
		await tick();
		expect(sendButton).not.toBeDisabled(); // Should be enabled before sending

		// Simulate loading state starting
		chatStoreMocks.isLoading.set(true);
		await tick(); // Allow component to react to store change

		// Get the button again since it might have changed after state updates
		const disabledButton = screen.getByRole('button', { name: /send/i });
		expect(disabledButton).toBeDisabled();

		// Simulate loading finished and restore input
		chatStoreMocks.isLoading.set(false);
		await fireEvent.input(textarea, { target: { value: 'Text restored' } });
		await tick();
		
		// Button should be enabled again 
		expect(screen.getByRole('button', { name: /send/i })).not.toBeDisabled();
	});
});