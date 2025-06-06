import { render, screen, waitFor, within, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
// MockInstance was removed as it's no longer used after refactoring the mock
import { tick } from 'svelte';
import Chat from './chat.svelte';
import type {
	User,
	ScribeCharacter,
	ScribeChatSession,
	ScribeChatMessage,
	MessageRole
} from '$lib/types';

// --- Mock for $lib/components/messages.svelte ---
// Removed old MockMessages class, messagesPropsHistory, and getLatestMessagesPassed

// Use the actual Svelte component mock
vi.mock('$lib/components/messages.svelte', async () => {
	const actual = await vi.importActual('$lib/components/__mocks__/Messages.svelte');
	return actual;
});

// Mock ChatHistory context
vi.mock('$lib/hooks/chat-history.svelte', () => {
	const mockRefetch = vi.fn();
	class MockChatHistory {
		static fromContext() {
			// Return an object that mimics the necessary parts of ChatHistory instance
			return {
				refetch: mockRefetch,
				// Add other methods/properties if Chat.svelte uses them (e.g., chats state if needed)
				chats: $state([]) // Add a minimal state if required by other parts, though likely not for this error
			};
		}
		// Add static properties or methods if needed
	}
	// Mock $state for the mock class scope if needed internally by the mock
	const $state = <T>(val: T): T => val;

	return {
		ChatHistory: MockChatHistory
	};
});

// Mock SelectedCharacterStore and SelectedPersonaStore
vi.mock('$lib/stores/selected-character.svelte', () => {
	class MockSelectedCharacterStore {
		characterId = null;
		static fromContext() {
			return new MockSelectedCharacterStore();
		}
		clear() {
			this.characterId = null;
		}
		select(id: string | null) {
			this.characterId = id;
		}
	}
	return {
		SelectedCharacterStore: MockSelectedCharacterStore
	};
});

vi.mock('$lib/stores/selected-persona.svelte', () => {
	class MockSelectedPersonaStore {
		personaId = null;
		static fromContext() {
			return new MockSelectedPersonaStore();
		}
		clear() {
			this.personaId = null;
		}
		selectPersona(id: string | null) {
			this.personaId = id;
		}
	}
	return {
		SelectedPersonaStore: MockSelectedPersonaStore
	};
});

vi.mock('$lib/stores/settings.svelte', () => {
	class MockSettingsStore {
		settings = {};
		static fromContext() {
			return new MockSettingsStore();
		}
	}
	return {
		SettingsStore: MockSettingsStore
	};
});

// --- Mock Browser & SvelteKit APIs ---
vi.mock('svelte/reactivity/window', () => ({
	innerWidth: { current: 1024, subscribe: vi.fn(() => () => {}) }
}));

beforeEach(() => {
	// Set up environment - mock NODE_ENV properly
	vi.stubGlobal('process', {
		...process,
		env: {
			...process.env,
			NODE_ENV: 'test'
		}
	});

	// messagesPropsHistory = []; // Removed: No longer needed

	Element.prototype.scrollIntoView = vi.fn();
	Element.prototype.animate = vi
		.fn()
		.mockReturnValue({ finished: Promise.resolve(), cancel: vi.fn() });
	if (!global.ResizeObserver) {
		global.ResizeObserver = vi.fn().mockImplementation(() => ({
			observe: vi.fn(),
			unobserve: vi.fn(),
			disconnect: vi.fn()
		}));
	}
});

afterEach(() => {
	// Restore the original process object
	vi.unstubAllGlobals();
});

// --- Mock UI Child Components & Hooks ---
vi.mock('$lib/components/sidebar-toggle.svelte', () => ({ default: vi.fn() }));
vi.mock('$lib/components/chat-header.svelte', () => ({ default: vi.fn() }));
vi.mock('$lib/components/ui/input/input.svelte', () => ({ default: vi.fn() }));
// Use actual Button component for testing its event handling
vi.mock('$lib/components/ui/button', async () => {
	const actual = await vi.importActual('$lib/components/ui/button');
	return actual;
});
vi.mock('$lib/components/ui/textarea/textarea.svelte', () => ({ default: vi.fn() }));

vi.mock('$app/forms', () => ({
	enhance: vi.fn((formElement, callback) => {
		const handleSubmit = async (event: Event) => {
			event.preventDefault();
			if (callback) {
				const fakeFetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
				await callback({
					form: formElement as HTMLFormElement,
					data: new FormData(formElement as HTMLFormElement),
					action: new URL((formElement as HTMLFormElement).action),
					cancel: vi.fn(),
					controller: new AbortController(),
					submitter: (formElement as HTMLFormElement).querySelector('button[type="submit"]'),
					fetch: fakeFetch,
					result: { type: 'success', status: 200, data: {} },
					update: vi.fn()
				});
			}
		};
		formElement.addEventListener('submit', handleSubmit);
		return { destroy: () => formElement.removeEventListener('submit', handleSubmit) };
	})
}));

// --- Test Suite ---
describe('Chat.svelte Component', () => {
	const mockUser: User = {
		user_id: 'user-test-123',
		username: 'Test User',
		email: 'test@example.com'
	};

	const mockChatSession: ScribeChatSession = {
		id: 'chat-session-test-456',
		user_id: 'user-test-123',
		character_id: 'char-test-789',
		title: 'Test Chat Session',
		created_at: new Date().toISOString(),
		updated_at: new Date().toISOString(),
		system_prompt: 'You are a helpful test assistant.',
		visibility: 'private',
		temperature: 0.7,
		max_output_tokens: 100,
		frequency_penalty: 0,
		presence_penalty: 0,
		top_k: 50,
		top_p: 0.9,
		seed: null,
		history_management_strategy: 'truncate_start',
		history_management_limit: 10
	};

	const mockCharacter: ScribeCharacter = {
		id: 'char-test-789',
		name: 'Test Character',
		system_prompt: 'System prompt for Test Character',
		first_mes: "Hello from Test Character's first_mes!",
		personality: 'testy',
		scenario: 'a test scenario'
	};

	it("should display character's first_mes when initialMessages is empty", async () => {
		render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				initialMessages: [],
				character: mockCharacter,
				readonly: false
			}
		});

		await waitFor(() => {
			// const messages = getLatestMessagesPassed(); // Removed
			// expect(messages).toBeDefined(); // Removed
			// expect(messages?.length).toBe(1); // Removed
			// expect(messages?.[0]?.content).toBe(mockCharacter.first_mes); // Removed
			// expect(messages?.[0]?.message_type).toBe('assistant' as MessageRole); // Removed

			const mockMessagesComponent = screen.getByTestId('mock-messages-component');
			expect(mockMessagesComponent).toBeInTheDocument();
			expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('1');
			const messageContent = within(mockMessagesComponent).getByText(mockCharacter.first_mes!);
			expect(messageContent).toBeInTheDocument();
			// Check message type via attribute if your mock sets it
			const messageDiv = within(mockMessagesComponent)
				.getByText(mockCharacter.first_mes!)
				.closest('[data-message-type]');
			expect(messageDiv?.getAttribute('data-message-type')).toBe('Assistant');
		});

		// This assertion might be redundant if the above works, but kept for now.
		// screen.findByText is good for asserting visibility.
		expect(await screen.findByText(mockCharacter.first_mes!)).toBeInTheDocument();
	});

	it('should display initialMessages when provided', async () => {
		const initialMessagesData: ScribeChatMessage[] = [
			{
				id: 'msg1',
				session_id: mockChatSession.id,
				message_type: 'user' as MessageRole,
				content: 'Hello from user',
				created_at: new Date().toISOString(),
				user_id: mockUser.user_id
			},
			{
				id: 'msg2',
				session_id: mockChatSession.id,
				message_type: 'assistant' as MessageRole,
				content: 'Hello from assistant',
				created_at: new Date().toISOString(),
				user_id: mockUser.user_id
			}
		];

		render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				initialMessages: initialMessagesData,
				character: mockCharacter,
				readonly: false
			}
		});

		await waitFor(() => {
			// const messages = getLatestMessagesPassed(); // Removed
			// expect(messages).toBeDefined(); // Removed
			// expect(messages?.length).toBe(2); // Removed
			// expect(messages?.[0]?.content).toBe('Hello from user'); // Removed
			// expect(messages?.[1]?.content).toBe('Hello from assistant'); // Removed

			const mockMessagesComponent = screen.getByTestId('mock-messages-component');
			expect(mockMessagesComponent).toBeInTheDocument();
			expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('2');
			expect(within(mockMessagesComponent).getByText('Hello from user')).toBeInTheDocument();
			expect(within(mockMessagesComponent).getByText('Hello from assistant')).toBeInTheDocument();
		});

		// screen.findByText is good for asserting visibility.
		expect(await screen.findByText('Hello from user')).toBeInTheDocument();
		expect(await screen.findByText('Hello from assistant')).toBeInTheDocument();
	});

	it('should display no initial messages if initialMessages is empty and character has no first_mes', async () => {
		const characterWithoutFirstMes: ScribeCharacter = {
			...mockCharacter,
			first_mes: undefined
		};

		render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				initialMessages: [],
				character: characterWithoutFirstMes,
				readonly: false
			}
		});

		await waitFor(() => {
			// const messages = getLatestMessagesPassed(); // Removed
			// expect(messages).toBeDefined(); // Removed
			// expect(messages?.length).toBe(0); // Removed

			const mockMessagesComponent = screen.getByTestId('mock-messages-component');
			expect(mockMessagesComponent).toBeInTheDocument();
			expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('0');
			expect(within(mockMessagesComponent).getByTestId('no-messages')).toBeInTheDocument();
		});

		const messagesContainer = screen.queryByTestId('mock-messages-component'); // Changed from mock-messages
		expect(messagesContainer).toBeInTheDocument();
		// Check actual rendered message elements count if needed, e.g. queryAllByTestId('message-content')
		const renderedMessages = within(messagesContainer!).queryAllByTestId('message-content');
		expect(renderedMessages.length).toBe(0);
	});

	it('should send user message and display optimistic update, then server response', async () => {
		const characterWithoutFirstMes: ScribeCharacter = {
			...mockCharacter,
			first_mes: undefined
		};

		// Mock global fetch for the /generate endpoint to simulate SSE
		global.fetch = vi.fn().mockImplementation((url, _options) => {
			if (typeof url === 'string' && url.endsWith('/generate')) {
				const encoder = new TextEncoder();
				const stream = new ReadableStream({
					async start(controller) {
						// Simulate sending the final message data chunk
						/* // Removed unused variable
            const finalMessagePayload = {
              id: 'server-msg-id',
              session_id: mockChatSession.id,
              message_type: 'Assistant', // Corrected casing
              content: 'Response from server',
              created_at: new Date().toISOString(),
              user_id: mockUser.user_id, 
            };
            */
						// Simulate a simple SSE message containing JSON
						// Note: Real SSE might send delta chunks first.
						// This sends the whole message as one chunk.
						controller.enqueue(
							encoder.encode(`data: ${JSON.stringify({ text: 'Response from server' })}\n\n`)
						);

						// Simulate the [DONE] signal
						controller.enqueue(encoder.encode('data: [DONE]\n\n'));
						controller.close();
					}
				});

				return Promise.resolve({
					ok: true,
					status: 200,
					headers: new Headers({ 'Content-Type': 'text/event-stream' }),
					body: stream, // Provide the stream
					json: () => Promise.reject(new Error('Cannot call .json() on SSE stream response')),
					text: () => Promise.reject(new Error('Cannot call .text() on SSE stream response'))
				});
			}
			return Promise.resolve({
				ok: false,
				status: 404,
				text: () => Promise.resolve('Unknown endpoint')
			});
		});

		const { container } = render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				initialMessages: [],
				character: characterWithoutFirstMes,
				readonly: false,
				initialChatInputValue: 'Test user input'
			}
		});

		await waitFor(() => {
			// const messages = getLatestMessagesPassed(); // Removed
			// expect(messages?.length).toBe(0); // Removed
			const mockMessagesComponent = screen.getByTestId('mock-messages-component');
			expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('0');
		});

		const form = container.querySelector('form');
		expect(form).toBeInTheDocument();

		// const textarea = document.createElement('textarea'); // REMOVE THIS
		// textarea.name = 'userInput'; // REMOVE THIS
		// textarea.value = 'Test user input'; // REMOVE THIS
		// form?.appendChild(textarea); // REMOVE THIS

		form?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
		await tick();

		await waitFor(() => {
			// const messages = getLatestMessagesPassed(); // Removed
			// expect(messages?.length).toBe(2); // Removed
			// expect(messages?.[0]?.content).toBe('Test user input'); // Removed
			// expect(messages?.[0]?.message_type).toBe('user' as MessageRole); // Removed
			// expect(messages?.[1]?.message_type).toBe('assistant'as MessageRole); // Removed
			// expect(messages?.[1]?.loading).toBe(true); // Removed

			const mockMessagesComponent = screen.getByTestId('mock-messages-component');
			expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('2');

			const userInputMessage = within(mockMessagesComponent)
				.getByText('Test user input')
				.closest('[data-message-type]');
			expect(userInputMessage).toBeInTheDocument();
			expect(userInputMessage?.getAttribute('data-message-type')).toBe('User');

			// Check for loading state on the assistant's placeholder message
			// This requires the mock to render something specific for loading, e.g., a data attribute or specific text
			const loadingMessage = within(mockMessagesComponent).getByTestId('message-loading');
			expect(loadingMessage).toBeInTheDocument();
			expect(loadingMessage.closest('[data-message-type]')?.getAttribute('data-message-type')).toBe(
				'Assistant'
			);
		});

		// screen.findByText is good for asserting visibility of optimistic user message.
		expect(await screen.findByText('Test user input')).toBeInTheDocument();

		await waitFor(
			() => {
				// const messages = getLatestMessagesPassed(); // Removed
				// expect(messages?.length).toBe(2); // Removed
				// expect(messages?.[0]?.content).toBe('Test user input'); // Removed
				// expect(messages?.[1]?.content).toBe('Response from server'); // Removed
				// expect(messages?.[1]?.loading === false || messages?.[1]?.loading === undefined).toBe(true); // Removed
				// expect(messages?.[1]?.message_type).toBe('assistant' as MessageRole); // Removed

				const mockMessagesComponent = screen.getByTestId('mock-messages-component');
				expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('2');
				expect(within(mockMessagesComponent).getByText('Test user input')).toBeInTheDocument();

				// Use a more flexible text matcher for the response text
				const responseText = within(mockMessagesComponent).getByText((content, element) => {
					// Make sure element exists before trying to use it
					return Boolean(
						content.includes('Response from server') &&
							element &&
							element.closest('[data-message-type]')?.getAttribute('data-message-type') ===
								'Assistant'
					);
				});
				expect(responseText).toBeInTheDocument();

				const serverMessage = responseText.closest('[data-message-type]');
				expect(serverMessage?.getAttribute('data-message-type')).toBe('Assistant');
				// Ensure loading indicator is gone
				expect(
					within(mockMessagesComponent).queryByTestId('message-loading')
				).not.toBeInTheDocument();
			},
			{ timeout: 2000 }
		);

		// Use the same flexible matcher for the screen.findByText call
		expect(
			await screen.findByText((content) => Boolean(content.includes('Response from server')))
		).toBeInTheDocument();
	});

	it('should call fetchSuggestedActions when "Get Suggestions" button is clicked and enabled', async () => {
		// 1. Spy on console.log
		const consoleLogSpy = vi.spyOn(console, 'log');

		// 2. Mock global.fetch for the suggestions API
		const mockApiFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ suggestions: [{ action: 'Test Suggestion' }] })
		});
		// Store original fetch and restore it later
		const originalFetch = global.fetch;
		global.fetch = mockApiFetch;

		// 3. Define initial messages and character to enable the button
		const testUserMessage: ScribeChatMessage = {
			id: 'user-msg-test-1',
			session_id: mockChatSession.id,
			message_type: 'User',
			content: 'This is the first user message for suggestions test.',
			created_at: new Date(Date.now() - 20000).toISOString(), // Older
			user_id: mockUser.user_id
		};
		const testAssistantResponse: ScribeChatMessage = {
			id: 'assistant-msg-test-1',
			session_id: mockChatSession.id,
			message_type: 'Assistant',
			content: 'This is the first AI response after the user for suggestions test.',
			created_at: new Date(Date.now() - 10000).toISOString(), // Newer than user, older than now
			user_id: ''
		};

		render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				// initialMessages will be processed by the $effect in Chat.svelte
				// The character's first_mes will be added if not present,
				// then these two messages.
				initialMessages: [testUserMessage, testAssistantResponse],
				character: mockCharacter, // Has first_mes
				readonly: false
			}
		});

		// Wait for Svelte's reactivity and component updates, especially $derived state
		await tick(); // Initial render
		await tick(); // $effect for initialMessages
		await tick(); // $derived canFetchSuggestions update

		// 4. Find the button
		const getSuggestionsButton = screen.getByRole('button', { name: /Get Suggestions/i });
		expect(getSuggestionsButton).toBeInTheDocument();

		// Verify the button is NOT disabled (meaning canFetchSuggestions is true)
		// This is a critical check for the test setup itself.
		await waitFor(
			() => {
				expect(getSuggestionsButton).not.toBeDisabled();
			},
			{ timeout: 1000 }
		); // Added timeout for safety

		// Reset the spy to ensure we only capture calls after the click
		consoleLogSpy.mockReset();

		// 5. Simulate a click using fireEvent directly
		fireEvent.click(getSuggestionsButton);

		// 6. Assert console.log was called (from the handler in chat.svelte)
		await waitFor(
			() => {
				expect(consoleLogSpy).toHaveBeenCalledWith('Get Suggestions button clicked!');
			},
			{ timeout: 1000 }
		);

		// 7. Assert fetch was called for suggestions API
		await waitFor(() => {
			expect(mockApiFetch).toHaveBeenCalledWith(
				`/api/chat/actions/${mockChatSession.id}/suggest`,
				expect.objectContaining({
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({}) // API client sends empty object
				})
			);
		});

		// Cleanup
		consoleLogSpy.mockRestore();
		global.fetch = originalFetch; // Restore original fetch
	});

	it('should show the chat interface when in a chat with character (even with only first_mes)', async () => {
		// 1. Spy on console.log
		const consoleLogSpy = vi.spyOn(console, 'log');

		// 2. Mock global.fetch for the suggestions API
		const mockApiFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ suggestions: [{ action: 'Test Suggestion from first_mes' }] })
		});
		const originalFetch = global.fetch;
		global.fetch = mockApiFetch;

		// Render Chat component with a character that has first_mes, but no initial user/assistant messages
		const characterWithOnlyFirstMes: ScribeCharacter = {
			...mockCharacter // mockCharacter already has first_mes
		};

		render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				initialMessages: [], // No initial messages from conversation history
				character: characterWithOnlyFirstMes,
				readonly: false
			}
		});

		// Wait for Svelte's reactivity and component updates
		await tick(); // Initial render
		await tick(); // $effect for initialMessages (will add character.first_mes to internal messages state)
		await tick(); // $effect shouldShowChatInterface update

		// The Get Suggestions button SHOULD be visible when we're in a chat with a character (even with just first_mes)
		const getSuggestionsButton = await screen.findByRole('button', { name: /Get Suggestions/i });
		expect(getSuggestionsButton).toBeInTheDocument();

		// The input form should also be visible
		const inputForm = await screen.findByRole('form');
		expect(inputForm).toBeInTheDocument();

		// Verify the button is NOT disabled
		await waitFor(
			() => {
				expect(getSuggestionsButton).not.toBeDisabled();
			},
			{ timeout: 1000 }
		);

		// Reset the spy to ensure we only capture calls after the click
		consoleLogSpy.mockReset();

		// Simulate a click
		fireEvent.click(getSuggestionsButton);

		// Assert console.log was called
		await waitFor(() => {
			expect(consoleLogSpy).toHaveBeenCalledWith('Get Suggestions button clicked!');
		});

		// Assert fetch was called for suggestions API with correct payload
		await waitFor(() => {
			expect(mockApiFetch).toHaveBeenCalledWith(
				`/api/chat/actions/${mockChatSession.id}/suggest`,
				expect.objectContaining({
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({}) // API client sends empty object
				})
			);
		});

		// Cleanup
		consoleLogSpy.mockRestore();
		global.fetch = originalFetch;
	});

	it('should NOT show the chat interface when not in a chat (no chat session)', async () => {
		// Render Chat component without a chat session (like on main page or character selection)
		render(Chat, {
			props: {
				user: mockUser,
				chat: undefined, // No chat session
				initialMessages: [],
				character: mockCharacter,
				readonly: false
			}
		});

		// Wait for Svelte's reactivity and component updates
		await tick();
		await tick();
		await tick();

		// The Get Suggestions button should NOT be visible when there's no chat session
		const getSuggestionsButton = screen.queryByRole('button', { name: /Get Suggestions/i });
		expect(getSuggestionsButton).not.toBeInTheDocument();

		// The input form should also NOT be visible
		const inputForm = screen.queryByRole('form');
		expect(inputForm).not.toBeInTheDocument();
	});

	it('should NOT show the chat interface when in chat but no character', async () => {
		// Render Chat component with chat session but no character
		render(Chat, {
			props: {
				user: mockUser,
				chat: mockChatSession,
				initialMessages: [],
				character: null, // No character
				readonly: false
			}
		});

		// Wait for Svelte's reactivity and component updates
		await tick();
		await tick();
		await tick();

		// The Get Suggestions button should NOT be visible when there's no character
		const getSuggestionsButton = screen.queryByRole('button', { name: /Get Suggestions/i });
		expect(getSuggestionsButton).not.toBeInTheDocument();

		// The input form should also NOT be visible
		const inputForm = screen.queryByRole('form');
		expect(inputForm).not.toBeInTheDocument();
	});
});
