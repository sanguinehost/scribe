import { render, screen, waitFor, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
// MockInstance was removed as it's no longer used after refactoring the mock
import { tick } from 'svelte';
import Chat from './chat.svelte';
import type { User, ScribeCharacter, ScribeChatSession, ScribeChatMessage, MessageRole } from '$lib/types';

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
  const $state = <T,>(val: T): T => val;
  
  return {
    ChatHistory: MockChatHistory,
  };
});

// --- Mock Browser & SvelteKit APIs ---
vi.mock('svelte/reactivity/window', () => ({
  innerWidth: { current: 1024, subscribe: vi.fn(() => () => {}) }
}));

beforeEach(() => {
  // messagesPropsHistory = []; // Removed: No longer needed

  Element.prototype.scrollIntoView = vi.fn();
  Element.prototype.animate = vi.fn().mockReturnValue({ finished: Promise.resolve(), cancel: vi.fn() });
  if (!global.ResizeObserver) {
    global.ResizeObserver = vi.fn().mockImplementation(() => ({
      observe: vi.fn(),
      unobserve: vi.fn(),
      disconnect: vi.fn(),
    }));
  }
});

// --- Mock UI Child Components & Hooks ---
vi.mock('$lib/components/sidebar-toggle.svelte', () => ({ default: vi.fn() }));
vi.mock('$lib/components/chat-header.svelte', () => ({ default: vi.fn() }));
vi.mock('$lib/components/ui/input/input.svelte', () => ({ default: vi.fn() }));
vi.mock('$lib/components/ui/button/index.js', () => ({ Button: vi.fn() }));
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
          update: vi.fn(),
        });
      }
    };
    formElement.addEventListener('submit', handleSubmit);
    return { destroy: () => formElement.removeEventListener('submit', handleSubmit) };
  }),
}));


// --- Test Suite ---
describe('Chat.svelte Component', () => {
  const mockUser: User = {
    user_id: 'user-test-123',
    username: 'Test User',
    email: 'test@example.com',
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
    repetition_penalty: 1.0,
    min_p: 0.01,
    top_a: 0,
    seed: null,
    logit_bias: null,
    history_management_strategy: 'truncate_start',
    history_management_limit: 10,
  };

  const mockCharacter: ScribeCharacter = {
    id: 'char-test-789',
    name: 'Test Character',
    system_prompt: 'System prompt for Test Character',
    first_mes: "Hello from Test Character's first_mes!",
    personality: 'testy',
    scenario: 'a test scenario',
  };

  it('should display character\'s first_mes when initialMessages is empty', async () => {
    render(Chat, {
      props: {
        user: mockUser,
        chat: mockChatSession,
        initialMessages: [],
        character: mockCharacter,
        readonly: false,
      },
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
      const messageContent = within(mockMessagesComponent).getByText(mockCharacter.first_mes!)
      expect(messageContent).toBeInTheDocument();
      // Check message type via attribute if your mock sets it
      const messageDiv = within(mockMessagesComponent).getByText(mockCharacter.first_mes!).closest('[data-message-type]');
      expect(messageDiv?.getAttribute('data-message-type')).toBe('Assistant');
    });

    // This assertion might be redundant if the above works, but kept for now.
    // screen.findByText is good for asserting visibility.
    expect(await screen.findByText(mockCharacter.first_mes!)).toBeInTheDocument();
  });

  it('should display initialMessages when provided', async () => {
    const initialMessagesData: ScribeChatMessage[] = [
      { id: 'msg1', session_id: mockChatSession.id, message_type: 'user' as MessageRole, content: 'Hello from user', created_at: new Date().toISOString(), user_id: mockUser.user_id },
      { id: 'msg2', session_id: mockChatSession.id, message_type: 'assistant' as MessageRole, content: 'Hello from assistant', created_at: new Date().toISOString(), user_id: mockUser.user_id },
    ];

    render(Chat, {
      props: {
        user: mockUser,
        chat: mockChatSession,
        initialMessages: initialMessagesData,
        character: mockCharacter,
        readonly: false,
      },
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
      first_mes: undefined,
    };

    render(Chat, {
      props: {
        user: mockUser,
        chat: mockChatSession,
        initialMessages: [],
        character: characterWithoutFirstMes,
        readonly: false,
      },
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
      first_mes: undefined,
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
            controller.enqueue(encoder.encode(`data: ${JSON.stringify({ text: 'Response from server' })}\n\n`));
            
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
      return Promise.resolve({ ok: false, status: 404, text: () => Promise.resolve('Unknown endpoint') });
    });


    const { container } = render(Chat, {
      props: {
        user: mockUser,
        chat: mockChatSession,
        initialMessages: [],
        character: characterWithoutFirstMes,
        readonly: false,
        initialChatInputValue: 'Test user input'
      },
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
      
      const userInputMessage = within(mockMessagesComponent).getByText('Test user input').closest('[data-message-type]');
      expect(userInputMessage).toBeInTheDocument();
      expect(userInputMessage?.getAttribute('data-message-type')).toBe('User');
      
      // Check for loading state on the assistant's placeholder message
      // This requires the mock to render something specific for loading, e.g., a data attribute or specific text
      const loadingMessage = within(mockMessagesComponent).getByTestId('message-loading');
      expect(loadingMessage).toBeInTheDocument();
      expect(loadingMessage.closest('[data-message-type]')?.getAttribute('data-message-type')).toBe('Assistant');
    });
    
    // screen.findByText is good for asserting visibility of optimistic user message.
    expect(await screen.findByText('Test user input')).toBeInTheDocument();

    await waitFor(() => {
      // const messages = getLatestMessagesPassed(); // Removed
      // expect(messages?.length).toBe(2); // Removed
      // expect(messages?.[0]?.content).toBe('Test user input'); // Removed
      // expect(messages?.[1]?.content).toBe('Response from server'); // Removed
      // expect(messages?.[1]?.loading === false || messages?.[1]?.loading === undefined).toBe(true); // Removed
      // expect(messages?.[1]?.message_type).toBe('assistant' as MessageRole); // Removed

      const mockMessagesComponent = screen.getByTestId('mock-messages-component');
      expect(mockMessagesComponent.getAttribute('data-messages-count')).toBe('2');
      expect(within(mockMessagesComponent).getByText('Test user input')).toBeInTheDocument();
      expect(within(mockMessagesComponent).getByText('Response from server')).toBeInTheDocument();

      const serverMessage = within(mockMessagesComponent).getByText('Response from server').closest('[data-message-type]');
      expect(serverMessage?.getAttribute('data-message-type')).toBe('Assistant');
      // Ensure loading indicator is gone
      expect(within(mockMessagesComponent).queryByTestId('message-loading')).not.toBeInTheDocument();
    }, { timeout: 2000 });

    // screen.findByText is good for asserting visibility of server response.
    expect(await screen.findByText('Response from server')).toBeInTheDocument();

    // @ts-expect-error - Resetting global fetch after test
    global.fetch = undefined;
  });

}); 