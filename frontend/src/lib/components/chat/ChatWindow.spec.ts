// frontend/src/lib/components/chat/ChatWindow.spec.ts
import { render, screen, cleanup } from '@testing-library/svelte';
import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest';
import ChatWindow from './ChatWindow.svelte'; // Use direct default import
import { chatStore } from '$lib/stores/chatStore';
import type { Message } from '$lib/stores/chatStore';
import type { Writable } from 'svelte/store';
// Removed unused 'get' import from top level

// Mock ResizeObserver globally
class MockResizeObserver {
    observe() { /* do nothing */ }
    unobserve() { /* do nothing */ }
    disconnect() { /* do nothing */ }
}

// Add to global before tests
beforeEach(() => {
    global.ResizeObserver = global.ResizeObserver || MockResizeObserver;
});

// --- Apply Mocks ---
// Vitest automatically uses mocks from __mocks__ directory for child components.

// Define mock store state structure
interface MockChatStoreState {
    messages: Message[];
    isLoading: boolean;
    error: string | null;
    currentSessionId: string | null;
}

// Define mock store interface including writables for manipulation
interface MockChatStore {
    subscribe: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
    loadMessages: ReturnType<typeof vi.fn>;
    _messages: Writable<Message[]>;
    _isLoading: Writable<boolean>;
    _error: Writable<string | null>;
    _currentSessionId: Writable<string | null>;
}


// Mock chatStore using writables
vi.mock('$lib/stores/chatStore', async () => {
    const svelteStore = await vi.importActual<typeof import('svelte/store')>('svelte/store');
    const writable = svelteStore.writable;
    const get = svelteStore.get; // Keep 'get' for reading initial state and inside 'update'

    // Create writable stores for state
    const _messages = writable<Message[]>([]);
    const _isLoading = writable(false);
    const _error = writable<string | null>(null);
    const _currentSessionId = writable<string | null>('mock-session-123');

    // Mock store methods
    const update = vi.fn((updater: (state: MockChatStoreState) => MockChatStoreState) => {
        const currentState = {
            messages: get(_messages),
            isLoading: get(_isLoading),
            error: get(_error),
            currentSessionId: get(_currentSessionId),
        };
        const newState = updater(currentState);
        _messages.set(newState.messages);
        _isLoading.set(newState.isLoading);
        _error.set(newState.error);
        _currentSessionId.set(newState.currentSessionId);
    });

    // Mock loadMessages method
    const loadMessages = vi.fn((sessionId: string) => {
        _currentSessionId.set(sessionId);
        return Promise.resolve();
    });

    // Mock subscribe to combine writables
    const subscribe = vi.fn((callback: (value: MockChatStoreState) => void) => {
        let combinedState: MockChatStoreState = {
            messages: get(_messages),
            isLoading: get(_isLoading),
            error: get(_error),
            currentSessionId: get(_currentSessionId),
        };

        // Use more specific type for value based on the key
        const updateCombinedState = (key: keyof MockChatStoreState, value: MockChatStoreState[keyof MockChatStoreState]) => {
            combinedState = { ...combinedState, [key]: value };
            callback(combinedState);
        };

        const unsubMessages = _messages.subscribe(val => updateCombinedState('messages', val));
        const unsubLoading = _isLoading.subscribe(val => updateCombinedState('isLoading', val));
        const unsubError = _error.subscribe(val => updateCombinedState('error', val));
        const unsubSessionId = _currentSessionId.subscribe(val => updateCombinedState('currentSessionId', val));

        callback(combinedState); // Initial call

        return () => { // Unsubscriber function
            unsubMessages();
            unsubLoading();
            unsubError();
            unsubSessionId();
        };
    });

    const mockStore: MockChatStore = {
        subscribe,
        update,
        loadMessages,
        _messages,
        _isLoading,
        _error,
        _currentSessionId,
    };

    return { chatStore: mockStore };
});

// Mock api client
vi.mock('$lib/services/apiClient', () => ({
    sendMessageAndGenerate: vi.fn(),
    fetchChatMessages: vi.fn().mockResolvedValue([]),
    createChatSession: vi.fn(),
    listCharacters: vi.fn(),
    uploadCharacter: vi.fn(),
    getCharacterImageUrl: vi.fn(),
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    checkAuthStatus: vi.fn(),
}));

const mockedChatStore = chatStore as unknown as MockChatStore;

describe('ChatWindow.svelte', () => {
	beforeEach(() => {
        mockedChatStore._messages.set([]);
        mockedChatStore._isLoading.set(false);
        mockedChatStore._error.set(null);
        mockedChatStore._currentSessionId.set('mock-session-123');
        vi.clearAllMocks();
    });

	afterEach(() => {
        cleanup();
    });

    it('renders correctly with default empty state', () => {
        render(ChatWindow, { props: { sessionId: 'mock-session-123' } }); // Use direct import
        expect(screen.getByTestId('chat-window-container')).toBeInTheDocument();
        expect(screen.getByTestId('message-input')).toBeInTheDocument();
        expect(screen.queryByTestId('message-bubble')).not.toBeInTheDocument();
    });

	it('renders messages from the chatStore', async () => {
        const mockMessages: Message[] = [
            { id: '1', sender: 'user', content: 'Hello there!', timestamp: new Date() },
            { id: '2', sender: 'ai', content: 'General Kenobi!', timestamp: new Date(), isStreaming: false },
            { id: '3', sender: 'user', content: 'Testing 123', timestamp: new Date() },
        ];
        mockedChatStore._messages.set(mockMessages);

        render(ChatWindow, { props: { sessionId: 'mock-session-123' } }); // Use direct import

        expect(screen.getByText('Hello there!')).toBeInTheDocument();
        expect(screen.getByText('General Kenobi!')).toBeInTheDocument();
        expect(screen.getByText('Testing 123')).toBeInTheDocument();
        const bubbles = screen.getAllByTestId('message-bubble');
        expect(bubbles).toHaveLength(mockMessages.length);
    });

    it('displays loading indicator when chatStore.isLoading is true', () => {
        mockedChatStore._isLoading.set(true);
        render(ChatWindow, { props: { sessionId: 'mock-session-123' } }); // Use direct import
        expect(screen.getByTestId('chat-loading-indicator')).toBeInTheDocument();
    });

    it('displays error message when chatStore.error has a value', () => {
        const errorMessage = 'Failed to fetch messages';
        mockedChatStore._error.set(errorMessage);
        render(ChatWindow, { props: { sessionId: 'mock-session-123' } }); // Use direct import
        expect(screen.getByTestId('chat-error-message')).toBeInTheDocument();
        expect(screen.getByText(new RegExp(errorMessage, 'i'))).toBeInTheDocument();
    });
});