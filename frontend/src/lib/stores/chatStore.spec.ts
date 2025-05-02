// frontend/src/lib/stores/chatStore.spec.ts

import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { chatStore, type Message } from './chatStore'; // Assuming chatStore exports these

describe('chatStore', () => {
	// Helper to reset store to initial state before each test
	const resetStore = () => {
		chatStore.set({
			currentSessionId: null,
			messages: [],
			isLoading: false,
			error: null,
		});
	};

	beforeEach(() => {
		resetStore();
	});

	it('should have the correct initial state', () => {
		const state = get(chatStore);
		expect(state.currentSessionId).toBeNull();
		expect(state.messages).toEqual([]);
		expect(state.isLoading).toBe(false);
		expect(state.error).toBeNull();
	});

	it('should update currentSessionId', () => {
		chatStore.update((state) => ({ ...state, currentSessionId: 'session-123' }));
		expect(get(chatStore).currentSessionId).toBe('session-123');
	});

	it('should add a user message', () => {
		const userMessage: Message = { id: 'msg-1', content: 'Hello AI', sender: 'user' };
		chatStore.update((state) => ({
			...state,
			messages: [...state.messages, userMessage],
		}));
		const state = get(chatStore);
		expect(state.messages).toHaveLength(1);
		expect(state.messages[0]).toEqual(userMessage);
	});

    it('should add an initial AI message placeholder', () => {
        const aiPlaceholder: Message = { id: 'msg-2', content: '', sender: 'ai', isStreaming: true };
        chatStore.update((state) => ({
            ...state,
            messages: [...state.messages, aiPlaceholder],
        }));
        const state = get(chatStore);
        expect(state.messages).toHaveLength(1);
        expect(state.messages[0]).toEqual(aiPlaceholder);
        expect(state.messages[0].isStreaming).toBe(true);
    });

	it('should update an existing AI message during streaming', () => {
		const initialMessages: Message[] = [
			{ id: 'msg-1', content: 'Hello User', sender: 'user' },
			{ id: 'msg-2', content: '', sender: 'ai', isStreaming: true },
		];
		chatStore.set({ ...get(chatStore), messages: initialMessages });

		// Simulate streaming update
		chatStore.update((state) => {
			const updatedMessages = state.messages.map((msg) =>
				msg.id === 'msg-2' ? { ...msg, content: msg.content + 'Hello ' } : msg
			);
			return { ...state, messages: updatedMessages };
		});

        expect(get(chatStore).messages[1].content).toBe('Hello ');
        expect(get(chatStore).messages[1].isStreaming).toBe(true); // Still streaming

        // Simulate another chunk
		chatStore.update((state) => {
			const updatedMessages = state.messages.map((msg) =>
				msg.id === 'msg-2' ? { ...msg, content: msg.content + 'World!' } : msg
			);
			return { ...state, messages: updatedMessages };
		});
        expect(get(chatStore).messages[1].content).toBe('Hello World!');

        // Simulate end of stream
        chatStore.update((state) => {
			const updatedMessages = state.messages.map((msg) =>
				msg.id === 'msg-2' ? { ...msg, isStreaming: false } : msg
			);
			return { ...state, messages: updatedMessages };
		});
        expect(get(chatStore).messages[1].isStreaming).toBe(false);
	});

	it('should set isLoading state', () => {
		chatStore.update((state) => ({ ...state, isLoading: true }));
		expect(get(chatStore).isLoading).toBe(true);
		chatStore.update((state) => ({ ...state, isLoading: false }));
		expect(get(chatStore).isLoading).toBe(false);
	});

	it('should set error state', () => {
		const errorMessage = 'Network Error';
		chatStore.update((state) => ({ ...state, error: errorMessage }));
		expect(get(chatStore).error).toBe(errorMessage);
		chatStore.update((state) => ({ ...state, error: null }));
		expect(get(chatStore).error).toBeNull();
	});

    it('should clear error when loading starts', () => {
        chatStore.set({ ...get(chatStore), error: 'Previous Error' });
        chatStore.update((state) => ({ ...state, isLoading: true, error: null })); // Simulate action start
        expect(get(chatStore).isLoading).toBe(true);
        expect(get(chatStore).error).toBeNull();
    });
});