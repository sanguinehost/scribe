import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { chatStore, type ChatMessage } from './chatStore';

describe('chatStore', () => {
	beforeEach(() => {
		// Reset store before each test
		chatStore.reset();
	});

	it('initializes with correct default state', () => {
		const state = get(chatStore);
		expect(state.sessionId).toBeNull();
		expect(state.messages).toEqual([]);
		expect(state.isLoadingHistory).toBe(false);
		expect(state.isGeneratingResponse).toBe(false);
		expect(state.error).toBeNull();
	});

	it('setSessionId updates the session ID', () => {
		chatStore.setSessionId('test-session-123');
		const state = get(chatStore);
		expect(state.sessionId).toBe('test-session-123');
	});

	it('loadMessages replaces existing messages and resets loading/error', () => {
		const initialMessages: ChatMessage[] = [{ id: '1', session_id: 's1', user_id: 'u1', sender: 'user', content: 'Initial', created_at: '', updated_at: '' }];
		chatStore.addMessage(initialMessages[0]); // Add one first
        chatStore.setLoadingHistory(true);
        chatStore.setError("Some error");

		const newMessages: ChatMessage[] = [
			{ id: '2', session_id: 's1', user_id: 'u1', sender: 'user', content: 'Hello', created_at: '', updated_at: '' },
			{ id: '3', session_id: 's1', user_id: null, sender: 'ai', content: 'Hi', created_at: '', updated_at: '' }
		];
		chatStore.loadMessages(newMessages);
		const state = get(chatStore);
		expect(state.messages).toEqual(newMessages);
        expect(state.isLoadingHistory).toBe(false);
        expect(state.error).toBeNull();
	});

	it('addMessage appends a message to the list', () => {
		const message1: ChatMessage = { id: '1', session_id: 's1', user_id: 'u1', sender: 'user', content: 'First', created_at: '', updated_at: '' };
		const message2: ChatMessage = { id: '2', session_id: 's1', user_id: null, sender: 'ai', content: 'Second', created_at: '', updated_at: '' };
		chatStore.addMessage(message1);
		chatStore.addMessage(message2);
		const state = get(chatStore);
		expect(state.messages).toEqual([message1, message2]);
	});

    it('updateStreamingMessage appends content to the correct AI message', () => {
        const aiMessage: ChatMessage = { id: 'ai-1', session_id: 's1', user_id: null, sender: 'ai', content: 'Initial AI ', created_at: '', updated_at: '' };
        const userMessage: ChatMessage = { id: 'user-1', session_id: 's1', user_id: 'u1', sender: 'user', content: 'User msg', created_at: '', updated_at: '' };
        chatStore.loadMessages([userMessage, aiMessage]);

        chatStore.updateStreamingMessage('ai-1', 'chunk 1');
        let state = get(chatStore);
        expect(state.messages[1].content).toBe('Initial AI chunk 1');
        expect(state.messages[1].isStreaming).toBe(true);

        chatStore.updateStreamingMessage('ai-1', ' chunk 2');
        state = get(chatStore);
        expect(state.messages[1].content).toBe('Initial AI chunk 1 chunk 2');
        expect(state.messages[1].isStreaming).toBe(true);

        // Should not affect other messages
        expect(state.messages[0].content).toBe('User msg');
    });

    it('finalizeStreamingMessage sets isStreaming to false and handles errors', () => {
        const aiMessage: ChatMessage = { id: 'ai-1', session_id: 's1', user_id: null, sender: 'ai', content: 'Streaming', isStreaming: true, created_at: '', updated_at: '' };
        chatStore.loadMessages([aiMessage]);
        chatStore.setGeneratingResponse(true); // Simulate generation started

        // Finalize without error
        chatStore.finalizeStreamingMessage('ai-1');
        let state = get(chatStore);
        expect(state.messages[0].isStreaming).toBe(false);
        expect(state.messages[0].error).toBeUndefined();
        expect(state.isGeneratingResponse).toBe(false); // Should reset generating state

        // Finalize with error
        chatStore.updateStreamingMessage('ai-1', ''); // Reset content for clarity
        state = get(chatStore);
        state.messages[0].isStreaming = true; // Set streaming back to true
        chatStore.setGeneratingResponse(true); // Simulate generation started again
        chatStore.finalizeStreamingMessage('ai-1', 'Stream failed');
        state = get(chatStore);
        expect(state.messages[0].isStreaming).toBe(false);
        expect(state.messages[0].error).toBe('Stream failed');
        expect(state.isGeneratingResponse).toBe(false); // Should reset generating state
    });

	it('setLoadingHistory updates the loading state', () => {
		chatStore.setLoadingHistory(true);
		expect(get(chatStore).isLoadingHistory).toBe(true);
		chatStore.setLoadingHistory(false);
		expect(get(chatStore).isLoadingHistory).toBe(false);
	});

	it('setGeneratingResponse updates the generating state', () => {
		chatStore.setGeneratingResponse(true);
		expect(get(chatStore).isGeneratingResponse).toBe(true);
		chatStore.setGeneratingResponse(false);
		expect(get(chatStore).isGeneratingResponse).toBe(false);
	});

	it('setError updates the error message', () => {
		chatStore.setError('Test error');
		expect(get(chatStore).error).toBe('Test error');
		chatStore.setError(null);
		expect(get(chatStore).error).toBeNull();
	});

	it('reset sets the store back to initial state', () => {
		chatStore.setSessionId('temp-id');
		chatStore.addMessage({ id: '1', session_id: 's1', user_id: 'u1', sender: 'user', content: 'Test', created_at: '', updated_at: '' });
		chatStore.setError('Some error');
		chatStore.setGeneratingResponse(true);

		chatStore.reset();
		const state = get(chatStore);
		expect(state.sessionId).toBeNull();
		expect(state.messages).toEqual([]);
		expect(state.isLoadingHistory).toBe(false);
		expect(state.isGeneratingResponse).toBe(false);
		expect(state.error).toBeNull();
	});
});