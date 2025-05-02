// frontend/src/lib/services/apiClient.spec.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'; // Removed unused afterEach
// Removed unused get import
import {
	createChatSession,
	fetchChatMessages,
	generateChatResponse, // <-- Renamed function
	// Assuming apiClient exports these and Message type
	type Message,
} from './apiClient';
import { chatStore } from '$lib/stores/chatStore'; // Need store to check side effects

// Mock fetch - Use vi.fn() directly on globalThis for better type inference with vi.mocked
globalThis.fetch = vi.fn();


// REMOVED: MockEventSource class and vi.stubGlobal('EventSource', ...)
// generateChatResponse now uses fetch and manual stream processing.

// Helper to reset store and mocks
const reset = () => {
	chatStore.set({
		currentSessionId: 'test-session-123', // Assume a session exists for some tests
		messages: [],
		isLoading: false,
		error: null,
	});
	vi.clearAllMocks(); // Clear fetch mocks
	vi.mocked(fetch).mockClear(); // Explicitly clear fetch mock
};

describe('apiClient', () => {
	beforeEach(reset);
    // REMOVED: afterEach related to EventSource cleanup

	// --- createChatSession ---
	describe('createChatSession', () => {
		it('should call POST /api/chats and return sessionId', async () => {
			const mockJsonResponse = { session_id: 'new-session-456' }; // Use snake_case for the raw JSON mock
			// Use vi.mocked for type safety
			// Ensure the json mock returns a resolved promise
			vi.mocked(fetch).mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve(mockJsonResponse), // Explicitly resolve promise
			} as Response);

			const result = await createChatSession('char-abc');

			expect(fetch).toHaveBeenCalledWith('/api/chats', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, // Added Accept
				body: JSON.stringify({ character_id: 'char-abc' }),
				credentials: 'include', // Added credentials
			});
			expect(result).toEqual({ sessionId: 'new-session-456' }); // Assert the function's output format
		});

		it('should throw an error if the API call fails', async () => {
			vi.mocked(fetch).mockResolvedValueOnce({
				ok: false,
				status: 500,
				statusText: 'Server Error',
			} as Response);

			await expect(createChatSession('char-abc')).rejects.toThrow(
				'Failed to create chat session: 500 Server Error'
			);
		});
	});

	// --- fetchChatMessages ---
	describe('fetchChatMessages', () => {
		it('should call GET /api/chats/{id}/messages and return messages', async () => {
			const mockMessages: Message[] = [ // Assuming Message type is defined correctly in apiClient.ts
				{ id: 'm1', content: 'Hi', sender: 'user', timestamp: new Date() },
				{ id: 'm2', content: 'Hello', sender: 'ai', timestamp: new Date() },
			];
			vi.mocked(fetch).mockResolvedValueOnce({
				ok: true,
				json: async () => mockMessages, // Assuming API returns array directly
			} as Response);

			const result = await fetchChatMessages('session-789');

			expect(fetch).toHaveBeenCalledWith('/api/chats/session-789/messages', {
				method: 'GET', // Added method
				headers: { Accept: 'application/json' }, // Added Accept
				credentials: 'include', // Added credentials
			});
			expect(result).toEqual(mockMessages);
		});

		it('should throw an error if the API call fails', async () => {
			vi.mocked(fetch).mockResolvedValueOnce({
				ok: false,
				status: 404,
				statusText: 'Not Found',
			} as Response);

			await expect(fetchChatMessages('session-789')).rejects.toThrow(
				'Failed to fetch chat messages: 404 Not Found'
			);
		});
	});

	// --- generateChatResponse ---
	// Helper to create a mock ReadableStream from SSE message strings
	function createMockStream(messages: string[]): ReadableStream<Uint8Array> {
		const encoder = new TextEncoder();
		let cancelled = false;
		return new ReadableStream({
			async pull(controller) {
				if (cancelled) {
					return;
				}
				if (messages.length === 0) {
					controller.close();
					return;
				}
				const msg = messages.shift();
				if (msg !== undefined) {
					controller.enqueue(encoder.encode(msg + '\n\n')); // SSE messages end with \n\n
					await new Promise(resolve => setTimeout(resolve, 1)); // Simulate async delay
				} else {
					controller.close();
				}
			},
			cancel() {
				cancelled = true;
				// console.log("Mock stream cancelled");
			}
		});
	}

	describe('generateChatResponse', () => {
		const sessionId = 'test-session-123';
		const userMessageContent = 'Tell me a joke';
		let onChunkMock: ReturnType<typeof vi.fn>;
		let onErrorMock: ReturnType<typeof vi.fn>;
		let onCompleteMock: ReturnType<typeof vi.fn>;

		beforeEach(() => {
			// Reset mocks for callbacks
			onChunkMock = vi.fn();
			onErrorMock = vi.fn();
			onCompleteMock = vi.fn();
			// Reset store if needed (already handled by global beforeEach)
			chatStore.set({
				currentSessionId: sessionId,
				messages: [], // Start fresh
				isLoading: false,
				error: null,
			});
			vi.mocked(fetch).mockClear(); // Clear fetch mocks specifically
		});

		// Helper to mock fetch for generateChatResponse
		const mockFetchStream = (streamMessages: string[], status = 200, ok = true, statusText = 'OK') => {
			const stream = createMockStream([...streamMessages]); // Clone array to avoid mutation issues
			const mockResponse = {
				ok: ok,
				status: status,
				statusText: statusText, // Added statusText
				body: stream,
				headers: new Headers({ 'Content-Type': 'text/event-stream' }),
				json: async () => { throw new Error('Should not call json() on stream'); },
				text: async () => { throw new Error('Should not call text() on stream'); },
				// Add other essential Response properties required by TS/runtime if needed
				type: 'basic', // Added type
				url: `/api/chats/${sessionId}/generate`, // Added url (adjust if needed)
				redirected: false, // Added redirected
				clone: function() { return this; }, // Basic clone needs to be a function
				// Add arrayBuffer, blob, formData if they were ever needed, but likely not for this mock
				arrayBuffer: async () => new ArrayBuffer(0),
				blob: async () => new Blob(),
				formData: async () => new FormData(),
				bodyUsed: false, // Added bodyUsed
				bytes: async () => new Uint8Array(), // Added bytes
			} as Response; // Cast to Response after adding required fields
			vi.mocked(fetch).mockResolvedValueOnce(mockResponse);
		};

		it('should call POST /api/chats/{id}/generate with correct parameters', async () => {
			mockFetchStream([]); // Mock an empty stream for this check
			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(fetch).toHaveBeenCalledWith(`/api/chats/${sessionId}/generate`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream',
				},
				body: JSON.stringify({ message: userMessageContent }),
				credentials: 'include',
			});
		});

		it('should call onChunk for each content message', async () => {
			const messageId = 'ai-msg-1';
			mockFetchStream([
				`data: ${JSON.stringify({ type: 'content', data: 'Why ', message_id: messageId })}`,
				`data: ${JSON.stringify({ type: 'content', data: 'did the ', message_id: messageId })}`,
				`data: ${JSON.stringify({ type: 'content', data: 'chicken?', message_id: messageId })}`,
				`data: ${JSON.stringify({ type: 'end', message_id: messageId })}` // Ensure stream ends
			]);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onChunkMock).toHaveBeenCalledTimes(3);
			expect(onChunkMock).toHaveBeenNthCalledWith(1, 'Why ', messageId);
			expect(onChunkMock).toHaveBeenNthCalledWith(2, 'did the ', messageId);
			expect(onChunkMock).toHaveBeenNthCalledWith(3, 'chicken?', messageId);
			expect(onErrorMock).not.toHaveBeenCalled();
			expect(onCompleteMock).toHaveBeenCalledWith(messageId);
		});

		 it('should call onComplete when the stream finishes successfully', async () => {
			const messageId = 'ai-msg-2';
			mockFetchStream([
				`data: ${JSON.stringify({ type: 'content', data: 'Chunk 1', message_id: messageId })}`,
				// `data: ${JSON.stringify({ type: 'end', message_id: messageId })}` // End event is optional, completion happens when stream closes
			]);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onCompleteMock).toHaveBeenCalledTimes(1);
			expect(onCompleteMock).toHaveBeenCalledWith(messageId);
			expect(onErrorMock).not.toHaveBeenCalled();
		});

		it('should call onError if the fetch request fails', async () => {
			vi.mocked(fetch).mockRejectedValueOnce(new Error('Network Error'));

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onErrorMock).toHaveBeenCalledTimes(1);
			expect(onErrorMock).toHaveBeenCalledWith(expect.any(Error));
			expect(onErrorMock.mock.calls[0][0].message).toContain('Network Error');
			expect(onChunkMock).not.toHaveBeenCalled();
			expect(onCompleteMock).not.toHaveBeenCalled();
		});

		 it('should call onError if the fetch response is not ok', async () => {
			// Use the helper to mock the non-ok response
			mockFetchStream(
				[`data: ${JSON.stringify({ message: "Backend Error Detail" })}`], // Stream content doesn't matter much here, but provide something
				500,
				false,
				'Server Error'
			);
			// Override the json method specifically for this non-ok case if needed,
			// but the implementation tries json() on the original response object.
			// Let's refine the mockFetchStream or the apiClient error handling if this becomes an issue.
			// For now, assume the implementation handles the stream correctly even on error status before trying json().
			// The apiClient code actually tries response.json() *before* processing the stream if !response.ok
			// So, we need to mock the fetch response slightly differently for this specific test case.
			vi.mocked(fetch).mockReset(); // Clear previous mock setup by mockFetchStream
			vi.mocked(fetch).mockResolvedValueOnce({
				ok: false,
				status: 500,
				statusText: 'Server Error',
				// Provide a json method that returns the error detail
				json: async () => ({ message: 'Backend Error Detail' }),
				// Body might be null or an empty stream in a real error case
				body: null, // Or createMockStream([])
				headers: new Headers(),
				type: 'basic',
				url: `/api/chats/${sessionId}/generate`,
				redirected: false,
				clone: function() { return this; }, // Basic clone
				arrayBuffer: async () => new ArrayBuffer(0),
				blob: async () => new Blob(),
				formData: async () => new FormData(),
			} as Response);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onErrorMock).toHaveBeenCalledTimes(1);
			expect(onErrorMock).toHaveBeenCalledWith(expect.any(Error));
			// Check if it includes the specific message from the backend
			expect(onErrorMock.mock.calls[0][0].message).toContain('Backend Error Detail');
			expect(onChunkMock).not.toHaveBeenCalled();
			expect(onCompleteMock).not.toHaveBeenCalled();
		});

		it('should call onError if the response body is null', async () => {
			vi.mocked(fetch).mockResolvedValueOnce({
				ok: true,
				status: 200,
				body: null, // Simulate null body
			} as Response);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onErrorMock).toHaveBeenCalledTimes(1);
			expect(onErrorMock).toHaveBeenCalledWith(new Error('Response body is null'));
			expect(onChunkMock).not.toHaveBeenCalled();
			expect(onCompleteMock).not.toHaveBeenCalled();
		});


		it('should call onError for SSE "error" type messages and stop processing', async () => {
			const messageId = 'ai-msg-err';
			mockFetchStream([
				`data: ${JSON.stringify({ type: 'content', data: 'Starting...', message_id: messageId })}`,
				`data: ${JSON.stringify({ type: 'error', message: 'Something went wrong', message_id: messageId })}`,
				`data: ${JSON.stringify({ type: 'content', data: 'This should not be processed', message_id: messageId })}` // Should not be processed
			]);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onChunkMock).toHaveBeenCalledTimes(1); // Called only for the first content chunk
			expect(onChunkMock).toHaveBeenCalledWith('Starting...', messageId);
			expect(onErrorMock).toHaveBeenCalledTimes(1);
			expect(onErrorMock).toHaveBeenCalledWith(new Error('Something went wrong'));
			expect(onCompleteMock).not.toHaveBeenCalled(); // Should not complete on error
		});

		 it('should call onError if SSE data parsing fails and stop processing', async () => {
			mockFetchStream([
				`data: ${JSON.stringify({ type: 'content', data: 'Valid JSON', message_id: 'ai-msg-parse-1' })}`,
				`data: {invalid json`, // Malformed JSON
				`data: ${JSON.stringify({ type: 'content', data: 'More valid data', message_id: 'ai-msg-parse-2' })}` // Should not be processed
			]);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onChunkMock).toHaveBeenCalledTimes(1); // Called only for the first valid chunk
			expect(onChunkMock).toHaveBeenCalledWith('Valid JSON', 'ai-msg-parse-1');
			expect(onErrorMock).toHaveBeenCalledTimes(1);
			expect(onErrorMock).toHaveBeenCalledWith(new Error('Failed to parse AI response stream.'));
			expect(onCompleteMock).not.toHaveBeenCalled();
		});

		it('should handle empty stream correctly', async () => {
			mockFetchStream([]); // Empty stream

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onChunkMock).not.toHaveBeenCalled();
			expect(onErrorMock).not.toHaveBeenCalled();
			// Should complete even if empty, but without a messageId if none was received
			expect(onCompleteMock).toHaveBeenCalledTimes(1);
			expect(onCompleteMock).toHaveBeenCalledWith(null); // Correctly expect null when no message_id is received
		});

		it('should handle stream ending without a final newline correctly', async () => {
			const messageId = 'ai-msg-partial';
			// Simulate stream ending mid-message (no final \n\n) - TextDecoderStream handles this
			// Removed unused stream variable declaration

			// Use the helper to mock the stream response
			mockFetchStream([
				`data: ${JSON.stringify({ type: 'content', data: 'Partial', message_id: messageId })}\n\n`,
				`data: ${JSON.stringify({ type: 'content', data: 'End', message_id: messageId })}` // No final \n\n needed here for the mock helper
			]);

			await generateChatResponse(sessionId, userMessageContent, onChunkMock, onErrorMock, onCompleteMock);

			expect(onChunkMock).toHaveBeenCalledTimes(2);
			expect(onChunkMock).toHaveBeenNthCalledWith(1, 'Partial', messageId);
			expect(onChunkMock).toHaveBeenNthCalledWith(2, 'End', messageId); // The parser handles the last line on stream close
			expect(onErrorMock).not.toHaveBeenCalled();
			expect(onCompleteMock).toHaveBeenCalledWith(messageId);
		});

		// Note: Tests for direct store manipulation are removed as generateChatResponse
		// now uses callbacks. The caller (e.g., chatStore actions) is responsible
		// for updating the store based on these callbacks. Store interactions should
		// be tested in chatStore.spec.ts.
	});
});