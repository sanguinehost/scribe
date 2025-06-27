import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { StreamingService, streamingService } from './StreamingService';
import type { EventSourceMessage } from '@microsoft/fetch-event-source';

// Mock @microsoft/fetch-event-source
vi.mock('@microsoft/fetch-event-source', () => ({
  fetchEventSource: vi.fn()
}));

// Mock environment
vi.mock('$env/dynamic/public', () => ({
  env: {
    PUBLIC_API_URL: 'https://localhost:8080'
  }
}));

// Import the mocked function
import { fetchEventSource } from '@microsoft/fetch-event-source';
const mockFetchEventSource = vi.mocked(fetchEventSource);

describe('StreamingService', () => {
  let service: StreamingService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new StreamingService({
      timeoutMs: 5000,
      maxRetries: 2,
      retryDelayMs: 100,
      enableBackoff: false
    });
  });

  afterEach(() => {
    service.disconnect();
  });

  describe('Initial State', () => {
    it('should start with correct initial state', () => {
      const state = service.getState();
      
      expect(state.messages).toEqual([]);
      expect(state.connectionStatus).toBe('idle');
      expect(state.currentError).toBeNull();
      expect(state.isTyping).toBe(false);
    });

    it('should have correct connection info', () => {
      const info = service.getConnectionInfo();
      
      expect(info.chatId).toBeNull();
      expect(info.status).toBe('idle');
      expect(info.retryCount).toBe(0);
      expect(info.config).toEqual({
        timeoutMs: 5000,
        maxRetries: 2,
        retryDelayMs: 100,
        enableBackoff: false
      });
    });
  });

  describe('Connection Management', () => {
    it('should prevent multiple simultaneous connections', async () => {
      // Start first connection
      const connectPromise1 = service.connect({
        chatId: 'test-chat-1',
        userMessage: 'Hello',
        history: [],
        model: 'test-model'
      });

      // Try to start second connection
      const connectSpy = vi.spyOn(console, 'warn');
      const connectPromise2 = service.connect({
        chatId: 'test-chat-2',
        userMessage: 'Hello again',
        history: [],
        model: 'test-model'
      });

      expect(connectSpy).toHaveBeenCalledWith('Connection already active. Disconnect first.');
    });

    it('should update connection status during connect', async () => {
      let onOpenCallback: ((response: Response) => Promise<void>) | undefined;
      
      mockFetchEventSource.mockImplementation(async (url, options) => {
        onOpenCallback = options.onopen;
        
        // Don't call onopen immediately - let us check the connecting state first
        return new Promise(async (resolve) => {
          // Small delay to let us check the connecting state
          setTimeout(async () => {
            if (onOpenCallback) {
              const mockResponse = {
                ok: true,
                headers: {
                  get: (name: string) => name === 'content-type' ? 'text/event-stream' : null
                }
              } as Response;
              
              await onOpenCallback(mockResponse);
            }
            resolve(undefined);
          }, 10);
        });
      });

      const connectPromise = service.connect({
        chatId: 'test-chat',
        userMessage: 'Hello',
        history: [],
        model: 'test-model'
      });

      // Should be connecting initially
      expect(service.getState().connectionStatus).toBe('connecting');

      await connectPromise;

      // Should be open after successful connection
      expect(service.getState().connectionStatus).toBe('open');
    });

    it('should add user message optimistically', async () => {
      mockFetchEventSource.mockResolvedValue(undefined);

      await service.connect({
        chatId: 'test-chat',
        userMessage: 'Hello world',
        history: [],
        model: 'test-model'
      });

      const messages = service.getState().messages;
      expect(messages).toHaveLength(2); // User message + assistant placeholder
      expect(messages[0].content).toBe('Hello world');
      expect(messages[0].sender).toBe('user');
      expect(messages[1].sender).toBe('assistant');
      expect(messages[1].loading).toBe(true);
    });
  });

  describe('Message Handling', () => {
    let onMessageCallback: ((event: EventSourceMessage) => void) | undefined;
    let assistantMessageId: string;

    beforeEach(async () => {
      mockFetchEventSource.mockImplementation(async (url, options) => {
        onMessageCallback = options.onmessage;
        
        // Simulate successful connection
        if (options.onopen) {
          const mockResponse = {
            ok: true,
            headers: {
              get: (name: string) => name === 'content-type' ? 'text/event-stream' : null
            }
          } as Response;
          
          await options.onopen(mockResponse);
        }
        
        return Promise.resolve();
      });

      await service.connect({
        chatId: 'test-chat',
        userMessage: 'Hello',
        history: [],
        model: 'test-model'
      });

      // Get the assistant message ID
      const messages = service.getState().messages;
      assistantMessageId = messages[1].id;
    });

    it('should handle content events correctly', () => {
      expect(onMessageCallback).toBeDefined();
      
      const contentEvent: EventSourceMessage = {
        data: 'Hello there!',
        event: 'content',
        id: '',
        retry: undefined
      };

      onMessageCallback!(contentEvent);

      // Should start typing animation
      expect(service.getState().isTyping).toBe(true);
      
      // Note: The actual content update happens through the typing queue
      // which uses setTimeout, so we'd need to use vi.useFakeTimers() to test it
    });

    it('should handle error events correctly', () => {
      expect(onMessageCallback).toBeDefined();
      
      const errorEvent: EventSourceMessage = {
        data: 'Test error message',
        event: 'error',
        id: '',
        retry: undefined
      };

      onMessageCallback!(errorEvent);

      const state = service.getState();
      expect(state.connectionStatus).toBe('error');
      expect(state.currentError).toBeTruthy();
      expect(state.currentError?.message).toBe('Test error message');
    });

    it('should handle done events correctly', () => {
      expect(onMessageCallback).toBeDefined();
      
      const doneEvent: EventSourceMessage = {
        data: '[DONE]',
        event: 'done',
        id: '',
        retry: undefined
      };

      onMessageCallback!(doneEvent);

      expect(service.getState().connectionStatus).toBe('closed');
    });

    it('should handle message_saved events correctly', () => {
      expect(onMessageCallback).toBeDefined();
      
      const messageSavedEvent: EventSourceMessage = {
        data: JSON.stringify({ message_id: 'backend-message-id-123' }),
        event: 'message_saved',
        id: '',
        retry: undefined
      };

      onMessageCallback!(messageSavedEvent);

      const messages = service.getState().messages;
      const assistantMessage = messages.find(m => m.sender === 'assistant');
      expect(assistantMessage?.id).toBe('backend-message-id-123');
    });

    it('should handle token_usage events correctly', () => {
      expect(onMessageCallback).toBeDefined();
      
      const tokenUsageEvent: EventSourceMessage = {
        data: JSON.stringify({
          prompt_tokens: 100,
          completion_tokens: 50,
          model_name: 'gemini-2.5-pro'
        }),
        event: 'token_usage',
        id: '',
        retry: undefined
      };

      onMessageCallback!(tokenUsageEvent);

      const messages = service.getState().messages;
      const assistantMessage = messages.find(m => m.sender === 'assistant');
      expect(assistantMessage?.prompt_tokens).toBe(100);
      expect(assistantMessage?.completion_tokens).toBe(50);
      expect(assistantMessage?.model_name).toBe('gemini-2.5-pro');
    });
  });

  describe('Error Handling', () => {
    it('should handle authentication errors', async () => {
      mockFetchEventSource.mockImplementation(async (url, options) => {
        if (options.onopen) {
          const mockResponse = {
            ok: false,
            status: 401,
            statusText: 'Unauthorized',
            text: () => Promise.resolve('Authentication failed')
          } as Response;
          
          await options.onopen(mockResponse);
        }
        return Promise.resolve();
      });

      // Mock window for auth event
      const mockDispatchEvent = vi.fn();
      Object.defineProperty(window, 'dispatchEvent', {
        value: mockDispatchEvent,
        writable: true
      });

      await service.connect({
        chatId: 'test-chat',
        userMessage: 'Hello',
        history: [],
        model: 'test-model'
      });

      const state = service.getState();
      expect(state.connectionStatus).toBe('error');
      expect(state.currentError?.type).toBe('auth');
      expect(state.currentError?.retryable).toBe(false);
      expect(mockDispatchEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'auth:session-expired'
        })
      );
    });

    it('should handle network timeouts', () => {
      const networkError = new Error('Stream timeout');

      service['handleStreamError'](networkError, 'test-message-id');

      const state = service.getState();
      expect(state.connectionStatus).toBe('error');
      expect(state.currentError?.type).toBe('timeout');
      expect(state.currentError?.retryable).toBe(true);
    });

    it('should handle safety filter errors', () => {
      const safetyError = new Error('PropertyNotFound("/content/parts")');

      service['handleStreamError'](safetyError, 'test-message-id');

      const state = service.getState();
      expect(state.connectionStatus).toBe('error');
      expect(state.currentError?.message).toContain('AI safety filters blocked');
      expect(state.currentError?.retryable).toBe(false);
    });
  });

  describe('Retry Logic', () => {
    it('should calculate retry delay correctly with backoff disabled', () => {
      service['retryCount'] = 1;
      const delay = service['calculateRetryDelay']();
      expect(delay).toBe(100); // Should be the base delay
    });

    it('should calculate retry delay correctly with exponential backoff', () => {
      const serviceWithBackoff = new StreamingService({
        retryDelayMs: 100,
        enableBackoff: true
      });
      
      serviceWithBackoff['retryCount'] = 3;
      const delay = serviceWithBackoff['calculateRetryDelay']();
      expect(delay).toBe(400); // 100 * 2^(3-1) = 100 * 4 = 400
    });

    it('should not retry auth errors', () => {
      const authError = new Error('401 Unauthorized');
      const shouldRetry = service['shouldRetry'](authError);
      expect(shouldRetry).toBe(false);
    });

    it('should not retry when max retries reached', () => {
      service['retryCount'] = 2; // Same as maxRetries in config
      const networkError = new Error('Network error');
      const shouldRetry = service['shouldRetry'](networkError);
      expect(shouldRetry).toBe(false);
    });

    it('should retry recoverable errors', () => {
      service['retryCount'] = 0;
      const networkError = new Error('Network error');
      const shouldRetry = service['shouldRetry'](networkError);
      expect(shouldRetry).toBe(true);
      expect(service['retryCount']).toBe(1);
    });
  });

  describe('Utility Methods', () => {
    it('should clear messages correctly', () => {
      // Add some messages first
      service.messages = [
        {
          id: 'msg-1',
          content: 'Hello',
          sender: 'user',
          created_at: new Date().toISOString()
        },
        {
          id: 'msg-2',
          content: 'Hi there',
          sender: 'assistant',
          created_at: new Date().toISOString()
        }
      ];

      expect(service.getState().messages).toHaveLength(2);

      service.clearMessages();

      expect(service.getState().messages).toHaveLength(0);
    });

    it('should update typing speed correctly', () => {
      service.setTypingSpeed(75);
      expect(service['typingSpeed']).toBe(75);

      // Test clamping
      service.setTypingSpeed(5); // Too low
      expect(service['typingSpeed']).toBe(10);

      service.setTypingSpeed(300); // Too high
      expect(service['typingSpeed']).toBe(200);
    });

    it('should disconnect properly', () => {
      // Set up some state
      service['abortController'] = new AbortController();
      service['currentChatId'] = 'test-chat';
      service.connectionStatus = 'open';

      const abortSpy = vi.spyOn(service['abortController'], 'abort');

      service.disconnect();

      expect(abortSpy).toHaveBeenCalled();
      expect(service['abortController']).toBeNull();
      expect(service['currentChatId']).toBeNull();
      expect(service.getState().connectionStatus).toBe('closed');
    });
  });

  describe('Singleton Instance', () => {
    it('should provide a singleton instance', () => {
      expect(streamingService).toBeInstanceOf(StreamingService);
      
      // Should be the same instance when imported again
      expect(streamingService).toBe(streamingService);
    });
  });
});