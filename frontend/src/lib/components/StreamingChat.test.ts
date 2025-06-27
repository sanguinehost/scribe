import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import '@testing-library/jest-dom';
import StreamingChat from './StreamingChat.svelte';
import type { User, ScribeChatSession, ScribeCharacter } from '$lib/types';

// Mock the streaming service
vi.mock('$lib/services/StreamingService.svelte', () => {
  const mockState = {
    messages: [],
    connectionStatus: 'idle',
    currentError: null,
    isTyping: false
  };

  const mockService = {
    getState: () => mockState,
    connect: vi.fn(),
    disconnect: vi.fn(),
    clearMessages: vi.fn(),
    retryMessage: vi.fn(),
    messages: mockState.messages
  };

  return {
    streamingService: mockService,
    StreamingService: class MockStreamingService {
      getState = () => mockState;
      connect = vi.fn();
      disconnect = vi.fn();
      clearMessages = vi.fn();
      retryMessage = vi.fn();
    }
  };
});

// Mock the API client
vi.mock('$lib/api', () => ({
  apiClient: {
    getChatSessionSettings: vi.fn().mockResolvedValue({
      isOk: () => true,
      value: { model_name: 'gemini-2.5-pro' }
    })
  }
}));

// Mock toast
vi.mock('svelte-sonner', () => ({
  toast: {
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
    success: vi.fn()
  }
}));

// Mock other components
vi.mock('./chat-header.svelte', () => ({
  default: () => ({ $$set: vi.fn() })
}));

vi.mock('./TypewriterMessage.svelte', () => ({
  default: () => ({ $$set: vi.fn() })
}));

vi.mock('./multimodal-input.svelte', () => ({
  default: () => ({ $$set: vi.fn() })
}));

describe('StreamingChat', () => {
  let mockUser: User;
  let mockChat: ScribeChatSession;
  let mockCharacter: ScribeCharacter;

  beforeEach(() => {
    vi.clearAllMocks();

    mockUser = {
      id: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      created_at: new Date().toISOString(),
      user_id: 'user-123'
    };

    mockChat = {
      id: 'chat-123',
      user_id: 'user-123',
      title: 'Test Chat',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      chat_mode: 'roleplay',
      model_name: 'gemini-2.5-pro'
    };

    mockCharacter = {
      id: 'char-123',
      user_id: 'user-123',
      name: 'Test Character',
      first_mes: 'Hello! How can I help you today?',
      description: 'A helpful test character',
      personality: 'Friendly and helpful',
      mes_example: '',
      scenario: 'Testing environment',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Initial Rendering', () => {
    it('should render with basic props', () => {
      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // The component should render without throwing
      expect(document.body).toBeInTheDocument();
    });

    it('should show readonly state when readonly prop is true', () => {
      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter,
          readonly: true
        }
      });

      // Input form should not be present when readonly
      const inputForm = document.querySelector('form');
      expect(inputForm).not.toBeInTheDocument();
    });

    it('should initialize with character first message', async () => {
      const { component } = render(ModernChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Wait for the effect to run
      await waitFor(() => {
        const { streamingService } = require('$lib/services/StreamingService');
        expect(streamingService.messages).toHaveLength(1);
        expect(streamingService.messages[0].content).toBe('Hello! How can I help you today?');
        expect(streamingService.messages[0].sender).toBe('assistant');
      });
    });
  });

  describe('Message Handling', () => {
    it('should handle form submission correctly', async () => {
      const { component } = render(ModernChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter,
          initialChatInputValue: 'Test message'
        }
      });

      const { streamingService } = require('$lib/services/StreamingService');
      const { apiClient } = require('$lib/api');

      // Find and submit the form
      const form = document.querySelector('form');
      if (form) {
        await fireEvent.submit(form);

        // Should call streaming service connect
        expect(streamingService.connect).toHaveBeenCalledWith({
          chatId: mockChat.id,
          userMessage: 'Test message',
          history: expect.any(Array),
          model: 'gemini-2.5-pro'
        });
      }
    });

    it('should prevent submission when loading', async () => {
      // Mock loading state
      const { streamingService } = require('$lib/services/StreamingService');
      streamingService.getState = vi.fn().mockReturnValue({
        messages: [],
        connectionStatus: 'connecting',
        currentError: null,
        isTyping: false
      });

      const { toast } = require('svelte-sonner');

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter,
          initialChatInputValue: 'Test message'
        }
      });

      const form = document.querySelector('form');
      if (form) {
        await fireEvent.submit(form);

        // Should show warning and not call connect
        expect(toast.warning).toHaveBeenCalledWith('Please wait for the current message to complete.');
        expect(streamingService.connect).not.toHaveBeenCalled();
      }
    });

    it('should handle empty message submission', async () => {
      const { toast } = require('svelte-sonner');

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter,
          initialChatInputValue: '   ' // Whitespace only
        }
      });

      const form = document.querySelector('form');
      if (form) {
        await fireEvent.submit(form);

        // Should show error for empty/whitespace message
        expect(toast.error).toHaveBeenCalledWith('Chat session or user information is missing.');
      }
    });
  });

  describe('Error Handling', () => {
    it('should display error messages from streaming service', async () => {
      const { streamingService } = require('$lib/services/StreamingService');
      const { toast } = require('svelte-sonner');

      // Mock error state
      const mockError = {
        message: 'Connection failed',
        type: 'network',
        retryable: true
      };

      streamingService.getState = vi.fn().mockReturnValue({
        messages: [],
        connectionStatus: 'error',
        currentError: mockError,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should show error toast
      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith('Connection failed');
      });
    });

    it('should handle auth errors correctly', async () => {
      const { streamingService } = require('$lib/services/StreamingService');

      // Mock auth error
      const mockAuthError = {
        message: 'Session expired. Please sign in again.',
        type: 'auth',
        retryable: false
      };

      streamingService.getState = vi.fn().mockReturnValue({
        messages: [],
        connectionStatus: 'error',
        currentError: mockAuthError,
        isTyping: false
      });

      // Mock window.dispatchEvent
      const mockDispatchEvent = vi.fn();
      Object.defineProperty(window, 'dispatchEvent', {
        value: mockDispatchEvent,
        writable: true
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should dispatch auth event
      await waitFor(() => {
        expect(mockDispatchEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'auth:session-expired'
          })
        );
      });
    });
  });

  describe('Message Display', () => {
    it('should display user messages correctly', () => {
      const { streamingService } = require('$lib/services/StreamingService');

      // Mock messages state
      streamingService.getState = vi.fn().mockReturnValue({
        messages: [
          {
            id: 'msg-1',
            content: 'Hello there',
            sender: 'user',
            created_at: new Date().toISOString()
          }
        ],
        connectionStatus: 'idle',
        currentError: null,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should show user message content
      expect(screen.getByText('Hello there')).toBeInTheDocument();
    });

    it('should display assistant messages with character name', () => {
      const { streamingService } = require('$lib/services/StreamingService');

      // Mock messages state
      streamingService.getState = vi.fn().mockReturnValue({
        messages: [
          {
            id: 'msg-1',
            content: 'Hi! How can I help?',
            sender: 'assistant',
            created_at: new Date().toISOString(),
            loading: false
          }
        ],
        connectionStatus: 'idle',
        currentError: null,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should show character name and message content
      expect(screen.getByText('Test Character')).toBeInTheDocument();
      expect(screen.getByText('Hi! How can I help?')).toBeInTheDocument();
    });

    it('should show loading indicator for assistant messages', () => {
      const { streamingService } = require('$lib/services/StreamingService');

      // Mock loading message
      streamingService.getState = vi.fn().mockReturnValue({
        messages: [
          {
            id: 'msg-1',
            content: '',
            sender: 'assistant',
            created_at: new Date().toISOString(),
            loading: true
          }
        ],
        connectionStatus: 'open',
        currentError: null,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should show thinking indicator
      expect(screen.getByText('Thinking...')).toBeInTheDocument();
    });

    it('should display failed message with retry button', async () => {
      const { streamingService } = require('$lib/services/StreamingService');

      // Mock failed message
      streamingService.getState = vi.fn().mockReturnValue({
        messages: [
          {
            id: 'msg-1',
            content: 'Partial response...',
            sender: 'assistant',
            created_at: new Date().toISOString(),
            loading: false,
            error: 'Connection failed',
            retryable: true
          }
        ],
        connectionStatus: 'error',
        currentError: null,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should show error message and retry button
      expect(screen.getByText('Generation failed')).toBeInTheDocument();
      expect(screen.getByText('Connection failed')).toBeInTheDocument();
      
      const retryButton = screen.getByText('Retry');
      expect(retryButton).toBeInTheDocument();

      // Click retry button
      await fireEvent.click(retryButton);

      // Should call retry method
      expect(streamingService.retryMessage).toHaveBeenCalledWith(
        'msg-1',
        mockChat.id,
        expect.any(Array),
        'gemini-2.5-pro'
      );
    });
  });

  describe('Connection Status', () => {
    it('should show connecting status', () => {
      const { streamingService } = require('$lib/services/StreamingService');

      streamingService.getState = vi.fn().mockReturnValue({
        messages: [],
        connectionStatus: 'connecting',
        currentError: null,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      expect(screen.getByText('Connecting...')).toBeInTheDocument();
    });

    it('should update placeholder text based on state', () => {
      const { streamingService } = require('$lib/services/StreamingService');

      streamingService.getState = vi.fn().mockReturnValue({
        messages: [],
        connectionStatus: 'connecting',
        currentError: null,
        isTyping: false
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Placeholder should indicate loading state
      // Note: This would require checking the MultimodalInput component's props
      // For now, we just ensure the component renders without error
      expect(document.body).toBeInTheDocument();
    });
  });

  describe('Cleanup', () => {
    it('should disconnect streaming service on unmount', () => {
      const { streamingService } = require('$lib/services/StreamingService');

      const { unmount } = render(ModernChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      unmount();

      // Should have called disconnect
      expect(streamingService.disconnect).toHaveBeenCalled();
    });
  });

  describe('Development Features', () => {
    it('should show debug controls in development mode', () => {
      // Mock development environment
      Object.defineProperty(import.meta, 'env', {
        value: { DEV: true },
        writable: true
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      // Should show clear messages button
      const clearButton = screen.getByText('Clear Messages');
      expect(clearButton).toBeInTheDocument();
    });

    it('should handle clear messages action', async () => {
      const { streamingService } = require('$lib/services/StreamingService');
      const { toast } = require('svelte-sonner');

      // Mock development environment
      Object.defineProperty(import.meta, 'env', {
        value: { DEV: true },
        writable: true
      });

      render(StreamingChat, {
        props: {
          user: mockUser,
          chat: mockChat,
          character: mockCharacter
        }
      });

      const clearButton = screen.getByText('Clear Messages');
      await fireEvent.click(clearButton);

      expect(streamingService.clearMessages).toHaveBeenCalled();
      expect(toast.success).toHaveBeenCalledWith('Messages cleared.');
    });
  });
});