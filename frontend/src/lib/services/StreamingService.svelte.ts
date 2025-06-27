// StreamingService.ts - Decoupled Svelte 5 Streaming Client with Robust Error Handling
import { fetchEventSource, type EventSourceMessage } from '@microsoft/fetch-event-source';
import { env } from '$env/dynamic/public';
import type { ScribeChatMessage, ScribeChatSession } from '$lib/types';

// StreamingService loaded successfully

// Structured chunk format matching backend
interface StreamedChunk {
  index: number;
  content: string;
  checksum: number;
}

// Define the shape of our streaming messages
export interface StreamingMessage {
  id: string;
  content: string;
  sender: 'user' | 'assistant';
  created_at: string;
  loading?: boolean;
  error?: string;
  retryable?: boolean;
  prompt_tokens?: number;
  completion_tokens?: number;
  model_name?: string;
  backend_id?: string; // For mapping back to ScribeChatMessage
}

// Connection states following the architectural design
export type ConnectionStatus = 'idle' | 'connecting' | 'open' | 'error' | 'closed';

// Error types for sophisticated error handling
export interface StreamingError {
  message: string;
  type: 'network' | 'parse' | 'server' | 'auth' | 'timeout';
  retryable: boolean;
  originalError?: Error;
}

// Streaming configuration options
export interface StreamingConfig {
  timeoutMs: number;
  maxRetries: number;
  retryDelayMs: number;
  enableBackoff: boolean;
}

const DEFAULT_CONFIG: StreamingConfig = {
  timeoutMs: 60000, // 60 seconds
  maxRetries: 3,
  retryDelayMs: 1000,
  enableBackoff: true
};

/**
 * StreamingService - A robust, decoupled streaming service using Svelte 5 runes
 */
class StreamingService {
  // Reactive state variables using $state rune
  public messages = $state<StreamingMessage[]>([]);
  public connectionStatus = $state<ConnectionStatus>('idle');
  public currentError = $state<StreamingError | null>(null);
  public isTyping = $state(false);
  
  // Private state for connection management
  private abortController: AbortController | null = null;
  private retryCount = 0;
  private config: StreamingConfig;
  private currentChatId: string | null = null;
  
  // Track the current assistant message ID (may change when backend saves)
  private currentAssistantMessageId: string | null = null;
  
  // Typing effect state
  private typingQueues = new Map<string, string[]>();
  private typingIntervals = new Map<string, NodeJS.Timeout>();
  private typingSpeed = 50; // ms between characters
  
  // Chunk buffering for reliable streaming
  private chunkBuffers = new Map<string, { [index: number]: string }>();
  private expectedChunkIndex = new Map<string, number>();

  constructor(config: Partial<StreamingConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Simple CRC32 calculation for chunk verification
   * Note: This should match the rust crc32fast implementation
   */
  private calculateChecksum(content: string): number {
    // Simple implementation - in production, use a proper CRC32 library
    let crc = 0xFFFFFFFF;
    const bytes = new TextEncoder().encode(content);
    
    for (let i = 0; i < bytes.length; i++) {
      crc ^= bytes[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc & 1) ? (crc >>> 1) ^ 0xEDB88320 : crc >>> 1;
      }
    }
    
    return (crc ^ 0xFFFFFFFF) >>> 0; // Convert to unsigned 32-bit
  }

  /**
   * Process chunk buffer to ensure ordered delivery
   */
  private processChunkBuffer(messageId: string): void {
    const buffer = this.chunkBuffers.get(messageId);
    let nextIndex = this.expectedChunkIndex.get(messageId) ?? 0;
    
    // Process all contiguous chunks from the buffer
    while (buffer && buffer[nextIndex] !== undefined) {
      const content = buffer[nextIndex];
      this.addToTypingQueue(messageId, content);
      delete buffer[nextIndex];
      nextIndex++;
    }
    
    // Update the index for the next expected chunk
    this.expectedChunkIndex.set(messageId, nextIndex);
  }

  /**
   * Get the current reactive state - used by components
   */
  public getState() {
    return {
      messages: this.messages,
      connectionStatus: this.connectionStatus,
      currentError: this.currentError,
      isTyping: this.isTyping
    };
  }

  /**
   * Connect and start streaming with sophisticated error handling
   */
  public async connect(params: {
    chatId: string;
    userMessage: string;
    history: Array<{ role: 'user' | 'assistant'; content: string }>;
    model?: string;
  }): Promise<void> {
    // Connect to streaming service
    
    if (this.connectionStatus === 'connecting' || this.connectionStatus === 'open') {
      console.warn('Connection already active. Disconnect first.');
      return;
    }

    this.currentChatId = params.chatId;
    this.abortController = new AbortController();
    this.retryCount = 0;
    this.connectionStatus = 'connecting';
    this.currentError = null;

    // Add user message optimistically
    const userMessage: StreamingMessage = {
      id: crypto.randomUUID(),
      content: params.userMessage,
      sender: 'user',
      created_at: new Date().toISOString()
    };
    this.messages = [...this.messages, userMessage];

    // Add placeholder assistant message
    const assistantMessage: StreamingMessage = {
      id: crypto.randomUUID(),
      content: '',
      sender: 'assistant',
      created_at: new Date().toISOString(),
      loading: true
    };
    this.messages = [...this.messages, assistantMessage];
    
    // Track the current assistant message ID
    this.currentAssistantMessageId = assistantMessage.id;

    try {
      await this.startEventStream(params, assistantMessage.id);
    } catch (error) {
      this.handleConnectionError(error as Error);
    }
  }

  /**
   * Start the event stream using @microsoft/fetch-event-source
   */
  private async startEventStream(
    params: {
      chatId: string;
      userMessage: string;
      history: Array<{ role: 'user' | 'assistant'; content: string }>;
      model?: string;
    },
    assistantMessageId: string
  ): Promise<void> {
    const baseUrl = (env.PUBLIC_API_URL || '').trim();
    const apiUrl = `${baseUrl}/api/chat/${params.chatId}/generate`;

    const requestBody = {
      history: [...params.history, { role: 'user' as const, content: params.userMessage }],
      model: params.model
    };

    console.log('🚀 Starting fetchEventSource with URL:', apiUrl);

    await fetchEventSource(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream'
      },
      credentials: 'include',
      body: JSON.stringify(requestBody),
      signal: this.abortController?.signal,

      onopen: async (response) => {
        console.log('🔓 fetchEventSource onopen called', { status: response.status, contentType: response.headers.get('content-type') });
        if (response.ok && response.headers.get('content-type')?.includes('text/event-stream')) {
          this.connectionStatus = 'open';
          this.retryCount = 0; // Reset retry count on successful connection
          console.log('✓ Stream connection established');
        } else if (response.status === 401) {
          this.handleAuthError();
          throw new Error('Authentication failed');
        } else {
          const errorText = await response.text().catch(() => 'Unknown error');
          throw new Error(`Connection failed: ${response.status} ${response.statusText} - ${errorText}`);
        }
      },

      onmessage: (event: EventSourceMessage) => {
        this.handleStreamMessage(event, assistantMessageId);
      },

      onclose: () => {
        console.log('🔒 fetchEventSource onclose called');
        // Stream closed cleanly by server
        if (this.connectionStatus !== 'closed' && this.connectionStatus !== 'error') {
          console.log('Stream closed by server');
          const messageIdToFinalize = this.currentAssistantMessageId || assistantMessageId;
          console.log('🔒 Finalizing message on close with ID:', messageIdToFinalize);
          this.finalizeMessage(messageIdToFinalize);
          this.connectionStatus = 'closed';
        }
      },

      onerror: (error) => {
        console.error('❌ fetchEventSource onerror called:', error);
        
        // Determine if we should retry
        if (this.shouldRetry(error)) {
          const delay = this.calculateRetryDelay();
          console.log(`Retrying in ${delay}ms (attempt ${this.retryCount + 1}/${this.config.maxRetries})`);
          return delay; // Return delay to trigger retry
        } else {
          // Don't retry - let the error bubble up
          this.handleStreamError(error, assistantMessageId);
          throw error;
        }
      }
    });
  }

  /**
   * Handle incoming stream messages with sophisticated parsing
   */
  private handleStreamMessage(event: EventSourceMessage, assistantMessageId: string): void {
    try {
      switch (event.event) {
        case 'content':
          if (event.data) {
            try {
              // Parse structured chunk
              const chunk: StreamedChunk = JSON.parse(event.data);
              const { index, content, checksum } = chunk;

              // Verify checksum
              const calculatedChecksum = this.calculateChecksum(content);
              if (calculatedChecksum !== checksum) {
                console.error(`🔍 Checksum mismatch for chunk ${index}. Expected: ${checksum}, Got: ${calculatedChecksum}`);
                // For now, we'll still process the chunk but log the error
                // Future enhancement: Implement retry request mechanism
              }

              // Use the tracked message ID for chunk buffering
              const messageIdForChunks = this.currentAssistantMessageId || assistantMessageId;

              // Initialize buffer and expected index if they don't exist
              if (!this.chunkBuffers.has(messageIdForChunks)) {
                this.chunkBuffers.set(messageIdForChunks, {});
                this.expectedChunkIndex.set(messageIdForChunks, 0);
              }

              // Store chunk in the buffer
              const buffer = this.chunkBuffers.get(messageIdForChunks)!;
              buffer[index] = content;

              console.log(`📦 Received chunk ${index} for message ${messageIdForChunks}, content length: ${content.length}`);

              // Process the buffer to render chunks in the correct order
              this.processChunkBuffer(messageIdForChunks);

            } catch (e) {
              console.error("Failed to parse structured chunk, falling back to raw content:", e);
              // Fallback to old behavior if structured parsing fails
              const messageIdForTyping = this.currentAssistantMessageId || assistantMessageId;
              this.addToTypingQueue(messageIdForTyping, event.data);
            }
          }
          break;

        case 'error':
          this.handleStreamError(new Error(event.data), assistantMessageId);
          break;

        case 'done':
          if (event.data === '[DONE]') {
            // Use the current tracked message ID (which may have been updated by message_saved)
            const messageIdToFinalize = this.currentAssistantMessageId || assistantMessageId;
            this.finalizeMessage(messageIdToFinalize);
            this.connectionStatus = 'closed';
          }
          break;

        case 'message_saved':
          this.handleMessageSaved(event.data, assistantMessageId);
          break;

        case 'token_usage':
          console.log('📊 Processing token_usage event:', event.data);
          // Use the tracked message ID for token usage
          const messageIdForTokens = this.currentAssistantMessageId || assistantMessageId;
          this.handleTokenUsage(event.data, messageIdForTokens);
          break;

        case 'reasoning_chunk':
          // Handle reasoning chunks if needed
          console.log('Reasoning:', event.data);
          break;

        default:
          // Handle default message event or unknown events
          console.log('📤 Processing default/unknown event:', event.event);
          if (event.data && event.data !== '[DONE]') {
            // Use the tracked message ID for typing queue (may have been updated by message_saved)
            const messageIdForTyping = this.currentAssistantMessageId || assistantMessageId;
            this.addToTypingQueue(messageIdForTyping, event.data);
          }
          break;
      }
    } catch (error) {
      console.error('Error parsing stream message:', error);
      this.handleStreamError(error as Error, assistantMessageId);
    }
  }

  /**
   * Add content to typing queue for smooth animation
   */
  private addToTypingQueue(messageId: string, content: string): void {
    if (!this.typingQueues.has(messageId)) {
      this.typingQueues.set(messageId, []);
    }
    
    this.typingQueues.get(messageId)!.push(content);
    this.isTyping = true;
    
    // Start typing animation if not already running
    if (!this.typingIntervals.has(messageId)) {
      this.startTypingAnimation(messageId);
    }
  }

  /**
   * Start smooth typing animation
   */
  private startTypingAnimation(messageId: string): void {
    const interval = setInterval(() => {
      const queue = this.typingQueues.get(messageId);
      if (!queue || queue.length === 0) {
        clearInterval(interval);
        this.typingIntervals.delete(messageId);
        this.isTyping = this.typingIntervals.size > 0;
        return;
      }

      const nextChunk = queue.shift()!;
      
      // Update message content
      this.messages = this.messages.map((msg) => {
        if (msg.id === messageId) {
          const updated = { ...msg, content: msg.content + nextChunk };
          // Update message content
          return updated;
        }
        return msg;
      });
    }, this.typingSpeed);

    this.typingIntervals.set(messageId, interval);
  }

  /**
   * Handle message saved event
   */
  private handleMessageSaved(data: string, assistantMessageId: string): void {
    try {
      const messageData = JSON.parse(data);
      const actualMessageId = messageData.message_id;
      
      console.log(`💾 handleMessageSaved: Updating message ID from ${assistantMessageId} to ${actualMessageId}`);
      
      // Update message with backend ID
      this.messages = this.messages.map((msg) => {
        if (msg.id === assistantMessageId) {
          console.log(`💾 Found message to update:`, { oldId: msg.id, newId: actualMessageId });
          return { ...msg, id: actualMessageId };
        }
        return msg;
      });
      
      // Update the tracked assistant message ID so finalizeMessage can find it
      this.currentAssistantMessageId = actualMessageId;
      console.log(`💾 Updated currentAssistantMessageId to: ${actualMessageId}`);
    } catch (error) {
      console.error('Failed to parse message saved data:', error);
    }
  }

  /**
   * Handle token usage information
   */
  private handleTokenUsage(data: string, assistantMessageId: string): void {
    try {
      const tokenData = JSON.parse(data);
      
      this.messages = this.messages.map((msg) => {
        if (msg.id === assistantMessageId) {
          return {
            ...msg,
            prompt_tokens: tokenData.prompt_tokens,
            completion_tokens: tokenData.completion_tokens,
            model_name: tokenData.model_name
          };
        }
        return msg;
      });
    } catch (error) {
      console.error('Failed to parse token usage data:', error);
    }
  }

  /**
   * Finalize message when streaming is complete
   */
  private finalizeMessage(assistantMessageId: string): void {
    console.log(`🏁 ENTERING finalizeMessage with ID: ${assistantMessageId}`);
    
    // Check if message exists
    const messageExists = this.messages.find(m => m.id === assistantMessageId);
    console.log(`🏁 Message exists:`, !!messageExists, messageExists ? `loading: ${messageExists.loading}` : 'NOT FOUND');
    
    // Check if there are remaining content chunks in typing queue
    const remainingQueue = this.typingQueues.get(assistantMessageId);
    if (remainingQueue && remainingQueue.length > 0) {
      console.log(`⚠️ Finalizing with ${remainingQueue.length} chunks still in typing queue:`, remainingQueue);
      
      // Process remaining chunks immediately to avoid truncation
      const remainingContent = remainingQueue.join('');
      if (remainingContent) {
        console.log(`📝 Adding remaining content immediately: "${remainingContent.slice(-50)}"`);
        this.messages = this.messages.map((msg) => {
          if (msg.id === assistantMessageId) {
            return { ...msg, content: msg.content + remainingContent };
          }
          return msg;
        });
      }
    }
    
    // Clear any remaining typing queues and chunk buffers
    this.clearTyping(assistantMessageId);
    this.clearChunkBuffer(assistantMessageId);
    
    // Mark message as no longer loading
    let messageUpdated = false;
    this.messages = this.messages.map((msg) => {
      if (msg.id === assistantMessageId) {
        messageUpdated = true;
        console.log(`🏁 Updating message loading from ${msg.loading} to false`);
        return { ...msg, loading: false };
      }
      return msg;
    });
    
    console.log(`🏁 Message updated: ${messageUpdated}`);
    console.log(`🏁 EXITING finalizeMessage`);
  }

  /**
   * Clear typing animation for a specific message
   */
  private clearTyping(messageId: string): void {
    const interval = this.typingIntervals.get(messageId);
    if (interval) {
      clearInterval(interval);
      this.typingIntervals.delete(messageId);
    }
    this.typingQueues.delete(messageId);
    this.isTyping = this.typingIntervals.size > 0;
  }

  /**
   * Clear chunk buffer for a specific message
   */
  private clearChunkBuffer(messageId: string): void {
    this.chunkBuffers.delete(messageId);
    this.expectedChunkIndex.delete(messageId);
  }

  /**
   * Handle authentication errors
   */
  private handleAuthError(): void {
    this.currentError = {
      message: 'Session expired. Please sign in again.',
      type: 'auth',
      retryable: false
    };
    this.connectionStatus = 'error';
    
    // Emit auth event for app-level handling
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:session-expired'));
    }
  }

  /**
   * Handle stream errors with sophisticated categorization
   */
  private handleStreamError(error: Error, assistantMessageId?: string): void {
    let streamingError: StreamingError;

    if (error.name === 'AbortError') {
      // User cancelled - not really an error
      return;
    } else if (error.message.includes('401') || error.message.includes('Authentication')) {
      streamingError = {
        message: 'Session expired. Please sign in again.',
        type: 'auth',
        retryable: false,
        originalError: error
      };
    } else if (error.message.includes('timeout') || error.message.includes('Stream timeout')) {
      streamingError = {
        message: 'Connection timed out. Please try again.',
        type: 'timeout',
        retryable: true,
        originalError: error
      };
    } else {
      streamingError = {
        message: error.message || 'An unexpected error occurred.',
        type: 'network',
        retryable: true,
        originalError: error
      };
    }

    this.currentError = streamingError;
    this.connectionStatus = 'error';

    // Mark assistant message as failed if provided
    if (assistantMessageId) {
      this.messages = this.messages.map((msg) => {
        if (msg.id === assistantMessageId) {
          return {
            ...msg,
            loading: false,
            error: streamingError.message,
            retryable: streamingError.retryable
          };
        }
        return msg;
      });
    }
  }

  /**
   * Handle connection-level errors
   */
  private handleConnectionError(error: Error): void {
    this.handleStreamError(error);
  }

  /**
   * Determine if we should retry based on error type and retry count
   */
  private shouldRetry(error: any): boolean {
    if (this.retryCount >= this.config.maxRetries) {
      return false;
    }

    if (error?.name === 'AbortError') {
      return false;
    }

    // Don't retry auth errors
    if (error?.message?.includes('401') || error?.message?.includes('Authentication')) {
      return false;
    }

    this.retryCount++;
    return true;
  }

  /**
   * Calculate retry delay with optional exponential backoff
   */
  private calculateRetryDelay(): number {
    if (!this.config.enableBackoff) {
      return this.config.retryDelayMs;
    }

    // Exponential backoff: delay * 2^(retryCount - 1)
    return this.config.retryDelayMs * Math.pow(2, this.retryCount - 1);
  }

  /**
   * Disconnect and clean up
   */
  public disconnect(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }

    // Clear all typing animations
    for (const [messageId] of this.typingIntervals) {
      this.clearTyping(messageId);
    }

    if (this.connectionStatus !== 'idle' && this.connectionStatus !== 'closed') {
      this.connectionStatus = 'closed';
    }

    this.currentChatId = null;
  }

  /**
   * Clear all messages
   */
  public clearMessages(): void {
    // Clear typing animations and chunk buffers
    for (const [messageId] of this.typingIntervals) {
      this.clearTyping(messageId);
    }
    for (const [messageId] of this.chunkBuffers.keys()) {
      this.clearChunkBuffer(messageId);
    }
    
    this.messages = [];
  }

  /**
   * Update typing speed
   */
  public setTypingSpeed(speed: number): void {
    this.typingSpeed = Math.max(10, Math.min(200, speed)); // Clamp between 10-200ms
  }

  /**
   * Get current connection info
   */
  public getConnectionInfo() {
    return {
      chatId: this.currentChatId,
      status: this.connectionStatus,
      retryCount: this.retryCount,
      config: this.config
    };
  }
}

// Export a singleton instance
export const streamingService = new StreamingService();

// StreamingService singleton ready

// Export the class for testing or multiple instances
export { StreamingService };