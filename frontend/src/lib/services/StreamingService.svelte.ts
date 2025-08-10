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
  content: string; // Full content (always complete)
  displayedContent: string; // Content currently shown to user (for animation)
  sender: 'user' | 'assistant';
  created_at: string;
  isAnimating?: boolean; // Currently playing typewriter animation
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
  
  // NEW: Buffer-first architecture state
  private messageBuffers = new Map<string, {
    content: string;
    chunks: { [index: number]: string };
    expectedIndex: number;
    prompt_tokens?: number;
    completion_tokens?: number;
    model_name?: string;
    backend_id?: string;
    isComplete: boolean;
  }>();
  
  // Local animation state (ChatGPT-style)
  private animationIntervals = new Map<string, NodeJS.Timeout>();
  private animationSpeed = 15; // ms between character reveals (2x faster than before)
  
  // LEGACY: Keep old state for gradual migration
  private typingQueues = new Map<string, string[]>();
  private typingIntervals = new Map<string, NodeJS.Timeout>();
  private typingSpeed = 50; // ms between characters
  private chunkBuffers = new Map<string, { [index: number]: string }>();
  private expectedChunkIndex = new Map<string, number>();
  
  // Connection closure tracking - wait for critical events after DONE
  private connectionCloseState = {
    doneReceived: false,
    messageSavedReceived: false,
    tokenUsageReceived: false,
    closeTimeoutId: null as NodeJS.Timeout | null,
    shouldClose: false
  };

  constructor(config: Partial<StreamingConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if we should close the connection based on received events
   */
  private shouldCloseConnection(): boolean {
    const state = this.connectionCloseState;
    
    // We can close if we've received DONE and token_usage (message_saved is optional)
    // OR if we've received DONE and it's been a while (fallback timeout)
    return state.doneReceived && (
      state.tokenUsageReceived ||
      state.shouldClose
    );
  }

  /**
   * Attempt to close the connection if all conditions are met
   */
  private tryCloseConnection(): void {
    if (this.shouldCloseConnection()) {
      console.log('🔒 All events received, closing connection');
      
      // Clear any pending timeout
      if (this.connectionCloseState.closeTimeoutId) {
        clearTimeout(this.connectionCloseState.closeTimeoutId);
        this.connectionCloseState.closeTimeoutId = null;
      }
      
      // Actually close the connection
      if (this.connectionStatus !== 'closed' && this.connectionStatus !== 'error') {
        this.connectionStatus = 'closed';
      }
      
      // Abort the fetch request to close the SSE connection
      if (this.abortController) {
        this.abortController.abort();
      }
    }
  }

  /**
   * NEW ARCHITECTURE: Update buffer content from contiguous chunks
   */
  private updateBufferContent(messageId: string): void {
    const buffer = this.messageBuffers.get(messageId);
    if (!buffer) return;
    
    let content = '';
    let nextIndex = buffer.expectedIndex;
    
    // Process all contiguous chunks
    while (buffer.chunks[nextIndex] !== undefined) {
      content += buffer.chunks[nextIndex];
      delete buffer.chunks[nextIndex];
      nextIndex++;
    }
    
    if (content) {
      buffer.content += content;
      buffer.expectedIndex = nextIndex;
      console.log(`📝 Updated buffer for ${messageId.slice(-8)}: ${buffer.content.length} total chars`);
    }
  }

  /**
   * NEW ARCHITECTURE: Try to start animation if all conditions are met
   */
  private tryStartAnimation(messageId: string): void {
    const buffer = this.messageBuffers.get(messageId);
    if (!buffer || !buffer.isComplete) return;
    
    // Check if message is already animating
    const message = this.messages.find(m => m.id === messageId);
    if (message?.isAnimating) return;
    
    console.log(`🎯 Conditions met for ${messageId.slice(-8)}, starting animation`);
    this.startLocalAnimation(messageId);
  }

  /**
   * NEW ARCHITECTURE: Start local animation after buffering complete
   */
  private startLocalAnimation(messageId: string): void {
    const buffer = this.messageBuffers.get(messageId);
    if (!buffer || !buffer.isComplete) return;
    
    console.log(`🎬 Starting animation for ${messageId.slice(-8)}: ${buffer.content.length} chars`);
    
    // Update message with complete content and metadata
    this.messages = this.messages.map(msg => {
      if (msg.id === messageId) {
        return {
          ...msg,
          content: buffer.content,
          displayedContent: '', // Start animation from empty
          isAnimating: true,
          prompt_tokens: buffer.prompt_tokens,
          completion_tokens: buffer.completion_tokens,
          model_name: buffer.model_name,
          backend_id: buffer.backend_id
        };
      }
      return msg;
    });
    
    // Start character-by-character animation
    let charIndex = 0;
    const fullContent = buffer.content;
    
    const animateNextChar = () => {
      if (charIndex >= fullContent.length) {
        // Animation complete
        this.messages = this.messages.map(msg => {
          if (msg.id === messageId) {
            return { ...msg, isAnimating: false };
          }
          return msg;
        });
        
        const interval = this.animationIntervals.get(messageId);
        if (interval) {
          clearInterval(interval);
          this.animationIntervals.delete(messageId);
        }
        
        console.log(`✅ Animation complete for ${messageId.slice(-8)}`);
        return;
      }
      
      // Reveal next character
      const displayedContent = fullContent.slice(0, charIndex + 1);
      
      this.messages = this.messages.map(msg => {
        if (msg.id === messageId) {
          return { ...msg, displayedContent };
        }
        return msg;
      });
      
      charIndex++;
    };
    
    // Start the animation interval
    const intervalId = setInterval(animateNextChar, this.animationSpeed);
    this.animationIntervals.set(messageId, intervalId);
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
    const initialNextIndex = nextIndex;
    
    // Only log if there's an issue (out of order chunks)
    if (buffer && buffer[nextIndex] === undefined && Object.keys(buffer).length > 0) {
      console.log(`⏳ Waiting for chunk ${nextIndex}, buffered: [${Object.keys(buffer).sort((a, b) => parseInt(a) - parseInt(b)).join(', ')}]`);
    }
    
    // Process all contiguous chunks from the buffer
    while (buffer && buffer[nextIndex] !== undefined) {
      const content = buffer[nextIndex];
      this.addToTypingQueue(messageId, content);
      delete buffer[nextIndex];
      nextIndex++;
    }
    
    // Only log remaining buffered chunks if we have a gap
    const remainingChunks = buffer ? Object.keys(buffer).map(k => parseInt(k)).sort((a, b) => a - b) : [];
    if (remainingChunks.length > 0 && nextIndex === initialNextIndex) {
      console.log(`⏳ Gap detected: waiting for chunk ${nextIndex}, have chunks [${remainingChunks.join(', ')}]`);
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
    agentMode?: string;
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
    
    // Reset connection close state for new connection
    this.connectionCloseState = {
      doneReceived: false,
      messageSavedReceived: false,
      tokenUsageReceived: false,
      closeTimeoutId: null,
      shouldClose: false
    };

    // Add user message optimistically
    const userMessage: StreamingMessage = {
      id: crypto.randomUUID(),
      content: params.userMessage,
      displayedContent: params.userMessage, // User messages show immediately
      sender: 'user',
      created_at: new Date().toISOString()
    };
    this.messages = [...this.messages, userMessage];

    // NEW ARCHITECTURE: Create assistant message with buffer-first approach
    const assistantMessage: StreamingMessage = {
      id: crypto.randomUUID(),
      content: '', // Will be filled when buffering completes
      displayedContent: '', // Will animate from empty to full content
      sender: 'assistant',
      created_at: new Date().toISOString(),
      isAnimating: false // Will start animating after buffering
    };
    this.messages = [...this.messages, assistantMessage];
    
    // Track the current assistant message ID
    this.currentAssistantMessageId = assistantMessage.id;
    
    // Initialize buffer for this message
    this.messageBuffers.set(assistantMessage.id, {
      content: '',
      chunks: {},
      expectedIndex: 0,
      isComplete: false
    });

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
      agentMode?: string;
    },
    assistantMessageId: string
  ): Promise<void> {
    const baseUrl = (env.PUBLIC_API_URL || '').trim();
    const apiUrl = `${baseUrl}/api/chat/${params.chatId}/generate`;

    const requestBody = {
      history: [...params.history, { role: 'user' as const, content: params.userMessage }],
      model: params.model,
      agent_mode: params.agentMode
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
        // Only perform cleanup if the connection was actually closed
        // Note: This can be called when we abort the connection ourselves or when the server closes
        
        // Clear any pending close timeout
        if (this.connectionCloseState.closeTimeoutId) {
          clearTimeout(this.connectionCloseState.closeTimeoutId);
          this.connectionCloseState.closeTimeoutId = null;
        }
        
        // Mark as closed if not already
        if (this.connectionStatus !== 'closed' && this.connectionStatus !== 'error') {
          console.log('🔒 Connection closed by server or client');
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
              }

              // NEW ARCHITECTURE: Buffer chunks without immediate UI updates
              const messageId = this.currentAssistantMessageId || assistantMessageId;
              const messageBuffer = this.messageBuffers.get(messageId);
              
              if (messageBuffer) {
                // Store chunk in buffer
                messageBuffer.chunks[index] = content;
                console.log(`📦 Buffering chunk ${index} for ${messageId.slice(-8)}: ${content.length} chars`);
                
                // Check for gaps in chunks
                const expectedIdx = messageBuffer.expectedIndex;
                if (index > expectedIdx) {
                  console.log(`⚠️ Chunk gap: expected ${expectedIdx}, got ${index}`);
                }
                
                // Update buffer content if we have contiguous chunks
                this.updateBufferContent(messageId);
              } else {
                console.warn(`No buffer found for message ${messageId}`);
              }

            } catch (e) {
              console.error("Failed to parse structured chunk:", e);
              // For fallback, still buffer the raw content
              const messageId = this.currentAssistantMessageId || assistantMessageId;
              const messageBuffer = this.messageBuffers.get(messageId);
              if (messageBuffer) {
                messageBuffer.content += event.data;
              }
            }
          }
          break;

        case 'error':
          this.handleStreamError(new Error(event.data), assistantMessageId);
          break;

        case 'done':
          if (event.data === '[DONE]') {
            // NEW ARCHITECTURE: Mark buffer as complete and start animation when ready
            const messageId = this.currentAssistantMessageId || assistantMessageId;
            const messageBuffer = this.messageBuffers.get(messageId);
            
            if (messageBuffer) {
              // Process any remaining chunks
              this.updateBufferContent(messageId);
              
              // Mark buffer as complete
              messageBuffer.isComplete = true;
              
              console.log(`✅ DONE received for ${messageId.slice(-8)}: ${messageBuffer.content.length} chars buffered`);
              
              // Check if we can start animation (need content + metadata)
              this.tryStartAnimation(messageId);
            }
            
            // Mark DONE as received and set up fallback timeout
            this.connectionCloseState.doneReceived = true;
            console.log('⏳ DONE received, keeping connection open for token_usage events');
            
            // Set up a fallback timeout in case token_usage event doesn't arrive
            this.connectionCloseState.closeTimeoutId = setTimeout(() => {
              console.warn('⚠️ Timeout waiting for token_usage event, closing connection anyway');
              this.connectionCloseState.shouldClose = true;
              this.tryCloseConnection();
            }, 3000); // 3 second timeout
            
            // Try to close immediately if conditions are already met
            this.tryCloseConnection();
          }
          break;

        case 'message_saved':
          this.handleMessageSaved(event.data, assistantMessageId);
          // Mark message_saved as received and try to close connection
          this.connectionCloseState.messageSavedReceived = true;
          console.log('💾 message_saved event received, checking if we can close connection');
          this.tryCloseConnection();
          break;

        case 'token_usage':
          console.log('📊 Processing token_usage event:', event.data);
          // Use the tracked message ID for token usage
          const messageIdForTokens = this.currentAssistantMessageId || assistantMessageId;
          console.log(`📊 TOKEN EVENT: original ID: ${assistantMessageId}, current tracked ID: ${this.currentAssistantMessageId}, using ID: ${messageIdForTokens}`);
          this.handleTokenUsage(event.data, messageIdForTokens);
          
          // Mark token_usage as received and try to close connection
          this.connectionCloseState.tokenUsageReceived = true;
          console.log('📊 token_usage event received, checking if we can close connection');
          this.tryCloseConnection();
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
    
    // Reduced logging - only log if queue is getting large
    const queueSize = this.typingQueues.get(messageId)!.length;
    if (queueSize > 10) {
      console.log(`⌨️ Large typing queue for ${messageId}: ${queueSize} items`);
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
          return { ...msg, content: msg.content + nextChunk };
        }
        return msg;
      });
    }, this.typingSpeed);

    this.typingIntervals.set(messageId, interval);
  }

  /**
   * NEW ARCHITECTURE: Handle message saved event with buffer updates
   */
  private handleMessageSaved(data: string, assistantMessageId: string): void {
    try {
      const messageData = JSON.parse(data);
      const actualMessageId = messageData.message_id;
      
      console.log(`💾 handleMessageSaved: Updating message ID from ${assistantMessageId} to ${actualMessageId}`);
      
      // NEW: Transfer message buffer to new ID
      const oldMessageBuffer = this.messageBuffers.get(assistantMessageId);
      if (oldMessageBuffer) {
        // Update buffer with backend ID
        oldMessageBuffer.backend_id = actualMessageId;
        
        // Transfer buffer to new ID
        this.messageBuffers.set(actualMessageId, oldMessageBuffer);
        this.messageBuffers.delete(assistantMessageId);
        
        console.log(`💾 Transferred message buffer from ${assistantMessageId} to ${actualMessageId}`);
        
        // Try to start animation if conditions are now met
        this.tryStartAnimation(actualMessageId);
      }
      
      // Update tracked ID
      this.currentAssistantMessageId = actualMessageId;
      
      // Update message ID in messages array
      this.messages = this.messages.map((msg) => {
        if (msg.id === assistantMessageId) {
          console.log(`💾 Updating message ID: ${assistantMessageId} → ${actualMessageId}`);
          return { ...msg, id: actualMessageId };
        }
        return msg;
      });
      
      // LEGACY: Also handle old buffer systems for compatibility
      const oldBuffer = this.chunkBuffers.get(assistantMessageId);
      if (oldBuffer) {
        this.chunkBuffers.set(actualMessageId, oldBuffer);
        this.chunkBuffers.delete(assistantMessageId);
      }
      
    } catch (error) {
      console.error('Failed to parse message saved data:', error);
    }
  }

  /**
   * NEW ARCHITECTURE: Handle token usage information with buffer updates
   */
  private handleTokenUsage(data: string, assistantMessageId: string): void {
    try {
      const tokenData = JSON.parse(data);
      console.log(`📊 handleTokenUsage: Processing tokens for message ${assistantMessageId}`, {
        prompt_tokens: tokenData.prompt_tokens,
        completion_tokens: tokenData.completion_tokens,
        model_name: tokenData.model_name
      });
      
      // NEW: Store tokens in message buffer
      const messageBuffer = this.messageBuffers.get(assistantMessageId);
      if (messageBuffer) {
        messageBuffer.prompt_tokens = tokenData.prompt_tokens;
        messageBuffer.completion_tokens = tokenData.completion_tokens;
        messageBuffer.model_name = tokenData.model_name;
        
        console.log(`📊 Stored tokens in buffer for ${assistantMessageId}`);
        
        // Try to start animation if conditions are now met
        this.tryStartAnimation(assistantMessageId);
      } else {
        console.warn(`📊 No buffer found for message ${assistantMessageId}, updating message directly`);
        
        // Fallback: Update message directly if no buffer
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
      }
      
    } catch (error) {
      console.error('Failed to parse token usage data:', error);
    }
  }

  /**
   * Finalize message when streaming is complete
   */
  private finalizeMessage(assistantMessageId: string): void {
    // Check if message exists
    const messageExists = this.messages.find(m => m.id === assistantMessageId);
    
    // FIRST: Process any remaining chunks in the chunk buffer
    // This handles the case where chunks are buffered but stream closed before processing
    const chunkBuffer = this.chunkBuffers.get(assistantMessageId);
    if (chunkBuffer && Object.keys(chunkBuffer).length > 0) {
      console.log(`⚠️ Found ${Object.keys(chunkBuffer).length} unprocessed chunks in buffer:`, Object.keys(chunkBuffer).sort((a, b) => parseInt(a) - parseInt(b)));
      
      // Process all remaining chunks in order, regardless of gaps
      const sortedChunkIndices = Object.keys(chunkBuffer)
        .map(k => parseInt(k))
        .sort((a, b) => a - b);
      
      for (const index of sortedChunkIndices) {
        const content = chunkBuffer[index];
        console.log(`📦 Force-processing buffered chunk ${index}, content length: ${content.length}`);
        this.addToTypingQueue(assistantMessageId, content);
      }
    }
    
    // SECOND: Check if there are remaining content chunks in typing queue
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
        const finalMsg = { ...msg, loading: false };
        console.log(`✅ Final message ${assistantMessageId}: ${finalMsg.content.length} chars, tokens: ${finalMsg.prompt_tokens || '?'}/${finalMsg.completion_tokens || '?'}`);
        return finalMsg;
      }
      return msg;
    });
    
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
   * Interrupt all streaming operations (SSE + animations) immediately
   */
  public interrupt(): void {
    console.log('🛑 Interrupting all streaming operations');
    
    // Stop SSE connection
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }

    // Stop all local animations immediately
    for (const [messageId, intervalId] of this.animationIntervals) {
      console.log(`🛑 Stopping animation for message ${messageId.slice(-8)}`);
      clearInterval(intervalId);
      
      // Immediately show all buffered content without animation
      const buffer = this.messageBuffers.get(messageId);
      if (buffer && buffer.content) {
        this.messages = this.messages.map(msg => {
          if (msg.id === messageId) {
            return {
              ...msg,
              content: buffer.content,
              displayedContent: buffer.content, // Show full content immediately
              isAnimating: false, // Stop animation
              prompt_tokens: buffer.prompt_tokens,
              completion_tokens: buffer.completion_tokens,
              model_name: buffer.model_name,
              backend_id: buffer.backend_id
            };
          }
          return msg;
        });
      }
    }
    
    // Clear all animation intervals
    this.animationIntervals.clear();

    // Clear all typing animations (legacy)
    for (const [messageId] of this.typingIntervals) {
      this.clearTyping(messageId);
    }

    // Clean up connection close state
    if (this.connectionCloseState.closeTimeoutId) {
      clearTimeout(this.connectionCloseState.closeTimeoutId);
      this.connectionCloseState.closeTimeoutId = null;
    }
    this.connectionCloseState = {
      doneReceived: false,
      messageSavedReceived: false,
      tokenUsageReceived: false,
      closeTimeoutId: null,
      shouldClose: false
    };

    if (this.connectionStatus !== 'idle' && this.connectionStatus !== 'closed') {
      this.connectionStatus = 'closed';
    }

    this.currentChatId = null;
  }

  /**
   * Disconnect and clean up (graceful shutdown)
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

    // Clear all local animations
    for (const [messageId, intervalId] of this.animationIntervals) {
      clearInterval(intervalId);
    }
    this.animationIntervals.clear();

    // Clean up connection close state
    if (this.connectionCloseState.closeTimeoutId) {
      clearTimeout(this.connectionCloseState.closeTimeoutId);
      this.connectionCloseState.closeTimeoutId = null;
    }
    this.connectionCloseState = {
      doneReceived: false,
      messageSavedReceived: false,
      tokenUsageReceived: false,
      closeTimeoutId: null,
      shouldClose: false
    };

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