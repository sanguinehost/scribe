// DesktopStreamingService.ts - Desktop-specific streaming using Tauri Channels
import { invoke, Channel } from '@tauri-apps/api/core';
import { logger } from '$lib/utils/logger';
import { apiClient } from '$lib/api';
import type {
	StreamingMessage,
	ConnectionStatus,
	StreamingError,
	StreamingConfig
} from './StreamingService.svelte.ts';

// Structured chunk format matching backend
interface StreamedChunk {
	index: number;
	content: string;
	checksum: number;
}

// Tauri Channel event types matching Rust ChatStreamEvent enum
type ChatStreamEvent =
	| { event: 'content'; data: { payload: string } }
	| { event: 'thinking'; data: { text: string } }
	| { event: 'error'; data: { message: string } }
	| {
			event: 'tokenUsage';
			data: { promptTokens: number; completionTokens: number; modelName: string };
	  }
	| {
			event: 'messageSaved';
			data: { messageId: string; variantCount: number; currentVariantIndex: number };
	  }
	| { event: 'gameStateUpdate'; data: { gameState: Record<string, unknown> } }
	| { event: 'done' };

const DEFAULT_CONFIG: StreamingConfig = {
	timeoutMs: 60000,
	maxRetries: 3,
	retryDelayMs: 1000,
	enableBackoff: true
};

/**
 * DesktopStreamingService - Desktop-specific streaming using Tauri Channels
 *
 * Architecture:
 * 1. Frontend calls invoke('stream_chat_response', { ..., channel })
 * 2. Rust parses backend SSE → ChatStreamEvent
 * 3. Events sent through channel to this service
 * 4. Same buffering/chunking logic as web StreamingService
 */
class DesktopStreamingService {
	// Reactive state using $state rune
	public messages = $state<StreamingMessage[]>([]);
	public connectionStatus = $state<ConnectionStatus>('idle');
	public currentError = $state<StreamingError | null>(null);
	public isTyping = $state(false);
	public latestGameState = $state<Record<string, unknown> | null>(null);

	// Private state for connection management
	private retryCount = 0;
	private config: StreamingConfig;
	private currentChatId: string | null = null;
	private currentAssistantMessageId: string | null = null;
	private lastActivity: number = 0;
	private timeoutInterval: ReturnType<typeof setInterval> | null = null;

	// Buffer-first architecture state
	private messageBuffers = new Map<
		string,
		{
			content: string;
			chunks: { [index: number]: string };
			prompt_tokens?: number;
			completion_tokens?: number;
			model_name?: string;
			backend_id?: string;
			isComplete: boolean;
		}
	>();

	// Connection close state tracking
	private connectionCloseState = {
		doneReceived: false,
		messageSavedReceived: false,
		tokenUsageReceived: false,
		shouldClose: false
	};

	constructor(config: Partial<StreamingConfig> = {}) {
		this.config = { ...DEFAULT_CONFIG, ...config };
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
	 * Connect and start streaming using Tauri Channels
	 */
	public async connect(params: {
		chatId: string;
		userMessage: string;
		history: Array<{ role: 'user' | 'assistant'; content: string }>;
		model?: string;
		agentMode?: string;
		analysisMode?: 'existing' | 'refresh' | 'skip';
		isRegeneration?: boolean;
		guidance?: string;
		targetMessageId?: string;
		variantOf?: string;
	}): Promise<void> {
		if (this.connectionStatus === 'connecting' || this.connectionStatus === 'open') {
			logger.warn('desktop-streaming', 'Connection already active. Disconnect first.');
			return;
		}

		logger.debug('desktop-streaming', 'Starting connection for chat', { chatId: params.chatId });
		console.log('🚀 [DesktopStreamingService] Connecting to chat', params.chatId);

		this.currentChatId = params.chatId;
		this.retryCount = 0;
		this.connectionStatus = 'connecting';
		this.currentError = null;

		// Reset connection close state
		this.connectionCloseState = {
			doneReceived: false,
			messageSavedReceived: false,
			tokenUsageReceived: false,
			shouldClose: false
		};

		this.lastActivity = Date.now();
		this.startTimeoutCheck();

		// Add user message optimistically (skip for regeneration)
		if (!params.isRegeneration) {
			const userMessage: StreamingMessage = {
				id: crypto.randomUUID(),
				content: params.userMessage,
				displayedContent: params.userMessage,
				sender: 'user',
				created_at: new Date().toISOString(),
				contentVersion: 0 // Initialize for Svelte 5 reactivity
			};
			this.messages = [...this.messages, userMessage];
		}

		// Create or update assistant message
		let assistantMessage: StreamingMessage;
		let assistantMessageId: string;

		if (params.targetMessageId) {
			// Variant mode: Update existing message
			logger.debug('desktop-streaming', 'Variant mode - searching for target message', {
				targetMessageId: params.targetMessageId
			});

			const existingMessageIndex = this.messages.findIndex(
				(msg) => msg.id === params.targetMessageId || msg.backend_id === params.targetMessageId
			);

			if (existingMessageIndex === -1) {
				logger.error('desktop-streaming', 'Target message not found', {
					targetMessageId: params.targetMessageId
				});
				throw new Error(`Target message ${params.targetMessageId} not found for variant update`);
			}

			const existingMessage = this.messages[existingMessageIndex];
			logger.debug('desktop-streaming', 'Preserving variant metadata', {
				variant_count: existingMessage.variant_count,
				current_variant_index: existingMessage.current_variant_index
			});

			// Replace message object entirely for Svelte reactivity
			this.messages[existingMessageIndex] = {
				...existingMessage,
				content: '',
				displayedContent: '',
				isAnimating: false,
				isRegenerating: true,
				error: undefined,
				contentVersion: 0, // Initialize reactivity signal
				retryable: false
			};
			this.messages = [...this.messages];

			assistantMessage = this.messages[existingMessageIndex];
			assistantMessageId = assistantMessage.id;
			logger.debug('desktop-streaming', 'Using existing message ID', {
				messageId: assistantMessageId
			});
		} else {
			// New message mode
			logger.debug('desktop-streaming', 'Creating new message');
			assistantMessage = {
				id: crypto.randomUUID(),
				content: '',
				displayedContent: '',
				sender: 'assistant',
				created_at: new Date().toISOString(),
				isAnimating: false,
				contentVersion: 0, // Initialize reactivity signal
				shouldAnimate: true
			};
			this.messages = [...this.messages, assistantMessage];
			assistantMessageId = assistantMessage.id;
			logger.debug('desktop-streaming', 'Created new message', {
				messageId: assistantMessageId
			});
		}

		// Track current assistant message ID
		this.currentAssistantMessageId = assistantMessageId;

		// Initialize buffer
		this.messageBuffers.set(assistantMessageId, {
			content: '',
			chunks: {},
			isComplete: false
		});

		try {
			await this.startChannelStream(
				{
					chatId: params.chatId,
					userMessage: params.userMessage,
					history: params.history,
					model: params.model,
					agentMode: params.agentMode,
					analysisMode: params.analysisMode,
					guidance: params.guidance,
					variantOf: params.variantOf,
					isRegeneration: params.isRegeneration
				},
				assistantMessageId
			);
		} catch (error) {
			this.handleConnectionError(error as Error);
		}
	}

	/**
	 * Start streaming using Tauri Channel
	 */
	private async startChannelStream(
		params: {
			chatId: string;
			userMessage: string;
			history: Array<{ role: 'user' | 'assistant'; content: string }>;
			model?: string;
			agentMode?: string;
			analysisMode?: 'existing' | 'refresh' | 'skip';
			guidance?: string;
			variantOf?: string;
			isRegeneration?: boolean;
		},
		assistantMessageId: string
	): Promise<void> {
		logger.debug('desktop-streaming', 'Creating Tauri Channel for session', {
			sessionId: params.chatId
		});

		// Create Tauri Channel for receiving events
		const channel = new Channel<ChatStreamEvent>();

		// Set up channel message handler
		let eventCount = 0;
		channel.onmessage = (event: ChatStreamEvent) => {
			eventCount++;
			this.lastActivity = Date.now();
			logger.debug('desktop-streaming', 'Channel event received', {
				eventNumber: eventCount,
				eventType: event.event
			});

			// Enhanced logging to trace data corruption
			// Use type narrowing or 'in' check to safely access data
			let eventData: unknown = 'N/A';
			if ('data' in event) {
				eventData = (event as { data: unknown }).data;
			}

			logger.debug('desktop-streaming', 'Full event data from Tauri', {
				eventType: event.event,
				data: eventData,
				dataType: typeof eventData,
				dataStringified: JSON.stringify(eventData),
				dataKeys:
					eventData && typeof eventData === 'object' ? Object.keys(eventData as object) : 'N/A'
			});

			this.handleChannelEvent(event, assistantMessageId);
			logger.debug('desktop-streaming', 'Event handled successfully', {
				eventNumber: eventCount
			});
		};

		try {
			logger.debug('desktop-streaming', 'Invoking stream_chat_response', {
				sessionId: params.chatId,
				userMessageLength: params.userMessage.length,
				historyLength: params.history.length,
				model: params.model || 'default'
			});

			// Invoke Tauri command with channel parameter
			await invoke('stream_chat_response', {
				sessionId: params.chatId,
				userMessage: params.userMessage,
				history: params.history.map((msg) => ({ role: msg.role, content: msg.content })),
				model: params.model || null,
				agentMode: params.agentMode || null,
				analysisMode: params.analysisMode || null,
				guidance: params.guidance || null,
				variantOf: params.variantOf || null,
				isRegeneration: params.isRegeneration || false,
				channel
			});

			logger.debug('desktop-streaming', 'Stream command completed successfully');
			this.stopTimeoutCheck();
			this.connectionStatus = 'closed';
		} catch (error) {
			logger.error('desktop-streaming', 'Stream command failed', error as Error);
			this.stopTimeoutCheck();
			this.handleConnectionError(error as Error);
		}
	}

	/**
	 * Start timeout check interval
	 */
	private startTimeoutCheck(): void {
		this.stopTimeoutCheck();
		this.timeoutInterval = setInterval(() => {
			this.checkTimeout();
		}, 1000);
	}

	/**
	 * Stop timeout check interval
	 */
	private stopTimeoutCheck(): void {
		if (this.timeoutInterval) {
			clearInterval(this.timeoutInterval);
			this.timeoutInterval = null;
		}
	}

	/**
	 * Check for connection timeout
	 */
	private checkTimeout(): void {
		if (this.connectionStatus !== 'connecting' && this.connectionStatus !== 'open') {
			this.stopTimeoutCheck();
			return;
		}

		const now = Date.now();
		// Use configured timeout (default 60s) instead of hardcoded 10s
		if (now - this.lastActivity > this.config.timeoutMs) {
			logger.warn('desktop-streaming', `Connection timed out (${this.config.timeoutMs}ms idle)`);

			// If we have received done OR messageSaved, just close it gracefully
			// This handles cases where the stream ends but the 'done' event is delayed or lost,
			// but we know the message is safe in the DB.
			if (
				this.connectionCloseState.doneReceived ||
				this.connectionCloseState.messageSavedReceived
			) {
				logger.info(
					'desktop-streaming',
					'Timeout while waiting for final events, forcing close (message safe)'
				);
				this.connectionStatus = 'closed';
			} else {
				// If we haven't received done AND haven't saved the message, it's a real timeout error
				this.handleConnectionError(
					new Error(`Connection timed out (no data received for ${this.config.timeoutMs}ms)`)
				);
			}
			this.stopTimeoutCheck();
		}
	}

	/**
	 * Handle incoming channel events
	 */
	private handleChannelEvent(event: ChatStreamEvent, assistantMessageId: string): void {
		switch (event.event) {
			case 'content':
				this.handleContentEvent(event.data.payload, assistantMessageId);
				break;

			case 'thinking':
				this.handleThinkingEvent(event.data.text, assistantMessageId);
				break;

			case 'error':
				this.handleErrorEvent(event.data.message);
				break;

			case 'tokenUsage':
				this.handleTokenUsageEvent(
					event.data.promptTokens,
					event.data.completionTokens,
					event.data.modelName,
					assistantMessageId
				);
				break;

			case 'messageSaved':
				// Enhanced logging to trace data extraction
				logger.debug('desktop-streaming', 'messageSaved event data', {
					fullEventData: event.data,
					messageId: event.data.messageId,
					messageIdType: typeof event.data.messageId,
					variantCount: event.data.variantCount,
					variantCountType: typeof event.data.variantCount,
					currentVariantIndex: event.data.currentVariantIndex,
					currentVariantIndexType: typeof event.data.currentVariantIndex
				});

				this.handleMessageSavedEvent(
					event.data.messageId,
					event.data.variantCount,
					event.data.currentVariantIndex,
					assistantMessageId
				);
				break;

			case 'done':
				this.handleDoneEvent(assistantMessageId);
				break;

			case 'gameStateUpdate':
				this.handleGameStateUpdateEvent(event.data.gameState);
				break;

			default:
				logger.warn('desktop-streaming', 'Unknown event type', {
					eventType: (event as { event: string }).event
				});
		}
	}

	/**
	 * Handle content chunk event
	 */
	private handleContentEvent(payload: string, assistantMessageId: string): void {
		try {
			const chunk: StreamedChunk = JSON.parse(payload);
			const buffer = this.messageBuffers.get(assistantMessageId);

			if (!buffer) {
				logger.warn('desktop-streaming', 'No buffer found for message', {
					messageId: assistantMessageId
				});
				return;
			}

			// Race Condition Fix:
			// If the message is already marked as complete (e.g. we received messageSaved),
			// ignore any late-arriving chunks to prevent overwriting the final state.
			if (buffer.isComplete) {
				logger.debug('desktop-streaming', 'Ignoring late chunk for completed message', {
					messageId: assistantMessageId,
					chunkIndex: chunk.index
				});
				return;
			}

			// Soft Checksum Verification
			const expectedChecksum = this.crc32(chunk.content);
			if (chunk.checksum !== expectedChecksum) {
				logger.warn('desktop-streaming', 'Checksum mismatch (soft)', {
					received: chunk.checksum,
					expected: expectedChecksum,
					contentPreview: chunk.content.substring(0, 20)
				});
			}

			// Store chunk in buffer
			// We keep ALL chunks to allow for reconstruction
			buffer.chunks[chunk.index] = chunk.content;

			// Reconstruct content from all available chunks
			this.reconstructContent(buffer, assistantMessageId);

			this.isTyping = true;
			this.connectionStatus = 'open';
		} catch (error) {
			logger.error('desktop-streaming', 'Failed to parse content chunk', error as Error);
		}
	}

	/**
	 * Reconstruct message content from all buffered chunks
	 * This ensures that even if chunks arrive out of order, the message
	 * is always consistent with what we have received so far.
	 */
	private reconstructContent(
		buffer: NonNullable<ReturnType<typeof this.messageBuffers.get>>,
		assistantMessageId: string
	): void {
		// Get all available chunk indices, sorted numerically
		const indices = Object.keys(buffer.chunks)
			.map(Number)
			.sort((a, b) => a - b);

		if (indices.length === 0) return;

		// Rebuild content string
		let reconstructedContent = '';
		for (const index of indices) {
			reconstructedContent += buffer.chunks[index];
		}

		// Update buffer content
		buffer.content = reconstructedContent;

		// Update UI
		this.messages = this.messages.map((msg) => {
			if (msg.id === assistantMessageId || msg.backend_id === assistantMessageId) {
				return {
					...msg,
					content: buffer.content,
					displayedContent: buffer.content,
					contentVersion: (msg.contentVersion || 0) + 1,
					isAnimating: false,
					isRegenerating: false
				};
			}
			return msg;
		});
	}

	/**
	 * Handle thinking event
	 */
	private handleThinkingEvent(text: string, _assistantMessageId: string): void {
		logger.debug('desktop-streaming', 'Thinking text received', {
			textPrefix: text.substring(0, 50)
		});
		// TODO: Implement thinking display if needed
	}

	/**
	 * Handle error event
	 */
	private handleErrorEvent(message: string): void {
		logger.error('desktop-streaming', 'Error event received', { message });

		const error: StreamingError = {
			message,
			type: 'server',
			retryable: false
		};

		this.currentError = error;
		this.connectionStatus = 'error';
		this.isTyping = false;

		// Update message with error using atomic .map() pattern
		if (this.currentAssistantMessageId) {
			this.messages = this.messages.map((msg) => {
				if (msg.id === this.currentAssistantMessageId) {
					return {
						...msg,
						error: message,
						retryable: false,
						isAnimating: false,
						isRegenerating: false
					};
				}
				return msg;
			});
		}
	}

	/**
	 * Handle token usage event
	 */
	private handleTokenUsageEvent(
		promptTokens: number,
		completionTokens: number,
		modelName: string,
		assistantMessageId: string
	): void {
		logger.debug('desktop-streaming', 'Token usage received', {
			promptTokens,
			completionTokens,
			modelName
		});

		const buffer = this.messageBuffers.get(assistantMessageId);
		if (buffer) {
			buffer.prompt_tokens = promptTokens;
			buffer.completion_tokens = completionTokens;
			buffer.model_name = modelName;
		}

		// Update token usage using atomic .map() pattern
		this.messages = this.messages.map((msg) => {
			if (msg.id === assistantMessageId || msg.backend_id === assistantMessageId) {
				return {
					...msg,
					prompt_tokens: promptTokens,
					completion_tokens: completionTokens,
					model_name: modelName
				};
			}
			return msg;
		});

		this.connectionCloseState.tokenUsageReceived = true;
		this.tryCloseConnection();
	}

	/**
	 * Handle message saved event
	 */
	private handleMessageSavedEvent(
		messageId: string,
		variantCount: number,
		currentVariantIndex: number,
		assistantMessageId: string
	): void {
		// Enhanced logging with type checking
		logger.debug('desktop-streaming', 'handleMessageSavedEvent called', {
			messageId,
			messageIdType: typeof messageId,
			messageIdTruthy: !!messageId,
			variantCount,
			variantCountType: typeof variantCount,
			variantCountTruthy: !!variantCount,
			currentVariantIndex,
			currentVariantIndexType: typeof currentVariantIndex,
			currentVariantIndexTruthy: currentVariantIndex !== undefined
		});

		// Validate inputs before using them
		if (!messageId || messageId === 'undefined' || typeof messageId !== 'string') {
			logger.error('desktop-streaming', 'Invalid messageId received', {
				value: messageId,
				type: typeof messageId,
				isNull: messageId === null,
				isUndefined: messageId === undefined
			});
			return;
		}

		if (typeof variantCount !== 'number' || isNaN(variantCount)) {
			logger.error('desktop-streaming', 'Invalid variantCount received', {
				value: variantCount,
				type: typeof variantCount,
				isNaN: isNaN(variantCount)
			});
			return;
		}

		logger.debug('desktop-streaming', 'Message saved validation passed');

		const buffer = this.messageBuffers.get(assistantMessageId);
		if (buffer) {
			buffer.backend_id = messageId;
			buffer.isComplete = true;
		}

		// Update message saved data using atomic .map() pattern
		this.messages = this.messages.map((msg) => {
			if (msg.id === assistantMessageId || msg.backend_id === assistantMessageId) {
				return {
					...msg,
					backend_id: messageId,
					variant_count: variantCount,
					current_variant_index: currentVariantIndex,
					status: 'completed'
				};
			}
			return msg;
		});

		this.connectionCloseState.messageSavedReceived = true;

		// Flush any remaining chunks in the buffer to ensure we have as much as possible
		this.flushBuffer(assistantMessageId);

		// CRITICAL FIX: Fetch the full, authoritative message from the backend
		// This ensures that even if the stream skipped chunks or was incomplete,
		// the user sees the perfect final result stored in the database.
		this.fetchFullMessage(messageId, assistantMessageId);

		this.tryCloseConnection();
	}

	/**
	 * Fetch the full message from backend and update local state
	 */
	private async fetchFullMessage(backendId: string, localId: string): Promise<void> {
		logger.debug('desktop-streaming', 'Fetching full message from backend', { backendId, localId });

		try {
			const result = await apiClient.getMessageById(backendId);

			if (result.isOk()) {
				const fullMessage = result.value;
				logger.debug('desktop-streaming', 'Successfully fetched full message', {
					id: fullMessage.id,
					contentLength: fullMessage.content.length
				});

				// Update the message with the authoritative content
				this.messages = this.messages.map((msg) => {
					if (msg.id === localId || msg.backend_id === backendId) {
						return {
							...msg,
							content: fullMessage.content,
							displayedContent: fullMessage.content,
							contentVersion: (msg.contentVersion || 0) + 1,
							status: 'completed',
							// Preserve other fields
							backend_id: fullMessage.id,
							variant_count: fullMessage.variant_count || msg.variant_count,
							current_variant_index: fullMessage.current_variant_index || msg.current_variant_index
						};
					}
					return msg;
				});
			} else {
				logger.error('desktop-streaming', 'Failed to fetch full message', result.error);
			}
		} catch (error) {
			logger.error('desktop-streaming', 'Exception fetching full message', error as Error);
		}
	}

	/**
	 * Flush buffer - effectively just a final reconstruction
	 */
	private flushBuffer(assistantMessageId: string): void {
		const buffer = this.messageBuffers.get(assistantMessageId);
		if (!buffer) return;

		logger.debug('desktop-streaming', 'Flushing buffer (final reconstruction)', {
			messageId: assistantMessageId,
			bufferedChunks: Object.keys(buffer.chunks).length
		});

		this.reconstructContent(buffer, assistantMessageId);
	}

	/**
	 * Handle done event
	 */
	private handleDoneEvent(assistantMessageId?: string): void {
		logger.debug('desktop-streaming', 'Done event received');

		if (assistantMessageId) {
			this.flushBuffer(assistantMessageId);
		} else if (this.currentAssistantMessageId) {
			this.flushBuffer(this.currentAssistantMessageId);
		}

		this.isTyping = false;
		this.connectionCloseState.doneReceived = true;
		this.tryCloseConnection();
	}

	/**
	 * Handle game state update event from backend
	 */
	private handleGameStateUpdateEvent(gameState: Record<string, unknown>): void {
		logger.debug('desktop-streaming', 'Game state update received', {
			gameStateKeys: Object.keys(gameState)
		});
		this.latestGameState = gameState;
	}

	/**
	 * Try to close connection if all events received
	 */
	private tryCloseConnection(): void {
		if (this.connectionCloseState.doneReceived && this.connectionCloseState.tokenUsageReceived) {
			logger.debug('desktop-streaming', 'All events received, closing connection');
			this.stopTimeoutCheck();
			this.connectionStatus = 'closed';
		}
	}

	/**
	 * Handle connection error
	 */
	private handleConnectionError(error: Error): void {
		logger.error('desktop-streaming', 'Connection error', error);

		const streamError: StreamingError = {
			message: error.message || 'Connection failed',
			type: 'network',
			retryable: this.retryCount < this.config.maxRetries,
			originalError: error
		};

		this.currentError = streamError;
		this.connectionStatus = 'error';
		this.isTyping = false;

		// Update message with error
		if (this.currentAssistantMessageId) {
			const messageIndex = this.messages.findIndex(
				(msg) => msg.id === this.currentAssistantMessageId
			);

			if (messageIndex !== -1) {
				this.messages[messageIndex] = {
					...this.messages[messageIndex],
					error: error.message,
					retryable: streamError.retryable,
					isAnimating: false,
					isRegenerating: false
				};
				this.messages = [...this.messages];
			}
		}
	}

	/**
	 * Disconnect and cleanup
	 */
	public async disconnect(): Promise<void> {
		logger.debug('desktop-streaming', 'Disconnecting');

		this.stopTimeoutCheck();
		this.connectionStatus = 'closed';
		this.isTyping = false;
		this.currentChatId = null;
		this.currentAssistantMessageId = null;
	}

	/**
	 * Reset the service state
	 */
	public reset(): void {
		logger.debug('desktop-streaming', 'Resetting service');

		this.messages = [];
		this.connectionStatus = 'idle';
		this.currentError = null;
		this.isTyping = false;
		this.retryCount = 0;
		this.stopTimeoutCheck();
		this.messageBuffers.clear();
		this.currentChatId = null;
		this.currentAssistantMessageId = null;
		this.connectionCloseState = {
			doneReceived: false,
			messageSavedReceived: false,
			tokenUsageReceived: false,
			shouldClose: false
		};
	}

	/**
	 * Clear all messages and buffers
	 * Delegates to reset() for compatibility with web StreamingService
	 */
	public clearMessages(): void {
		this.reset();
	}

	/**
	 * Stop the current streaming message
	 * Note: Can't actually abort Tauri invoke, but can mark message as complete
	 */
	public stopCurrentStream(): void {
		if (!this.currentAssistantMessageId) {
			logger.warn('desktop-streaming', 'No current stream to stop');
			return;
		}

		logger.debug('desktop-streaming', 'Stopping current stream', {
			messageId: this.currentAssistantMessageId
		});

		// Mark the current message buffer as complete
		const buffer = this.messageBuffers.get(this.currentAssistantMessageId);
		if (buffer) {
			buffer.isComplete = true;

			// Update message with current buffered content
			this.messages = this.messages.map((msg) => {
				if (msg.id === this.currentAssistantMessageId) {
					return {
						...msg,
						content: buffer.content,
						displayedContent: buffer.content,
						isAnimating: false,
						shouldAnimate: false,
						status: 'completed'
					};
				}
				return msg;
			});
		}

		// Reset connection status
		if (this.connectionStatus !== 'idle' && this.connectionStatus !== 'closed') {
			this.stopTimeoutCheck();
			this.connectionStatus = 'closed';
		}
	}

	/**
	 * Alias for stopCurrentStream to match StreamingService interface
	 */
	public interrupt(): void {
		this.stopCurrentStream();
	}

	/**
	 * TEST METHOD: Verify Tauri Channels work in isolation
	 * Invokes test_channel_simple command which sends 5 simple messages
	 * SUCCESS CRITERIA: All 5 messages must be received and logged with markers
	 */
	async testChannelSimple(): Promise<void> {
		logger.info('desktop-streaming', 'Starting channel test - expecting 5 test messages');

		const channel = new Channel<string>();
		const receivedMessages: string[] = [];

		channel.onmessage = (message: string) => {
			receivedMessages.push(message);
			logger.debug('desktop-streaming', 'Test message received', {
				messageNumber: receivedMessages.length,
				message
			});
		};

		try {
			logger.debug('desktop-streaming', 'Invoking test_channel_simple command');
			await invoke('test_channel_simple', { channel });
			logger.debug('desktop-streaming', 'Command completed successfully');
			logger.info('desktop-streaming', 'Test results', {
				totalReceived: receivedMessages.length,
				expected: 5
			});

			if (receivedMessages.length === 5) {
				logger.info('desktop-streaming', 'Channel test passed - all 5 messages received');
			} else {
				logger.error('desktop-streaming', 'Channel test failed - missing messages', {
					received: receivedMessages.length,
					expected: 5
				});
			}
		} catch (error) {
			logger.error('desktop-streaming', 'Command failed', error as Error);
		}
	}

	/**
	 * CRC32 checksum calculation (matches backend implementation)
	 * CRITICAL: Must convert to UTF-8 bytes to match backend's crc32fast::hash(content.as_bytes())
	 */
	private crc32(str: string): number {
		// Convert string to UTF-8 bytes (matching backend behavior)
		const encoder = new TextEncoder();
		const bytes = encoder.encode(str);

		let crc = 0xffffffff;
		for (let i = 0; i < bytes.length; i++) {
			crc = crc ^ bytes[i];
			for (let j = 0; j < 8; j++) {
				crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
			}
		}
		return (crc ^ 0xffffffff) >>> 0;
	}
}

// Export singleton instance
export const desktopStreamingService = new DesktopStreamingService();
