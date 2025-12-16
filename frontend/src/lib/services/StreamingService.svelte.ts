// StreamingService.ts - Decoupled Svelte 5 Streaming Client with Robust Error Handling
import { source } from 'sveltekit-sse';
import { env } from '$env/dynamic/public';
import { isInDesktopMode, desktopAuth } from '$lib/api/desktop-auth';
import { logger } from '$lib/utils/logger';
import type {
	ScribeChatMessage as _ScribeChatMessage,
	ScribeChatSession as _ScribeChatSession
} from '$lib/types';

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
	isRegenerating?: boolean; // Currently regenerating this message (shows loading indicator)
	shouldAnimate?: boolean; // True only for new streaming messages, false for historical messages
	error?: string;
	retryable?: boolean;
	prompt_tokens?: number;
	completion_tokens?: number;
	model_name?: string;
	backend_id?: string; // For mapping back to ScribeChatMessage
	status?: string; // Message status: streaming, completed, failed, partial, pending
	superseded_at?: string | null; // ISO 8601 timestamp when message was superseded
	// Variant metadata
	variant_count?: number; // Number of variants for this message
	current_variant_index?: number; // Currently selected variant index
	is_variant?: boolean; // Whether this is a variant of another message
	parent_message_id?: string | null; // UUID of parent message if this is a variant
	contentVersion?: number; // Reactivity signal - increments when content changes during streaming (required for Svelte 5 fine-grained tracking)
	game_state?: Record<string, unknown> | null; // Game state associated with this message
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
	public latestGameState = $state<Record<string, unknown> | null>(null);

	// Private state for connection management
	private activeConnection: ReturnType<typeof source> | null = null;
	private activeSubscriptions: Array<() => void> = [];
	private retryCount = 0;
	private config: StreamingConfig;
	private currentChatId: string | null = null;

	// Track the current assistant message ID (may change when backend saves)
	private currentAssistantMessageId: string | null = null;

	// NEW: Buffer-first architecture state
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

	// Animation state
	private animationIntervals = new Map<string, ReturnType<typeof setTimeout>>();
	private animationStartTimes = new Map<string, number>();
	private animationRequestIds = new Map<string, number>();
	private animationFallbackTimeouts = new Map<string, ReturnType<typeof setTimeout>>();
	private readonly DEFAULT_ANIMATION_SPEED = 15; // ms between character reveals

	// Connection closure tracking - wait for critical events after DONE
	private connectionCloseState = {
		doneReceived: false,
		messageSavedReceived: false,
		tokenUsageReceived: false,
		closeTimeoutId: null as ReturnType<typeof setTimeout> | null,
		shouldClose: false
	};

	// Page visibility tracking for recovery checks only
	private isTabVisible = true;
	private visibilityListenersAdded = false;

	constructor(config: Partial<StreamingConfig> = {}) {
		this.config = { ...DEFAULT_CONFIG, ...config };
		this.setupVisibilityListeners();
	}

	/**
	 * Setup page visibility event listeners to handle background tab behavior
	 */
	private setupVisibilityListeners(): void {
		if (typeof window === 'undefined' || this.visibilityListenersAdded) {
			return; // Skip on server-side or if already added
		}

		// Initialize visibility state
		this.isTabVisible = !document.hidden;

		// Listen for visibility changes
		const handleVisibilityChange = () => {
			const wasVisible = this.isTabVisible;
			this.isTabVisible = !document.hidden;

			logger.debug('streaming-service', 'Tab visibility changed', {
				from: wasVisible ? 'visible' : 'hidden',
				to: this.isTabVisible ? 'visible' : 'hidden'
			});

			// Tab visibility changed - no special handling needed anymore
		};

		// Listen for focus/blur events as fallback
		const handleFocus = () => {
			if (!this.isTabVisible) {
				this.isTabVisible = true;
				logger.debug('streaming-service', 'Tab gained focus (fallback visibility detection)');
			}
		};

		const handleBlur = () => {
			this.isTabVisible = false;
			logger.debug('streaming-service', 'Tab lost focus');
		};

		document.addEventListener('visibilitychange', handleVisibilityChange);
		window.addEventListener('focus', handleFocus);
		window.addEventListener('blur', handleBlur);

		this.visibilityListenersAdded = true;
		logger.debug('streaming-service', 'Page visibility listeners setup complete');
	}

	/**
	 * Check if we should close the connection based on received events
	 */
	private shouldCloseConnection(): boolean {
		const state = this.connectionCloseState;

		// We can close if we've received DONE and token_usage (message_saved is optional)
		// OR if we've received DONE and it's been a while (fallback timeout)
		return state.doneReceived && (state.tokenUsageReceived || state.shouldClose);
	}

	/**
	 * Attempt to close the connection if all conditions are met
	 */
	private tryCloseConnection(): void {
		if (this.shouldCloseConnection()) {
			logger.debug('streaming-service', 'All events received, closing connection');

			// Clear any pending timeout
			if (this.connectionCloseState.closeTimeoutId) {
				clearTimeout(this.connectionCloseState.closeTimeoutId);
				this.connectionCloseState.closeTimeoutId = null;
			}

			// Actually close the connection
			this.cleanupConnection();

			if (this.connectionStatus !== 'closed' && this.connectionStatus !== 'error') {
				this.connectionStatus = 'closed';
			}
		}
	}

	/**
	 * NEW ARCHITECTURE: Reconstruct message content from all buffered chunks
	 * This ensures that even if chunks arrive out of order, the message
	 * is always consistent with what we have received so far.
	 */
	private reconstructContent(messageId: string): void {
		const buffer = this.messageBuffers.get(messageId);
		if (!buffer) return;

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

		// Update message progressively so TypewriterMessage can see content
		this.updateMessageContentProgressive(messageId);
	}

	/**
	 * Update message with complete content (no animation in service)
	 */
	private updateMessageContent(messageId: string): void {
		const buffer = this.messageBuffers.get(messageId);
		if (!buffer || !buffer.isComplete) return;

		logger.debug('streaming-service', 'Updating message with complete content', {
			messageId: messageId.slice(-8),
			contentLength: buffer.content.length
		});

		// Use in-place mutation to preserve Svelte 5 reactivity proxies
		// Avoid array reassignment which breaks proxy chain and causes crashes
		const message = this.messages.find((msg) => msg.id === messageId);
		if (message) {
			message.content = buffer.content;
			message.displayedContent = buffer.content;
			message.isAnimating = false;
			message.isRegenerating = false;
			message.shouldAnimate = false; // Stream is complete, no need to animate
			message.prompt_tokens = buffer.prompt_tokens;
			message.completion_tokens = buffer.completion_tokens;
			message.model_name = buffer.model_name;
			message.backend_id = buffer.backend_id;
		}
	}

	/**
	 * Update message content progressively as chunks arrive (before streaming is complete)
	 */
	private updateMessageContentProgressive(messageId: string): void {
		const buffer = this.messageBuffers.get(messageId);
		if (!buffer) return;

		// Update message with current buffered content (even if not complete)
		// CRITICAL: Use in-place mutation to preserve Svelte 5 proxy chain
		const message = this.messages.find((msg) => msg.id === messageId);
		if (message) {
			message.content = buffer.content;
			message.displayedContent = buffer.content; // Update displayed content for UI
			message.isAnimating = false; // TypewriterMessage handles animation
		}
	}

	/**
	 * Handle game state update event
	 */
	private handleGameStateUpdateEvent(gameState: Record<string, unknown>): void {
		console.log('📡 StreamingService received game_state event:', gameState);
		this.latestGameState = gameState;
	}

	/**
	 * Parse multiple JSON chunks that may be concatenated in a single string
	 */
	private parseMultipleJsonChunks(_data: string): StreamedChunk[] {
		const chunks: StreamedChunk[] = [];
		let remaining = _data.trim();

		while (remaining.length > 0) {
			try {
				// Find the end of the current JSON object by counting braces
				let braceCount = 0;
				let inString = false;
				let escaped = false;
				let jsonEnd = -1;

				for (let i = 0; i < remaining.length; i++) {
					const char = remaining[i];

					if (escaped) {
						escaped = false;
						continue;
					}

					if (char === '\\' && inString) {
						escaped = true;
						continue;
					}

					if (char === '"') {
						inString = !inString;
						continue;
					}

					if (!inString) {
						if (char === '{') {
							braceCount++;
						} else if (char === '}') {
							braceCount--;
							if (braceCount === 0) {
								jsonEnd = i + 1;
								break;
							}
						}
					}
				}

				if (jsonEnd === -1) {
					// No complete JSON object found
					logger.warn('streaming-service', 'Incomplete JSON chunk found', {
						remainingPrefix: remaining.substring(0, 100)
					});
					break;
				}

				const jsonStr = remaining.substring(0, jsonEnd);
				const chunk = JSON.parse(jsonStr);
				chunks.push(chunk);

				remaining = remaining.substring(jsonEnd).trim();
			} catch (_e) {
				logger.error('streaming-service', 'Failed to parse JSON chunk', {
					error: _e as Error,
					remainingPrefix: remaining.substring(0, 100)
				});
				break;
			}
		}

		return chunks;
	}

	/**
	 * Simple CRC32 calculation for chunk verification
	 * Note: This should match the rust crc32fast implementation
	 */
	private calculateChecksum(content: string): number {
		// Simple implementation - in production, use a proper CRC32 library
		let crc = 0xffffffff;
		const bytes = new TextEncoder().encode(content);

		for (let i = 0; i < bytes.length; i++) {
			crc ^= bytes[i];
			for (let j = 0; j < 8; j++) {
				crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
			}
		}

		return (crc ^ 0xffffffff) >>> 0; // Convert to unsigned 32-bit
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
		analysisMode?: 'existing' | 'refresh' | 'skip'; // For variant regeneration
		isRegeneration?: boolean; // If true, don't add the user message again
		guidance?: string; // Optional guidance text for regeneration steering
		targetMessageId?: string; // If provided, update this message instead of creating new
		variantOf?: string; // If provided, create this response as a variant of the specified message ID
	}): Promise<void> {
		// Connect to streaming service
		console.log('🌐 [WebStreamingService] Connecting to chat', params.chatId);

		if (this.connectionStatus === 'connecting' || this.connectionStatus === 'open') {
			logger.warn('streaming-service', 'Connection already active. Disconnect first.');
			return;
		}

		// Note: Removed tab visibility check - connections should proceed regardless of tab focus

		this.currentChatId = params.chatId;
		this.cleanupConnection();
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

		// Add user message optimistically (skip for regeneration since it already exists)
		if (!params.isRegeneration) {
			const userMessage: StreamingMessage = {
				id: crypto.randomUUID(),
				content: params.userMessage,
				displayedContent: params.userMessage, // User messages show immediately
				sender: 'user',
				created_at: new Date().toISOString(),
				contentVersion: 0 // Initialize for Svelte 5 reactivity
			};
			this.messages = [...this.messages, userMessage];
		}

		// NEW ARCHITECTURE: Create or update assistant message with buffer-first approach
		let assistantMessage: StreamingMessage;
		let assistantMessageId: string;

		if (params.targetMessageId) {
			// Variant mode: Update existing message
			logger.debug('streaming-service', 'Variant mode - searching for target message', {
				targetMessageId: params.targetMessageId
			});
			logger.debug('streaming-service', 'Available messages', {
				messages: this.messages.map((m) => ({
					id: m.id,
					backend_id: m.backend_id,
					sender: m.sender
				}))
			});

			const existingMessageIndex = this.messages.findIndex(
				(msg) => msg.id === params.targetMessageId || msg.backend_id === params.targetMessageId
			);
			if (existingMessageIndex === -1) {
				logger.error('streaming-service', 'Target message not found for variant update', {
					targetMessageId: params.targetMessageId
				});
				throw new Error(`Target message ${params.targetMessageId} not found for variant update`);
			}

			logger.debug('streaming-service', 'Found target message', {
				index: existingMessageIndex
			});

			// Update the existing message in place to preserve object identity and variant metadata
			const existingMessage = this.messages[existingMessageIndex];
			logger.debug('streaming-service', 'Preserving variant metadata', {
				variant_count: existingMessage.variant_count,
				current_variant_index: existingMessage.current_variant_index
			});

			// Replace message object entirely to ensure Svelte reactivity (not in-place modification)
			this.messages[existingMessageIndex] = {
				...existingMessage, // Spread all existing properties
				content: '', // Clear content - will be filled when buffering completes
				displayedContent: '', // Clear displayed content - will animate from empty
				isAnimating: false, // Keep false - animation starts later
				isRegenerating: true, // Flag to show loading indicator during regeneration
				error: undefined, // Clear any existing error
				contentVersion: 0, // Initialize for Svelte 5 reactivity
				retryable: false // Clear retry state
				// variant_count and current_variant_index preserved from spread
			};
			// Force Svelte reactivity by reassigning the array
			this.messages = [...this.messages];

			// Use the new message reference
			assistantMessage = this.messages[existingMessageIndex];

			assistantMessageId = assistantMessage.id;
			logger.debug('streaming-service', 'Using existing message ID for variant', {
				messageId: assistantMessageId
			});
		} else {
			// New message mode: Create new assistant message
			logger.debug('streaming-service', 'Creating new message (no targetMessageId provided)');
			assistantMessage = {
				id: crypto.randomUUID(),
				content: '', // Will be filled when buffering completes
				displayedContent: '', // Will animate from empty to full content
				sender: 'assistant',
				created_at: new Date().toISOString(),
				isAnimating: false, // Will start animating after buffering
				contentVersion: 0, // Initialize for Svelte 5 reactivity
				shouldAnimate: true // New streaming message should animate
			};
			this.messages = [...this.messages, assistantMessage];
			assistantMessageId = assistantMessage.id;
			logger.debug('streaming-service', 'Created new message', {
				messageId: assistantMessageId
			});
		}

		// Track the current assistant message ID
		this.currentAssistantMessageId = assistantMessageId;

		// Initialize buffer for this message
		this.messageBuffers.set(assistantMessageId, {
			content: '',
			chunks: {},
			isComplete: false
		});

		try {
			await this.startEventStream(
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
		} catch (_error) {
			this.handleConnectionError(_error as Error);
		}
	}

	/**
	 * Start the event stream using sveltekit-sse
	 */
	private async startEventStream(
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
		const baseUrl = (env.PUBLIC_API_URL || '').trim();
		const apiUrl = `${baseUrl}/api/chat/${params.chatId}/generate`;

		// For regeneration/variants, don't append the user message again since it's already in history
		// For new messages, append the user message to complete the conversation
		const historyToSend = params.isRegeneration
			? params.history
			: [...params.history, { role: 'user' as const, content: params.userMessage }];

		// Validate history before sending request
		if (historyToSend.length === 0) {
			throw new Error('History cannot be empty');
		}

		const lastMessage = historyToSend[historyToSend.length - 1];
		if (lastMessage.role !== 'user') {
			logger.error('streaming-service', 'Invalid history: Last message must be from user', {
				historyLength: historyToSend.length,
				lastMessage,
				isRegeneration: params.isRegeneration,
				fullHistory: historyToSend
			});
			throw new Error(
				`Invalid conversation history: Last message must be from 'user', but got '${lastMessage.role}'. This is a frontend bug that should be reported.`
			);
		}

		logger.debug('streaming-service', 'History validation passed', {
			historyLength: historyToSend.length,
			lastMessageRole: lastMessage.role,
			isRegeneration: params.isRegeneration
		});

		const requestBody = {
			history: historyToSend,
			model: params.model,
			agent_mode: params.agentMode,
			analysis_mode: params.analysisMode, // Pass analysis mode for regeneration
			guidance: params.guidance, // Pass optional guidance for regeneration steering
			variant_of: params.variantOf // Pass variant_of for creating variants
		};

		logger.debug('streaming-service', 'Starting sveltekit-sse source', { url: apiUrl });

		// Prepare headers - add JWT Bearer token for desktop mode
		const headers: Record<string, string> = {
			'Content-Type': 'application/json',
			Accept: 'text/event-stream'
		};

		// Add JWT Bearer token for desktop mode (bypasses protocol handler)
		if (isInDesktopMode()) {
			const authHeaders = desktopAuth.getAuthHeaders();
			Object.assign(headers, authHeaders);
			logger.debug('streaming-service', 'Desktop mode: Added JWT Bearer token to SSE request');
		}

		try {
			// Initialize sveltekit-sse source
			this.activeConnection = source(apiUrl, {
				options: {
					method: 'POST',
					headers,
					body: JSON.stringify(requestBody)
				},
				close: () => {
					logger.debug('streaming-service', 'Source closed');
					this.handleConnectionClose();
				},
				error: (e) => {
					// If it's a connection error, we might want to retry
					const errorObj = e instanceof Error ? e : new Error(String(e));
					logger.error('streaming-service', 'Source error', errorObj);

					if (this.shouldRetry(errorObj)) {
						const delay = this.calculateRetryDelay();
						logger.debug('streaming-service', 'Retrying after error', {
							delayMs: delay,
							attempt: this.retryCount,
							maxRetries: this.config.maxRetries
						});
						setTimeout(() => {
							this.startEventStream(params, assistantMessageId).catch((err) => {
								this.handleConnectionError(err);
							});
						}, delay);
					} else {
						this.handleStreamError(errorObj, assistantMessageId);
					}
				}
			});

			this.connectionStatus = 'open';
			this.retryCount = 0; // Reset retry count on successful connection
			logger.debug('streaming-service', 'Stream connection established');

			// Subscribe to events
			const contentUnsub = this.activeConnection.select('content').subscribe((data) => {
				if (data) {
					this.handleStreamMessage({ event: 'content', data }, assistantMessageId);
				}
			});
			this.activeSubscriptions.push(contentUnsub);

			const errorUnsub = this.activeConnection.select('error').subscribe((data) => {
				if (data) {
					this.handleStreamMessage({ event: 'error', data }, assistantMessageId);
				}
			});
			this.activeSubscriptions.push(errorUnsub);

			const doneUnsub = this.activeConnection.select('done').subscribe((data) => {
				if (data) {
					this.handleStreamMessage({ event: 'done', data }, assistantMessageId);
				}
			});
			this.activeSubscriptions.push(doneUnsub);

			const savedUnsub = this.activeConnection.select('message_saved').subscribe((data) => {
				if (data) {
					this.handleStreamMessage({ event: 'message_saved', data }, assistantMessageId);
				}
			});
			this.activeSubscriptions.push(savedUnsub);

			const tokenUnsub = this.activeConnection.select('token_usage').subscribe((data) => {
				if (data) {
					this.handleStreamMessage({ event: 'token_usage', data }, assistantMessageId);
				}
			});
			this.activeSubscriptions.push(tokenUnsub);

			const gameStateUnsub = this.activeConnection.select('game_state').subscribe((data) => {
				if (data) {
					this.handleStreamMessage({ event: 'game_state', data }, assistantMessageId);
				}
			});
			this.activeSubscriptions.push(gameStateUnsub);
		} catch (error) {
			logger.error(
				'streaming-service',
				'Failed to initialize sveltekit-sse source',
				error as Error
			);
			this.handleConnectionError(error as Error);
		}
	}

	/**
	 * Handle incoming stream messages with sophisticated parsing
	 */
	private handleStreamMessage(
		_event: { event: string; data: string },
		assistantMessageId: string
	): void {
		try {
			switch (_event.event) {
				case 'content':
					logger.debug('streaming-service', 'Content event received', {
						dataLength: _event.data?.length
					});
					if (_event.data) {
						try {
							// Parse multiple JSON chunks that may be concatenated in a single SSE event
							const chunks = this.parseMultipleJsonChunks(_event.data);

							const messageId = this.currentAssistantMessageId || assistantMessageId;
							const messageBuffer = this.messageBuffers.get(messageId);

							if (!messageBuffer) {
								logger.warn('streaming-service', 'No buffer found for message', { messageId });
								break;
							}

							// Process each parsed chunk
							for (const chunk of chunks) {
								const { index, content, checksum } = chunk;

								// Verify checksum
								const calculatedChecksum = this.calculateChecksum(content);
								if (calculatedChecksum !== checksum) {
									logger.error('streaming-service', 'Checksum mismatch for chunk', {
										index,
										expected: checksum,
										calculated: calculatedChecksum
									});
								}

								// Store chunk in buffer
								messageBuffer.chunks[index] = content;
							}

							// Reconstruct content from all available chunks
							this.reconstructContent(messageId);
						} catch (_e) {
							logger.error('streaming-service', 'Failed to parse structured chunks', {
								error: _e as Error,
								rawData: _event.data
							});
							// For fallback, still buffer the raw content
							const messageId = this.currentAssistantMessageId || assistantMessageId;
							const messageBuffer = this.messageBuffers.get(messageId);
							if (messageBuffer) {
								messageBuffer.content += _event.data;
								// Update message progressively so TypewriterMessage can see content
								this.updateMessageContentProgressive(messageId);
							}
						}
					}
					break;

				case 'error':
					this.handleStreamError(new Error(_event.data), assistantMessageId);
					break;

				case 'done':
					if (_event.data === '[DONE]') {
						// NEW ARCHITECTURE: Mark buffer as complete and start animation when ready
						const messageId = this.currentAssistantMessageId || assistantMessageId;
						const messageBuffer = this.messageBuffers.get(messageId);

						if (messageBuffer) {
							messageBuffer.isComplete = true;
							logger.debug('streaming-service', 'Message buffer complete', {
								messageId,
								totalLength: messageBuffer.content.length
							});

							// Update message state to indicate streaming is done
							const message = this.messages.find((msg) => msg.id === messageId);
							if (message) {
								// Ensure final content is synced
								message.isRegenerating = false;
							}
						}

						// Mark DONE as received
						this.connectionCloseState.doneReceived = true;
						logger.debug('streaming-service', 'DONE signal received');

						// Set a fallback timeout to close connection if other events don't arrive
						// Increased to 5 seconds to allow for database operations and latency
						this.connectionCloseState.closeTimeoutId = setTimeout(() => {
							logger.warn('streaming-service', 'Connection close timeout reached, forcing close');
							this.connectionCloseState.shouldClose = true;
							this.tryCloseConnection();
						}, 5000);

						// Try to close if we have everything
						this.tryCloseConnection();
					}
					break;

				case 'game_state':
					if (_event.data) {
						try {
							const gameState = JSON.parse(_event.data);
							this.handleGameStateUpdateEvent(gameState);
						} catch (e) {
							logger.error('streaming-service', 'Failed to parse game state', e as Error);
						}
					}
					break;

				case 'message_saved':
					try {
						const savedData = JSON.parse(_event.data);
						logger.debug('streaming-service', 'Message saved event received', savedData);

						const messageId = this.currentAssistantMessageId || assistantMessageId;
						const message = this.messages.find((msg) => msg.id === messageId);

						if (message) {
							// Update with backend ID and final metadata
							message.backend_id = savedData.id;
							message.model_name = savedData.model_name;
							message.created_at = savedData.created_at;

							// Update buffer with metadata
							const buffer = this.messageBuffers.get(messageId);
							if (buffer) {
								buffer.backend_id = savedData.id;
								buffer.model_name = savedData.model_name;
							}
						}

						this.connectionCloseState.messageSavedReceived = true;
						this.tryCloseConnection();
					} catch (e) {
						logger.error('streaming-service', 'Failed to parse message_saved event', e as Error);
					}
					break;

				case 'token_usage':
					try {
						const usageData = JSON.parse(_event.data);
						logger.debug('streaming-service', 'Token usage event received', usageData);

						const messageId = this.currentAssistantMessageId || assistantMessageId;
						const message = this.messages.find((msg) => msg.id === messageId);

						if (message) {
							message.prompt_tokens = usageData.prompt_tokens;
							message.completion_tokens = usageData.completion_tokens;

							// Update buffer with metadata
							const buffer = this.messageBuffers.get(messageId);
							if (buffer) {
								buffer.prompt_tokens = usageData.prompt_tokens;
								buffer.completion_tokens = usageData.completion_tokens;
							}
						}

						this.connectionCloseState.tokenUsageReceived = true;
						this.tryCloseConnection();
					} catch (e) {
						logger.error('streaming-service', 'Failed to parse token_usage event', e as Error);
					}
					break;
			}
		} catch (error) {
			logger.error('streaming-service', 'Error handling stream message', error as Error);
		}
	}

	/**
	 * Handle stream errors with sophisticated recovery
	 */
	private handleStreamError(error: Error, messageId: string): void {
		logger.error('streaming-service', 'Stream error occurred', error);

		// Update message with error state
		const message = this.messages.find((msg) => msg.id === messageId);
		if (message) {
			message.error = error.message;
			message.isAnimating = false;
			message.isRegenerating = false;
			message.status = 'failed';
		}

		this.currentError = {
			message: error.message,
			type: 'server',
			retryable: false,
			originalError: error
		};

		this.connectionStatus = 'error';
		this.cleanupConnection();
	}

	/**
	 * Handle connection setup errors
	 */
	private handleConnectionError(error: Error): void {
		logger.error('streaming-service', 'Connection error', error);

		this.currentError = {
			message: error.message,
			type: 'network',
			retryable: true,
			originalError: error
		};

		this.connectionStatus = 'error';
		this.cleanupConnection();
	}

	/**
	 * Handle authentication errors
	 */
	private handleAuthError(): void {
		logger.error('streaming-service', 'Authentication error');

		this.currentError = {
			message: 'Authentication failed',
			type: 'auth',
			retryable: false
		};

		this.connectionStatus = 'error';
		this.cleanupConnection();
	}

	/**
	 * Handle connection closure
	 */
	private handleConnectionClose(): void {
		// Only update status if not already in error state
		if (this.connectionStatus !== 'error') {
			this.connectionStatus = 'closed';
		}

		// Ensure we clean up subscriptions
		this.activeSubscriptions.forEach((unsub) => unsub());
		this.activeSubscriptions = [];
		this.activeConnection = null;
	}

	/**
	 * Clean up connection resources
	 */
	private cleanupConnection(): void {
		if (this.activeConnection) {
			this.activeConnection.close();
			this.activeConnection = null;
		}

		this.activeSubscriptions.forEach((unsub) => unsub());
		this.activeSubscriptions = [];

		if (this.connectionCloseState.closeTimeoutId) {
			clearTimeout(this.connectionCloseState.closeTimeoutId);
			this.connectionCloseState.closeTimeoutId = null;
		}
	}

	/**
	 * Determine if an error is retryable
	 */
	private shouldRetry(error: Error): boolean {
		// Don't retry if we've exceeded max retries
		if (this.retryCount >= this.config.maxRetries) {
			return false;
		}

		// Don't retry auth errors or validation errors
		if (
			error.message.includes('Authentication failed') ||
			error.message.includes('Backend validation failed')
		) {
			return false;
		}

		// Retry network errors and server errors (5xx)
		return true;
	}

	/**
	 * Calculate retry delay with exponential backoff
	 */
	private calculateRetryDelay(): number {
		this.retryCount++;
		if (!this.config.enableBackoff) {
			return this.config.retryDelayMs;
		}
		return this.config.retryDelayMs * Math.pow(2, this.retryCount - 1);
	}

	/**
	 * Interrupt the current stream
	 */
	public interrupt(): void {
		logger.debug('streaming-service', 'Interrupting stream...');
		this.disconnect();
	}

	/**
	 * Disconnect and clean up
	 */
	public disconnect(): void {
		logger.debug('streaming-service', 'Disconnecting...');
		this.cleanupConnection();
		this.connectionStatus = 'closed';
	}

	/**
	 * Clear all messages
	 */
	public clearMessages(): void {
		this.messages = [];
		this.messageBuffers.clear();
		this.currentAssistantMessageId = null;
		this.currentChatId = null;
	}
}

// Export singleton instance
export const streamingService = new StreamingService();
