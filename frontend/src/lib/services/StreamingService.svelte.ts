// StreamingService.ts - Decoupled Svelte 5 Streaming Client with Robust Error Handling
import { fetchEventSource, type EventSourceMessage } from '@microsoft/fetch-event-source';
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
	 * Start the event stream using @microsoft/fetch-event-source
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

		logger.debug('streaming-service', 'Starting fetchEventSource', { url: apiUrl });

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

		await fetchEventSource(apiUrl, {
			method: 'POST',
			headers,
			credentials: 'include',
			body: JSON.stringify(requestBody),
			signal: this.abortController?.signal,

			onopen: async (response) => {
				logger.debug('streaming-service', 'fetchEventSource onopen called', {
					status: response.status,
					contentType: response.headers.get('content-type')
				});
				if (response.ok && response.headers.get('content-type')?.includes('text/event-stream')) {
					this.connectionStatus = 'open';
					this.retryCount = 0; // Reset retry count on successful connection
					logger.debug('streaming-service', 'Stream connection established');
				} else if (response.status === 401) {
					this.handleAuthError();
					throw new Error('Authentication failed');
				} else {
					const errorText = await response.text().catch(() => 'Unknown error');

					// Handle different types of 400 errors
					if (response.status === 400) {
						if (
							errorText.includes("last message in the payload's history must be from the 'user'")
						) {
							// This is a validation error - don't retry, fail immediately
							logger.error(
								'streaming-service',
								'Backend validation error: History validation failed'
							);
							const error = new Error(
								`Backend validation failed: ${errorText}. This suggests a frontend bug in history construction.`
							);
							// Don't mark for cleanup - just fail immediately
							throw error;
						} else if (errorText.includes('Daily message limit reached')) {
							// Daily limit error - don't retry, preserve original message for user display
							logger.error('streaming-service', 'Daily message limit reached');
							const error = new Error(errorText);
							error.name = 'DailyLimitError';
							throw error;
						} else {
							// Other 400 errors might be retryable (e.g. temporary server issues)
							throw new Error(
								`Client error: ${response.status} ${response.statusText} - ${errorText}`
							);
						}
					} else if (response.status >= 500) {
						// Server errors are typically retryable
						throw new Error(
							`Server error: ${response.status} ${response.statusText} - ${errorText}`
						);
					} else {
						// Other client errors (4xx) are typically not retryable
						throw new Error(
							`Connection failed: ${response.status} ${response.statusText} - ${errorText}`
						);
					}
				}
			},

			onmessage: (_event: EventSourceMessage) => {
				this.handleStreamMessage(_event, assistantMessageId);
			},

			onclose: () => {
				logger.debug('streaming-service', 'fetchEventSource onclose called');
				// Only perform cleanup if the connection was actually closed
				// Note: This can be called when we abort the connection ourselves or when the server closes

				// Clear any pending close timeout
				if (this.connectionCloseState.closeTimeoutId) {
					clearTimeout(this.connectionCloseState.closeTimeoutId);
					this.connectionCloseState.closeTimeoutId = null;
				}

				// Mark as closed if not already
				if (this.connectionStatus !== 'closed' && this.connectionStatus !== 'error') {
					logger.debug('streaming-service', 'Connection closed by server or client');
					this.connectionStatus = 'closed';
				}
			},

			onerror: (error) => {
				logger.error('streaming-service', 'fetchEventSource onerror called', error as Error);

				// Determine if we should retry
				if (this.shouldRetry(error)) {
					const delay = this.calculateRetryDelay();
					logger.debug('streaming-service', 'Retrying after error', {
						delayMs: delay,
						attempt: this.retryCount,
						maxRetries: this.config.maxRetries
					});
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
	private handleStreamMessage(_event: EventSourceMessage, assistantMessageId: string): void {
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
							// Process any remaining chunks
							this.reconstructContent(messageId);

							// Mark buffer as complete
							messageBuffer.isComplete = true;

							logger.debug('streaming-service', 'DONE received for message', {
								messageId: messageId.slice(-8),
								contentLength: messageBuffer.content.length
							});

							// Update message with complete content
							this.updateMessageContent(messageId);
						}

						// Mark DONE as received and set up fallback timeout
						this.connectionCloseState.doneReceived = true;
						logger.debug(
							'streaming-service',
							'DONE received, keeping connection open for token_usage events'
						);

						// Set up a fallback timeout in case token_usage event doesn't arrive
						this.connectionCloseState.closeTimeoutId = setTimeout(() => {
							logger.warn(
								'streaming-service',
								'Timeout waiting for token_usage event, closing connection anyway'
							);
							this.connectionCloseState.shouldClose = true;
							this.tryCloseConnection();
						}, 3000); // 3 second timeout

						// Try to close immediately if conditions are already met
						this.tryCloseConnection();
					}
					break;

				case 'message_saved':
					this.handleMessageSaved(_event.data, assistantMessageId);
					// Mark message_saved as received and try to close connection
					this.connectionCloseState.messageSavedReceived = true;
					logger.debug(
						'streaming-service',
						'message_saved event received, checking if we can close connection'
					);
					this.tryCloseConnection();
					break;

				case 'token_usage': {
					logger.debug('streaming-service', 'Processing token_usage event', {
						data: _event.data
					});
					// Use the tracked message ID for token usage
					const messageIdForTokens = this.currentAssistantMessageId || assistantMessageId;
					logger.debug('streaming-service', 'TOKEN EVENT', {
						originalId: assistantMessageId,
						currentTrackedId: this.currentAssistantMessageId,
						usingId: messageIdForTokens
					});
					this.handleTokenUsage(_event.data, messageIdForTokens);

					// Mark token_usage as received and try to close connection
					this.connectionCloseState.tokenUsageReceived = true;
					logger.debug(
						'streaming-service',
						'token_usage event received, checking if we can close connection'
					);
					this.tryCloseConnection();
					break;
				}

				case 'reasoning_chunk':
					// Handle reasoning chunks if needed
					logger.debug('streaming-service', 'Reasoning chunk received', {
						data: _event.data
					});
					break;

				default:
					// Handle default SSE message events (event type is empty string)
					// Some servers send content as default events instead of named events
					if (_event.data && _event.data !== '[DONE]') {
						const messageId = this.currentAssistantMessageId || assistantMessageId;
						const messageBuffer = this.messageBuffers.get(messageId);

						if (messageBuffer) {
							try {
								// Try to parse as structured chunks first
								const chunks = this.parseMultipleJsonChunks(_event.data);
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

								// Update buffer content if we have contiguous chunks
								this.reconstructContent(messageId);
							} catch (_e) {
								// If parsing as JSON fails, treat as raw text content
								// Append directly to buffer (for backends that send plain text)
								messageBuffer.content += _event.data;
								this.updateMessageContentProgressive(messageId);
							}
						} else {
							logger.warn('streaming-service', 'No buffer found for default event', {
								messageId
							});
						}
					}
					break;
			}
		} catch (_error) {
			logger.error('streaming-service', 'Error parsing stream message', _error as Error);
			this.handleStreamError(_error as Error, assistantMessageId);
		}
	}

	/**
	 * NEW ARCHITECTURE: Handle message saved event with buffer updates
	 */
	private handleMessageSaved(_data: string, assistantMessageId: string): void {
		try {
			const messageData = JSON.parse(_data);
			const actualMessageId = messageData.message_id;

			logger.debug('streaming-service', 'handleMessageSaved: Updating message ID', {
				from: assistantMessageId,
				to: actualMessageId
			});

			// NEW: Transfer message buffer to new ID
			const oldMessageBuffer = this.messageBuffers.get(assistantMessageId);
			if (oldMessageBuffer) {
				// Update buffer with backend ID
				oldMessageBuffer.backend_id = actualMessageId;

				// Transfer buffer to new ID (only delete old if different ID)
				this.messageBuffers.set(actualMessageId, oldMessageBuffer);
				if (assistantMessageId !== actualMessageId) {
					this.messageBuffers.delete(assistantMessageId);
					logger.debug('streaming-service', 'Transferred message buffer', {
						from: assistantMessageId,
						to: actualMessageId
					});
				} else {
					logger.debug('streaming-service', 'Updated buffer for variant (same ID)', {
						messageId: actualMessageId
					});
				}

				// Try to start animation if conditions are now met
				this.updateMessageContent(actualMessageId);
			}

			// Update tracked ID
			this.currentAssistantMessageId = actualMessageId;

			// Extract variant metadata from the message_saved event
			const variantCount = messageData.variant_count ?? 0;
			const currentVariantIndex = messageData.current_variant_index ?? 0;

			// Update message ID and variant metadata in messages array while preserving object identity
			let _messageUpdated = false;
			for (const msg of this.messages) {
				// For variants, we need to match by either frontend ID or backend ID
				if (msg.id === assistantMessageId || msg.backend_id === assistantMessageId) {
					logger.debug('streaming-service', 'Updating message backend_id and variant metadata', {
						from: assistantMessageId,
						to: actualMessageId,
						variant_count: variantCount,
						current_variant_index: currentVariantIndex
					});

					// Update the existing object in place to maintain identity and reactivity
					// IMPORTANT: Keep msg.id stable (frontend ID) to prevent component remount
					// Only update backend_id to track the actual backend ID
					msg.backend_id = actualMessageId;
					msg.variant_count = variantCount;
					msg.current_variant_index = currentVariantIndex;

					logger.debug('streaming-service', 'Updated message object in place', {
						id: msg.id,
						variant_count: msg.variant_count,
						current_variant_index: msg.current_variant_index
					});
					_messageUpdated = true;
					break;
				}
			}

			// Force Svelte reactivity if we updated a message
			if (_messageUpdated) {
				this.messages = [...this.messages];
			}

			// Verify the update took effect
			const updatedMessage = this.messages.find((msg) => msg.backend_id === actualMessageId);
			logger.debug('streaming-service', 'Verification - message in array', {
				found: !!updatedMessage,
				id: updatedMessage?.id,
				variant_count: updatedMessage?.variant_count,
				current_variant_index: updatedMessage?.current_variant_index
			});

			// Additional validation for variant metadata
			if (updatedMessage && (variantCount > 0 || currentVariantIndex > 0)) {
				const msgVariantCount = updatedMessage.variant_count ?? 0;
				const msgCurrentIndex = updatedMessage.current_variant_index ?? 0;
				logger.debug('streaming-service', 'VARIANT VALIDATION - Message has variant data', {
					messageId: actualMessageId,
					variant_count: msgVariantCount,
					current_variant_index: msgCurrentIndex,
					shouldShowChevrons: msgVariantCount > 0,
					displayString:
						msgVariantCount > 0 ? `${msgCurrentIndex + 1}/${msgVariantCount}` : 'no variants'
				});
			}
		} catch (_error) {
			logger.error('streaming-service', 'Failed to parse message saved data', _error as Error);
		}
	}

	/**
	 * NEW ARCHITECTURE: Handle token usage information with buffer updates
	 */
	private handleTokenUsage(_data: string, assistantMessageId: string): void {
		try {
			const tokenData = JSON.parse(_data);
			logger.debug('streaming-service', 'handleTokenUsage: Processing tokens for message', {
				messageId: assistantMessageId,
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

				logger.debug('streaming-service', 'Stored tokens in buffer', {
					messageId: assistantMessageId
				});

				// Try to start animation if conditions are now met
				this.updateMessageContent(assistantMessageId);
			} else {
				logger.warn('streaming-service', 'No buffer found for message, updating message directly', {
					messageId: assistantMessageId
				});

				// Fallback: Update message directly if no buffer
				// CRITICAL: Use in-place mutation to preserve Svelte 5 proxy chain
				const message = this.messages.find((msg) => msg.id === assistantMessageId);
				if (message) {
					message.prompt_tokens = tokenData.prompt_tokens;
					message.completion_tokens = tokenData.completion_tokens;
					message.model_name = tokenData.model_name;
				}
			}
		} catch (_error) {
			logger.error('streaming-service', 'Failed to parse token usage data', _error as Error);
		}
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
		} else if (error.name === 'DailyLimitError') {
			// Daily message limit reached - not retryable
			streamingError = {
				message: error.message,
				type: 'server',
				retryable: false,
				originalError: error
			};
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
		// CRITICAL: Use in-place mutation to preserve Svelte 5 proxy chain
		if (assistantMessageId) {
			const message = this.messages.find((msg) => msg.id === assistantMessageId);
			if (message) {
				message.isAnimating = false;
				message.isRegenerating = false;
				message.error = streamingError.message;
				message.retryable = streamingError.retryable;
			}
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
	private shouldRetry(error: unknown): boolean {
		if (this.retryCount >= this.config.maxRetries) {
			return false;
		}

		const err = error as unknown;
		// Type guard to check if error has expected properties
		const isErrorWithName = (e: unknown): e is { name: string } =>
			typeof e === 'object' &&
			e !== null &&
			'name' in e &&
			typeof (e as { name: unknown }).name === 'string';
		const isErrorWithMessage = (e: unknown): e is { message: string } =>
			typeof e === 'object' &&
			e !== null &&
			'message' in e &&
			typeof (e as { message: unknown }).message === 'string';

		if (isErrorWithName(err) && err.name === 'AbortError') {
			return false;
		}

		// Don't retry auth errors
		if (
			isErrorWithMessage(err) &&
			(err.message.includes('401') || err.message.includes('Authentication'))
		) {
			return false;
		}

		// Don't retry daily limit errors
		if (
			(isErrorWithName(err) && err.name === 'DailyLimitError') ||
			(isErrorWithMessage(err) && err.message.includes('Daily message limit reached'))
		) {
			logger.warn('streaming-service', 'Not retrying daily limit error', {
				message: isErrorWithMessage(err) ? err.message : 'Unknown error'
			});
			return false;
		}

		// Don't retry validation errors - these are frontend bugs that need to be fixed, not retried
		if (
			isErrorWithMessage(err) &&
			(err.message.includes('last message') ||
				err.message.includes('Invalid conversation history') ||
				err.message.includes('Backend validation failed'))
		) {
			logger.warn('streaming-service', 'Not retrying validation error', {
				message: err.message
			});
			return false;
		}

		// Don't retry most 4xx client errors (except some specific cases)
		if (
			isErrorWithMessage(err) &&
			err.message.includes('Connection failed:') &&
			err.message.includes('4')
		) {
			// Parse the status code to be more specific
			const statusMatch = err.message.match(/(\d{3})/);
			if (statusMatch) {
				const statusCode = parseInt(statusMatch[1]);
				if (statusCode >= 400 && statusCode < 500 && statusCode !== 429) {
					logger.warn('streaming-service', 'Not retrying client error', {
						statusCode,
						message: err.message
					});
					return false;
				}
			}
		}

		// Retry server errors (5xx) and rate limiting (429)
		if (
			isErrorWithMessage(err) &&
			(err.message.includes('Server error:') || err.message.includes('429'))
		) {
			logger.debug('streaming-service', 'Retrying server error or rate limit', {
				message: err.message
			});
			this.retryCount++;
			return true;
		}

		// Retry network errors and timeouts
		if (
			(isErrorWithMessage(err) &&
				(err.message.includes('timeout') || err.message.includes('network'))) ||
			(isErrorWithName(err) && err.name === 'TypeError')
		) {
			logger.debug('streaming-service', 'Retrying network/timeout error', {
				message: isErrorWithMessage(err) ? err.message : 'Unknown error'
			});
			this.retryCount++;
			return true;
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
	 * Remove a failed assistant message that was created but never successfully started streaming
	 */
	private removeFailedAssistantMessage(messageId: string): void {
		logger.debug('streaming-service', 'Removing failed assistant message', {
			messageId
		});

		// Remove from messages array
		this.messages = this.messages.filter((msg) => msg.id !== messageId);

		// Clean up associated buffers and state
		this.messageBuffers.delete(messageId);

		// Clear animation state
		const requestId = this.animationRequestIds.get(messageId);
		if (requestId) {
			cancelAnimationFrame(requestId);
			this.animationRequestIds.delete(messageId);
		}
		const fallbackTimeout = this.animationFallbackTimeouts.get(messageId);
		if (fallbackTimeout) {
			clearTimeout(fallbackTimeout);
			this.animationFallbackTimeouts.delete(messageId);
		}
		this.animationStartTimes.delete(messageId);

		// Clear interval if it exists
		const intervalId = this.animationIntervals.get(messageId);
		if (intervalId) {
			clearInterval(intervalId);
			this.animationIntervals.delete(messageId);
		}

		// Clear current assistant message ID if it matches
		if (this.currentAssistantMessageId === messageId) {
			this.currentAssistantMessageId = null;
		}
	}

	/**
	 * Interrupt all streaming operations (SSE + animations) immediately
	 */
	public interrupt(): void {
		logger.debug('streaming-service', 'Interrupting all streaming operations');

		// Stop SSE connection
		if (this.abortController) {
			this.abortController.abort();
			this.abortController = null;
		}

		// Collect all animating message IDs from both tracking systems BEFORE clearing
		const allAnimatingMessageIds = new Set([
			...this.animationIntervals.keys(),
			...this.animationRequestIds.keys(),
			...this.animationStartTimes.keys()
		]);

		// Stop all timestamp-based animations first
		for (const [messageId, requestId] of this.animationRequestIds) {
			logger.debug('streaming-service', 'Canceling requestAnimationFrame for message', {
				messageId: messageId.slice(-8)
			});
			cancelAnimationFrame(requestId);
		}
		this.animationRequestIds.clear();

		// Stop all local animations immediately
		for (const [messageId, intervalId] of this.animationIntervals) {
			logger.debug('streaming-service', 'Stopping setInterval animation for message', {
				messageId: messageId.slice(-8)
			});
			clearInterval(intervalId);
		}

		// Show full content for all animating messages
		for (const messageId of allAnimatingMessageIds) {
			logger.debug('streaming-service', 'Showing full content for message', {
				messageId: messageId.slice(-8)
			});

			// Immediately show all buffered content without animation
			const buffer = this.messageBuffers.get(messageId);
			if (buffer && buffer.content) {
				this.messages = this.messages.map((msg) => {
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

		// Clear all animation intervals and tracking
		this.animationIntervals.clear();
		this.animationStartTimes.clear();

		// Ensure any remaining messages are marked as not animating
		this.messages = this.messages.map((msg) => {
			if (msg.isAnimating) {
				return { ...msg, isAnimating: false };
			}
			return msg;
		});

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

		// Clear all animations
		for (const [_messageId, intervalId] of this.animationIntervals) {
			clearInterval(intervalId);
		}
		this.animationIntervals.clear();

		// Clear timestamp-based animation tracking
		for (const [_messageId, requestId] of this.animationRequestIds) {
			cancelAnimationFrame(requestId);
		}
		this.animationRequestIds.clear();
		this.animationStartTimes.clear();

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
	 * Stop the current streaming message
	 * Useful for user-initiated cancellation
	 */
	public stopCurrentStream(): void {
		if (!this.currentAssistantMessageId) {
			logger.warn('streaming-service', 'No current stream to stop');
			return;
		}

		logger.debug('streaming-service', 'Stopping current stream', {
			messageId: this.currentAssistantMessageId
		});

		// Close the SSE connection
		if (this.abortController) {
			this.abortController.abort();
			this.abortController = null;
		}

		// Mark the current message buffer as complete
		const buffer = this.messageBuffers.get(this.currentAssistantMessageId);
		if (buffer) {
			buffer.isComplete = true;

			// Update message with current buffered content and mark as not animating
			this.messages = this.messages.map((msg) => {
				if (msg.id === this.currentAssistantMessageId) {
					return {
						...msg,
						content: buffer.content,
						displayedContent: buffer.content,
						isAnimating: false,
						shouldAnimate: false, // No animation for stopped streams
						status: 'completed'
					};
				}
				return msg;
			});
		}

		// Reset connection status
		if (this.connectionStatus !== 'idle' && this.connectionStatus !== 'closed') {
			this.connectionStatus = 'closed';
		}
	}

	/**
	 * Clear all messages
	 */
	public clearMessages(): void {
		// Clear all message buffers and animation state
		this.messageBuffers.clear();
		this.animationIntervals.clear();
		this.animationRequestIds.clear();
		this.animationStartTimes.clear();
		this.animationFallbackTimeouts.clear();

		this.messages = [];
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
