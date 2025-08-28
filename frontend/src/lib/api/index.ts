import { Result, err, ok } from 'neverthrow';
import type { ApiError } from '$lib/errors/api';
import { ApiResponseError, ApiNetworkError } from '$lib/errors/api';
import { ENABLE_LOCAL_LLM } from '$lib/utils/features';
import type {
	User,
	Message,
	Vote,
	Suggestion,
	Session,
	AuthUser,
	ScribeChatSession,
	LoginSuccessData,
	Lorebook,
	LorebookEntry,
	CreateLorebookPayload,
	UpdateLorebookPayload,
	CreateLorebookEntryPayload,
	UpdateLorebookEntryPayload,
	LorebookUploadPayload,
	ScribeMinimalLorebook,
	ChatSessionLorebookAssociation,
	EnhancedChatSessionLorebookAssociation,
	CharacterLorebookOverrideResponse,
	Character,
	UserPersona,
	CreateUserPersonaRequest,
	UpdateUserPersonaRequest,
	CreateChatRequest,
	CreateMessageRequest,
	CreateDocumentRequest,
	CreateSuggestionRequest,
	DocumentResponse,
	SessionResponse,
	SuggestedActionsResponse,
	UpdateChatSessionSettingsRequest,
	ChatSessionSettingsResponse,
	UserSettingsResponse,
	UpdateUserSettingsRequest,
	ExpandTextRequest,
	ExpandTextResponse,
	ImpersonateRequest,
	ImpersonateResponse,
	GenerateCharacterFieldRequest,
	GenerateCharacterFieldResponse,
	GenerateCompleteCharacterRequest,
	GenerateCompleteCharacterResponse,
	EnhanceCharacterRequest,
	EnhanceCharacterResponse,
	GenerateLorebookEntriesRequest,
	GenerateLorebookEntriesResponse,
	GenerateLorebookEntryRequest,
	GenerateLorebookEntryResponse,
	ScribeAssistantRequest,
	ScribeAssistantResponse,
	PlayerChronicle,
	PlayerChronicleWithCounts,
	CreateChronicleRequest,
	UpdateChronicleRequest,
	ChronicleEvent,
	CreateEventRequest,
	EventFilter,
	TokenCountRequest,
	TokenCountResponse,
	AgentAnalysisResponse,
	PaginatedMessagesResponse,
	ChatDeletionAnalysisResponse,
	ChronicleAction,
	LlmInfoResponse,
	ModelInfo,
	DownloadProgressInfo,
	DownloadModelRequest,
	DownloadModelResponse,
	ModelRecommendation,
	ModelActionResponse,
	HardwareCapabilities
} from '$lib/types';
import {
	setConnectionError,
	performLogout,
	getHasConnectionError,
	clearConnectionError,
	debugCookies
} from '$lib/auth.svelte'; // Import the new auth store functions
import { browser } from '$app/environment'; // To check if in browser context
import { env } from '$env/dynamic/public';

// Actual API client
class ApiClient {
	private baseUrl: string;
	private fetchFn: typeof fetch = globalThis.fetch;

	constructor(baseUrl: string = '') {
		// Use PUBLIC_API_URL if available, otherwise fall back to relative paths
		// Trim whitespace/newlines that might be added by environment variable processing
		this.baseUrl = (baseUrl || env.PUBLIC_API_URL || '').trim();
	}

	// Method to set custom fetch function (useful for server-side rendering)
	setFetch(fetchFn: typeof fetch) {
		this.fetchFn = fetchFn;
	}

	// Generic fetch method with error handling
	private async fetch<T>(
		endpoint: string,
		options: RequestInit = {},
		fetchFn: typeof fetch = this.fetchFn
	): Promise<Result<T, ApiError>> {
		// Add debug logging for production debugging
		const fullUrl = `${this.baseUrl}${endpoint}`;
		console.log(`[${new Date().toISOString()}] ApiClient.fetch: Making request to ${fullUrl}`, {
			method: options.method || 'GET',
			headers: options.headers,
			credentials: 'include',
			baseUrl: this.baseUrl
		});

		try {
			const response = await fetchFn(fullUrl, {
				...options,
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json',
					...options.headers
				}
			});

			// Log response details for debugging
			console.log(`[${new Date().toISOString()}] ApiClient.fetch: Response received`, {
				url: fullUrl,
				status: response.status,
				statusText: response.statusText,
				headers: Object.fromEntries(response.headers.entries()),
				ok: response.ok
			});

			// Only log non-2xx responses
			if (!response.ok) {
				console.log(
					`[${new Date().toISOString()}] ApiClient.fetch: Response status ${response.status} for ${endpoint}`
				);
			}
			if (!response.ok) {
				// Handle 401 Unauthorized specifically
				if (response.status === 401) {
					// Check if this is a DEK missing error (specific message indicating server restart)
					let isDekMissingError = false;
					try {
						const errorResponse = await response.clone().json();
						isDekMissingError =
							errorResponse.error &&
							errorResponse.error.includes('Data Encryption Key not available');
					} catch {
						// If we can't parse the error, fall back to general handling
					}

					// Only update auth store and redirect if we're in the browser
					if (browser) {
						if (isDekMissingError) {
							console.log(
								`[${new Date().toISOString()}] ApiClient.fetch: 401 DEK Missing. Server likely restarted, performing comprehensive logout.`
							);
						} else {
							console.log(
								`[${new Date().toISOString()}] ApiClient.fetch: 401 Unauthorized. Session expired, performing comprehensive logout.`
							);
						}
						// Use comprehensive logout that clears both state and cookies
						await performLogout('expired', true);
					} else {
						console.log(
							`[${new Date().toISOString()}] ApiClient.fetch: 401 Unauthorized on server-side fetch. Not redirecting.`
						);
					}
				}

				let errorData = { message: 'An unknown error occurred' };
				let isProxyError = false;
				try {
					errorData = await response.json();
				} catch (parseError) {
					console.error(
						`[${new Date().toISOString()}] ApiClient.fetch: Failed to parse error JSON for ${endpoint}`,
						parseError
					);
					// If we can't parse the JSON and it's a 500+ error, it's likely a proxy error (backend offline)
					isProxyError = response.status >= 500;
				}

				// Handle proxy errors (Vite dev server can't reach backend) as connection issues
				if (isProxyError && browser) {
					const isAuthEndpoint =
						endpoint.includes('/api/auth/') ||
						endpoint.includes('/api/characters') ||
						endpoint.includes('/api/chats') ||
						endpoint.includes('/api/personas') ||
						endpoint.includes('/api/lorebooks');

					if (isAuthEndpoint) {
						console.log(
							`[${new Date().toISOString()}] ApiClient.fetch: Proxy error ${response.status} on endpoint ${endpoint}. Backend appears to be offline.`
						);
						setConnectionError();
					}
				}
				console.error(
					`[${new Date().toISOString()}] ApiClient.fetch: EXIT - API Error ${response.status}`,
					errorData
				);
				return err(new ApiResponseError(response.status, errorData.message));
			}

			// Check if response is empty (like for a 204 No Content)
			if (response.status === 204) {
				return ok({} as T);
			}

			const data = await response.json();
			// Success logging removed - only log errors

			// If we successfully made a request, clear any connection errors
			if (browser) {
				if (getHasConnectionError()) {
					console.log(
						`[${new Date().toISOString()}] ApiClient.fetch: Server appears to be back online, clearing connection error state.`
					);
					// Clear connection error state
					clearConnectionError();
					window.dispatchEvent(new CustomEvent('auth:connection-restored'));

					// Import initializeAuth dynamically to avoid circular dependency
					import('$lib/auth.svelte').then(({ initializeAuth }) => {
						// Force session revalidation now that server is back
						initializeAuth(true);
					});
				}
			}

			return ok(data as T);
		} catch (error) {
			console.error(
				`[${new Date().toISOString()}] ApiClient.fetch: EXIT - Network/Fetch Error for ${endpoint}`,
				error
			);

			// Check if this is a network connectivity issue
			const isNetworkError =
				error instanceof Error &&
				(error.message.includes('ECONNREFUSED') ||
					error.message.includes('fetch') ||
					error.name === 'TypeError' ||
					error.message.includes('NetworkError') ||
					error.message.includes('Failed to fetch'));

			if (isNetworkError && browser) {
				// For auth-related endpoints, treat network failures as potential auth issues
				// but be less aggressive than for 401s - show a message and let user decide
				const isAuthEndpoint =
					endpoint.includes('/api/auth/') ||
					endpoint.includes('/api/characters') ||
					endpoint.includes('/api/chats') ||
					endpoint.includes('/api/personas') ||
					endpoint.includes('/api/lorebooks');

				if (isAuthEndpoint) {
					console.log(
						`[${new Date().toISOString()}] ApiClient.fetch: Network error on auth endpoint ${endpoint}. Backend may be down.`
					);
					// Set connection error state but don't automatically log out
					setConnectionError();
				}
			}

			return err(
				new ApiNetworkError(
					isNetworkError
						? 'Unable to connect to server. Please check your internet connection or try again later.'
						: 'Network error',
					error as Error
				)
			);
		}
	}

	// Auth methods
	async getUser(fetchFn: typeof fetch = globalThis.fetch): Promise<Result<User, ApiError>> {
		return this.fetch<User>('/api/auth/me', {}, fetchFn);
	}

	async authenticateUser(
		data: { identifier: string; password: string },
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<LoginSuccessData, ApiError>> {
		return this.fetch<LoginSuccessData>(
			'/api/auth/login',
			{
				method: 'POST',
				body: JSON.stringify(data)
			},
			fetchFn
		);
	}

	async getAuthUser(
		data: { email: string },
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<LoginSuccessData, ApiError>> {
		console.warn('getAuthUser called - consider using authenticateUser for standard login flow');
		// This method likely also needs to align with the LoginSuccessData response if it's hitting the same /api/auth/login endpoint
		// For now, assuming it should also return LoginSuccessData. If it's a different flow, this might need adjustment.
		return this.fetch<LoginSuccessData>(
			'/api/auth/login',
			{
				method: 'POST',
				body: JSON.stringify({ identifier: data.email, password: '' }) // Assuming password can be empty for this specific getAuthUser flow
			},
			fetchFn
		);
	}

	async createUser(
		data: { email: string; username: string; password: string },
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<AuthUser, ApiError>> {
		return this.fetch<AuthUser>(
			'/api/auth/register',
			{
				method: 'POST',
				body: JSON.stringify(data)
			},
			fetchFn
		);
	}

	async logout(fetchFn: typeof fetch = globalThis.fetch): Promise<Result<void, ApiError>> {
		return this.fetch<void>(
			'/api/auth/logout',
			{
				method: 'POST'
			},
			fetchFn
		);
	}

	async verifyEmail(
		token: string,
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<{ message: string }, ApiError>> {
		return this.fetch<{ message: string }>(
			'/api/auth/verify-email',
			{
				method: 'POST',
				body: JSON.stringify({ token })
			},
			fetchFn
		);
	}

	// Session methods
	async createSession(
		session: Session,
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<Session, ApiError>> {
		return this.fetch<Session>(
			'/api/auth/session',
			{
				method: 'POST',
				body: JSON.stringify(session)
			},
			fetchFn
		);
	}

	// Updated to call /api/auth/session/current and not take sessionId
	async getSession(
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<SessionResponse, ApiError>> {
		return this.fetch<SessionResponse>('/api/auth/session/current', {}, fetchFn);
	}

	async extendSession(
		sessionId: string,
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<Session, ApiError>> {
		return this.fetch<Session>(
			`/api/auth/session/${sessionId}/extend`,
			{
				method: 'POST'
			},
			fetchFn
		);
	}

	async deleteSession(
		sessionId: string,
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<undefined, ApiError>> {
		return this.fetch<undefined>(
			`/api/auth/session/${sessionId}`,
			{
				method: 'DELETE'
			},
			fetchFn
		);
	}

	async deleteSessionsForUser(
		userId: string,
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<undefined, ApiError>> {
		return this.fetch<undefined>(
			`/api/auth/user/${userId}/sessions`,
			{
				method: 'DELETE'
			},
			fetchFn
		);
	}

	// Chat methods
	async getChats(): Promise<Result<ScribeChatSession[], ApiError>> {
		// Use ScribeChatSession from types.ts if it matches API response
		return this.fetch<ScribeChatSession[]>('/api/chats');
	}

	async getChatsByCharacter(characterId: string): Promise<Result<ScribeChatSession[], ApiError>> {
		return this.fetch<ScribeChatSession[]>(`/api/chats/by-character/${characterId}`);
	}

	// Updated createChat to accept and send character details
	async createChat(data: CreateChatRequest): Promise<Result<ScribeChatSession, ApiError>> {
		// Use ScribeChatSession
		console.log(
			`[${new Date().toISOString()}] ApiClient.createChat: Creating chat with data:`,
			data
		);
		return this.fetch<ScribeChatSession>('/api/chat/create_session', {
			// Use ScribeChatSession
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getChatById(id: string): Promise<Result<ScribeChatSession, ApiError>> {
		// Use ScribeChatSession
		return this.fetch<ScribeChatSession>(`/api/chats/fetch/${id}`); // Fixed type argument
	}

	// Character methods (Added)
	async getCharacters(): Promise<Result<Character[], ApiError>> {
		// Assuming an endpoint exists to list characters, adjust if needed
		return this.fetch<Character[]>('/api/characters');
	}

	async getCharacter(id: string): Promise<Result<Character, ApiError>> {
		console.log(`[${new Date().toISOString()}] ApiClient.getCharacter: Fetching character ${id}`);
		return this.fetch<Character>(`/api/characters/fetch/${id}`);
	}

	async updateCharacter(
		id: string,
		data: Partial<Character>
	): Promise<Result<Character, ApiError>> {
		console.log(
			`[${new Date().toISOString()}] ApiClient.updateCharacter: Updating character ${id}`,
			data
		);
		return this.fetch<Character>(`/api/characters/${id}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	async createCharacter(data: Omit<Character, 'id'>): Promise<Result<Character, ApiError>> {
		console.log(
			`[${new Date().toISOString()}] ApiClient.createCharacter: Creating character`,
			data
		);
		return this.fetch<Character>('/api/characters', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async deleteCharacter(id: string): Promise<Result<void, ApiError>> {
		console.log(
			`[${new Date().toISOString()}] ApiClient.deleteCharacter: Deleting character ${id}`
		);
		return this.fetch<void>(`/api/characters/remove/${id}`, {
			method: 'DELETE'
		});
	}

	async uploadCharacter(file: File): Promise<Result<Character, ApiError>> {
		console.log(
			`[${new Date().toISOString()}] ApiClient.uploadCharacter: Uploading character file ${file.name}`
		);

		const formData = new FormData();
		formData.append('character_card', file);

		try {
			const fullUrl = `${this.baseUrl}/api/characters/upload`;
			console.log(
				`[${new Date().toISOString()}] ApiClient.uploadCharacter: Making multipart request to ${fullUrl}`
			);

			const response = await fetch(fullUrl, {
				method: 'POST',
				body: formData,
				credentials: 'include'
				// Note: Don't set Content-Type header - let browser set it with boundary for multipart
			});

			console.log(`[${new Date().toISOString()}] ApiClient.uploadCharacter: Response received`, {
				url: fullUrl,
				status: response.status,
				statusText: response.statusText,
				ok: response.ok
			});

			if (!response.ok) {
				let errorData = { message: 'An unknown error occurred' };
				try {
					errorData = await response.json();
				} catch (parseError) {
					console.error(
						`[${new Date().toISOString()}] ApiClient.uploadCharacter: Failed to parse error JSON`,
						parseError
					);
				}
				console.error(
					`[${new Date().toISOString()}] ApiClient.uploadCharacter: Upload failed with status ${response.status}`,
					errorData
				);
				return err(new ApiResponseError(response.status, errorData.message));
			}

			const data = await response.json();
			console.log(
				`[${new Date().toISOString()}] ApiClient.uploadCharacter: Upload successful`,
				data
			);
			return ok(data as Character);
		} catch (error) {
			console.error(
				`[${new Date().toISOString()}] ApiClient.uploadCharacter: Network/Fetch Error`,
				error
			);
			return err(
				new ApiNetworkError(
					'Unable to upload character. Please check your connection or try again later.',
					error as Error
				)
			);
		}
	}

	async generateCharacter(payload: { prompt: string }): Promise<Result<Character, ApiError>> {
		console.log(
			`[${new Date().toISOString()}] ApiClient.generateCharacter: Generating character from prompt`
		);
		return this.fetch<Character>('/api/characters/generate', {
			method: 'POST',
			body: JSON.stringify(payload)
		});
	}

	// End Character methods

	async getChatDeletionAnalysis(
		id: string
	): Promise<Result<ChatDeletionAnalysisResponse, ApiError>> {
		return this.fetch<ChatDeletionAnalysisResponse>(`/api/chats/${id}/deletion-analysis`);
	}

	async deleteChatById(
		id: string,
		chronicleAction?: ChronicleAction
	): Promise<Result<void, ApiError>> {
		const queryParams = chronicleAction ? `?chronicle_action=${chronicleAction}` : '';
		return this.fetch<void>(`/api/chats/remove/${id}${queryParams}`, {
			method: 'DELETE'
		});
	}

	async updateChatVisibility(
		id: string,
		visibility: 'public' | 'private'
	): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/${id}/visibility`, {
			method: 'PUT',
			body: JSON.stringify({ visibility })
		});
	}

	async fetchSuggestedActions(chatId: string): Promise<Result<SuggestedActionsResponse, ApiError>> {
		return this.fetch<SuggestedActionsResponse>(`/api/chat/${chatId}/suggested-actions`, {
			method: 'POST',
			body: JSON.stringify({}) // Empty JSON object
		});
	}

	// Message methods
	async getMessagesByChatId(
		chatId: string,
		options?: { limit?: number; cursor?: string }
	): Promise<Result<PaginatedMessagesResponse | Message[], ApiError>> {
		// Support both old and new API responses
		const params = new URLSearchParams();
		if (options?.limit) params.append('limit', options.limit.toString());
		if (options?.cursor) params.append('cursor', options.cursor);
		const query = params.toString() ? `?${params.toString()}` : '';

		// The backend now returns PaginatedMessagesResponse, but we maintain backwards compatibility
		const result = await this.fetch<any>(`/api/chats/${chatId}/messages${query}`);

		if (result.isOk() && result.value) {
			// Check if it's the new paginated response format
			if ('messages' in result.value && 'nextCursor' in result.value) {
				return ok(result.value as PaginatedMessagesResponse);
			}
			// Fallback to array format for backwards compatibility
			return ok(result.value as Message[]);
		}

		return result;
	}

	async getMessageById(messageId: string): Promise<Result<Message, ApiError>> {
		return this.fetch<Message>(`/api/chats/messages/${messageId}`);
	}

	async createMessage(
		chatId: string,
		data: CreateMessageRequest
	): Promise<Result<Message, ApiError>> {
		return this.fetch<Message>(`/api/chats/${chatId}/messages`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async voteMessage(id: string, type: 'up' | 'down'): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/messages/${id}/vote`, {
			method: 'POST',
			body: JSON.stringify({ type_: type })
		});
	}

	async deleteTrailingMessages(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/messages/${id}/trailing`, {
			method: 'DELETE'
		});
	}

	async deleteMessage(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/messages/${id}`, {
			method: 'DELETE'
		});
	}

	// Vote methods
	async getVotesByChatId(chatId: string): Promise<Result<Vote[], ApiError>> {
		return this.fetch<Vote[]>(`/api/chats/${chatId}/votes`);
	}

	// Document methods
	async createDocument(data: CreateDocumentRequest): Promise<Result<DocumentResponse, ApiError>> {
		return this.fetch<DocumentResponse>('/api/documents', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getDocumentsById(id: string): Promise<Result<DocumentResponse[], ApiError>> {
		return this.fetch<DocumentResponse[]>(`/api/documents/${id}`);
	}

	async getLatestDocumentById(id: string): Promise<Result<DocumentResponse, ApiError>> {
		return this.fetch<DocumentResponse>(`/api/documents/${id}/latest`);
	}

	async deleteDocumentsAfterTimestamp(
		id: string,
		timestamp: string
	): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/documents/${id}/timestamp/${timestamp}`, {
			method: 'DELETE'
		});
	}

	// Suggestion methods
	async createSuggestion(data: CreateSuggestionRequest): Promise<Result<Suggestion, ApiError>> {
		return this.fetch<Suggestion>('/api/suggestions', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getSuggestionsByDocumentId(documentId: string): Promise<Result<Suggestion[], ApiError>> {
		return this.fetch<Suggestion[]>(`/api/suggestions/document/${documentId}`);
	}

	// Chat Session Settings methods
	async getChatSessionSettings(
		sessionId: string
	): Promise<Result<ChatSessionSettingsResponse, ApiError>> {
		return this.fetch<ChatSessionSettingsResponse>(`/api/chat/${sessionId}/settings`);
	}

	async updateChatSessionSettings(
		sessionId: string,
		settings: UpdateChatSessionSettingsRequest
	): Promise<Result<ChatSessionSettingsResponse, ApiError>> {
		return this.fetch<ChatSessionSettingsResponse>(`/api/chat/${sessionId}/settings`, {
			method: 'PUT',
			body: JSON.stringify(settings)
		});
	}

	async getAgentAnalysis(
		sessionId: string,
		analysisType?: 'pre_processing' | 'post_processing',
		messageId?: string
	): Promise<Result<AgentAnalysisResponse[], ApiError>> {
		const params = new URLSearchParams();
		if (analysisType) {
			params.append('analysis_type', analysisType);
		}
		if (messageId) {
			params.append('message_id', messageId);
		}
		const queryString = params.toString() ? `?${params.toString()}` : '';
		return this.fetch<AgentAnalysisResponse[]>(
			`/api/chat/${sessionId}/agent-analysis${queryString}`
		);
	}

	// User Persona methods
	async createUserPersona(data: CreateUserPersonaRequest): Promise<Result<UserPersona, ApiError>> {
		return this.fetch<UserPersona>('/api/personas', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getUserPersonas(): Promise<Result<UserPersona[], ApiError>> {
		return this.fetch<UserPersona[]>('/api/personas');
	}

	async getUserPersona(id: string): Promise<Result<UserPersona, ApiError>> {
		return this.fetch<UserPersona>(`/api/personas/${id}`);
	}

	async updateUserPersona(
		id: string,
		data: UpdateUserPersonaRequest
	): Promise<Result<UserPersona, ApiError>> {
		return this.fetch<UserPersona>(`/api/personas/${id}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	async deleteUserPersona(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/personas/${id}`, {
			method: 'DELETE'
		});
	}

	async setDefaultPersona(personaId: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/user-settings/set_default_persona/${personaId}`, {
			method: 'PUT'
		});
	}

	// User Settings methods - for global defaults
	async getUserSettings(): Promise<Result<UserSettingsResponse, ApiError>> {
		return this.fetch<UserSettingsResponse>('/api/user-settings');
	}

	async updateUserSettings(
		settings: UpdateUserSettingsRequest
	): Promise<Result<UserSettingsResponse, ApiError>> {
		return this.fetch<UserSettingsResponse>('/api/user-settings', {
			method: 'PUT',
			body: JSON.stringify(settings)
		});
	}

	async deleteUserSettings(): Promise<Result<void, ApiError>> {
		return this.fetch<void>('/api/user-settings', {
			method: 'DELETE'
		});
	}

	// Lorebook methods
	async getLorebooks(): Promise<Result<Lorebook[], ApiError>> {
		return this.fetch<Lorebook[]>('/api/lorebooks');
	}

	async getLorebook(id: string): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>(`/api/lorebooks/${id}`);
	}

	async createLorebook(data: CreateLorebookPayload): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>('/api/lorebooks', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async updateLorebook(
		id: string,
		data: UpdateLorebookPayload
	): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>(`/api/lorebooks/${id}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	async deleteLorebook(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/lorebooks/${id}`, {
			method: 'DELETE'
		});
	}

	// Lorebook Entry methods
	async getLorebookEntries(lorebookId: string): Promise<Result<LorebookEntry[], ApiError>> {
		return this.fetch<LorebookEntry[]>(`/api/lorebooks/${lorebookId}/entries`);
	}

	async getLorebookEntry(
		lorebookId: string,
		entryId: string
	): Promise<Result<LorebookEntry, ApiError>> {
		return this.fetch<LorebookEntry>(`/api/lorebooks/${lorebookId}/entries/${entryId}`);
	}

	async createLorebookEntry(
		lorebookId: string,
		data: CreateLorebookEntryPayload
	): Promise<Result<LorebookEntry, ApiError>> {
		return this.fetch<LorebookEntry>(`/api/lorebooks/${lorebookId}/entries`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async updateLorebookEntry(
		lorebookId: string,
		entryId: string,
		data: UpdateLorebookEntryPayload
	): Promise<Result<LorebookEntry, ApiError>> {
		return this.fetch<LorebookEntry>(`/api/lorebooks/${lorebookId}/entries/${entryId}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	async deleteLorebookEntry(lorebookId: string, entryId: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/lorebooks/${lorebookId}/entries/${entryId}`, {
			method: 'DELETE'
		});
	}

	// Extract lorebook entries from a chat session
	async extractLorebookEntriesFromChat(
		lorebookId: string,
		data: {
			chat_session_id: string;
			start_message_index?: number;
			end_message_index?: number;
			extraction_model?: string;
		}
	): Promise<Result<{ entries_extracted: number; entries: LorebookEntry[] }, ApiError>> {
		return this.fetch<{ entries_extracted: number; entries: LorebookEntry[] }>(
			`/api/lorebooks/${lorebookId}/extract-from-chat`,
			{
				method: 'POST',
				body: JSON.stringify(data)
			}
		);
	}

	// Chat-Lorebook association methods
	async associateLorebookToChat(
		chatId: string,
		lorebookId: string
	): Promise<Result<ChatSessionLorebookAssociation, ApiError>> {
		return this.fetch<ChatSessionLorebookAssociation>(`/api/chats/${chatId}/lorebooks`, {
			method: 'POST',
			body: JSON.stringify({ lorebook_id: lorebookId })
		});
	}

	async getChatLorebookAssociations(
		chatId: string,
		includeSource = false
	): Promise<Result<EnhancedChatSessionLorebookAssociation[], ApiError>> {
		const url = `/api/chats/${chatId}/lorebooks${includeSource ? '?include_source=true' : ''}`;
		return this.fetch<EnhancedChatSessionLorebookAssociation[]>(url);
	}

	async disassociateLorebookFromChat(
		chatId: string,
		lorebookId: string
	): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/${chatId}/lorebooks/${lorebookId}`, {
			method: 'DELETE'
		});
	}

	// Character lorebook override management
	async setCharacterLorebookOverride(
		chatId: string,
		lorebookId: string,
		action: 'disable' | 'enable'
	): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/${chatId}/lorebooks/${lorebookId}/override`, {
			method: 'PUT',
			body: JSON.stringify({ action })
		});
	}

	async removeCharacterLorebookOverride(
		chatId: string,
		lorebookId: string
	): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/${chatId}/lorebooks/${lorebookId}/override`, {
			method: 'DELETE'
		});
	}

	async getCharacterLorebookOverrides(
		chatId: string
	): Promise<Result<CharacterLorebookOverrideResponse[], ApiError>> {
		return this.fetch<CharacterLorebookOverrideResponse[]>(
			`/api/chats/${chatId}/lorebook-overrides`
		);
	}

	// Import/Export methods
	async importLorebook(data: LorebookUploadPayload): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>('/api/lorebooks/import?format=silly_tavern_full', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async importLorebookScribeMinimal(
		data: ScribeMinimalLorebook
	): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>('/api/lorebooks/import?format=scribe_minimal', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async exportLorebook(
		lorebookId: string,
		format: 'scribe_minimal' | 'silly_tavern_full' = 'silly_tavern_full'
	): Promise<Result<ScribeMinimalLorebook | LorebookUploadPayload, ApiError>> {
		return this.fetch<ScribeMinimalLorebook | LorebookUploadPayload>(
			`/api/lorebooks/${lorebookId}/export?format=${format}`
		);
	}

	// Text expansion method
	async expandText(
		chatId: string,
		originalText: string
	): Promise<Result<ExpandTextResponse, ApiError>> {
		const payload: ExpandTextRequest = { original_text: originalText };
		return this.fetch<ExpandTextResponse>(`/api/chat/${chatId}/expand`, {
			method: 'POST',
			body: JSON.stringify(payload)
		});
	}

	// Impersonate method - generates user actions based on chat context
	async impersonate(chatId: string): Promise<Result<ImpersonateResponse, ApiError>> {
		const payload: ImpersonateRequest = {};
		return this.fetch<ImpersonateResponse>(`/api/chat/${chatId}/impersonate`, {
			method: 'POST',
			body: JSON.stringify(payload)
		});
	}

	// ============================================================================
	// AI Generation Methods (leveraging existing expand/impersonate infrastructure)
	// ============================================================================

	// Generate or enhance a specific character field
	async generateCharacterField(
		request: GenerateCharacterFieldRequest
	): Promise<Result<GenerateCharacterFieldResponse, ApiError>> {
		return this.fetch<GenerateCharacterFieldResponse>('/api/generation/character/field', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// Generate a complete character from a prompt
	async generateCompleteCharacter(
		request: GenerateCompleteCharacterRequest
	): Promise<Result<GenerateCompleteCharacterResponse, ApiError>> {
		return this.fetch<GenerateCompleteCharacterResponse>('/api/generation/character/complete', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// Enhance an existing character
	async enhanceCharacter(
		request: EnhanceCharacterRequest
	): Promise<Result<EnhanceCharacterResponse, ApiError>> {
		return this.fetch<EnhanceCharacterResponse>('/api/generation/character/enhance', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// Generate lorebook entries
	async generateLorebookEntries(
		request: GenerateLorebookEntriesRequest
	): Promise<Result<GenerateLorebookEntriesResponse, ApiError>> {
		return this.fetch<GenerateLorebookEntriesResponse>('/api/generation/lorebook/entries', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// Generate a single lorebook entry
	async generateLorebookEntry(
		request: GenerateLorebookEntryRequest
	): Promise<Result<GenerateLorebookEntryResponse, ApiError>> {
		return this.fetch<GenerateLorebookEntryResponse>('/api/generation/lorebook/entry', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// Chat with Scribe assistant for content creation
	async scribeAssistant(
		request: ScribeAssistantRequest
	): Promise<Result<ScribeAssistantResponse, ApiError>> {
		return this.fetch<ScribeAssistantResponse>('/api/generation/scribe-assistant', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// ============================================================================
	// Chronicle Methods
	// ============================================================================

	// Get all chronicles for the current user
	async getChronicles(): Promise<Result<PlayerChronicleWithCounts[], ApiError>> {
		return this.fetch<PlayerChronicleWithCounts[]>('/api/chronicles');
	}

	// Get a specific chronicle by ID
	async getChronicle(id: string): Promise<Result<PlayerChronicle, ApiError>> {
		return this.fetch<PlayerChronicle>(`/api/chronicles/${id}`);
	}

	// Generate a chronicle name from chat messages
	async generateChronicleName(
		chatSessionId: string
	): Promise<Result<{ name: string; reasoning?: string }, ApiError>> {
		return this.fetch<{ name: string; reasoning?: string }>('/api/chronicles/generate-name', {
			method: 'POST',
			body: JSON.stringify({ chat_session_id: chatSessionId })
		});
	}

	// Create a new chronicle
	async createChronicle(data: CreateChronicleRequest): Promise<Result<PlayerChronicle, ApiError>> {
		return this.fetch<PlayerChronicle>('/api/chronicles', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	// Update an existing chronicle
	async updateChronicle(
		id: string,
		data: UpdateChronicleRequest
	): Promise<Result<PlayerChronicle, ApiError>> {
		return this.fetch<PlayerChronicle>(`/api/chronicles/${id}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	// Delete a chronicle
	async deleteChronicle(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chronicles/${id}`, {
			method: 'DELETE'
		});
	}

	// Get events for a chronicle
	async getChronicleEvents(
		chronicleId: string,
		filter?: EventFilter
	): Promise<Result<ChronicleEvent[], ApiError>> {
		const params = new URLSearchParams();
		if (filter) {
			if (filter.event_type) params.append('event_type', filter.event_type);
			if (filter.source) params.append('source', filter.source);
			if (filter.keywords && filter.keywords.length > 0) {
				filter.keywords.forEach((keyword) => params.append('keywords', keyword));
			}
			if (filter.after_timestamp) params.append('after_timestamp', filter.after_timestamp);
			if (filter.before_timestamp) params.append('before_timestamp', filter.before_timestamp);
			if (filter.chat_session_id) params.append('chat_session_id', filter.chat_session_id);
			if (filter.order_by) params.append('order_by', filter.order_by);
			if (filter.limit) params.append('limit', filter.limit.toString());
			if (filter.offset) params.append('offset', filter.offset.toString());
		}
		const query = params.toString() ? `?${params.toString()}` : '';
		return this.fetch<ChronicleEvent[]>(`/api/chronicles/${chronicleId}/events${query}`);
	}

	// Create a new event in a chronicle
	async createChronicleEvent(
		chronicleId: string,
		data: CreateEventRequest
	): Promise<Result<ChronicleEvent, ApiError>> {
		return this.fetch<ChronicleEvent>(`/api/chronicles/${chronicleId}/events`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	// Delete an event from a chronicle
	async deleteChronicleEvent(
		chronicleId: string,
		eventId: string
	): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chronicles/${chronicleId}/events/${eventId}`, {
			method: 'DELETE'
		});
	}

	// Extract events from a chat session
	async extractEventsFromChat(
		chronicleId: string,
		data: {
			chat_session_id: string;
			start_message_index?: number;
			end_message_index?: number;
			extraction_model?: string;
		}
	): Promise<Result<{ events_extracted: number; events: ChronicleEvent[] }, ApiError>> {
		return this.fetch<{ events_extracted: number; events: ChronicleEvent[] }>(
			`/api/chronicles/${chronicleId}/extract-events`,
			{
				method: 'POST',
				body: JSON.stringify(data)
			}
		);
	}

	// Create a chronicle from a chat session
	async createChronicleFromChat(data: {
		chat_session_id: string;
		chronicle_name: string;
		chronicle_description?: string;
		start_message_index?: number;
		end_message_index?: number;
		extraction_model?: string;
	}): Promise<
		Result<
			{ chronicle: PlayerChronicle; events_extracted: number; events: ChronicleEvent[] },
			ApiError
		>
	> {
		return this.fetch<{
			chronicle: PlayerChronicle;
			events_extracted: number;
			events: ChronicleEvent[];
		}>('/api/chronicles/from-chat', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	// Re-chronicle events from a chat session
	async reChronicleFromChat(
		chronicleId: string,
		data: {
			chat_session_id: string;
			purge_existing?: boolean;
			start_message_index?: number;
			end_message_index?: number;
			extraction_model?: string;
			batch_size?: number;
		}
	): Promise<
		Result<
			{
				events_created: number;
				messages_processed: number;
				events_purged: number;
				summary: string;
			},
			ApiError
		>
	> {
		return this.fetch<{
			events_created: number;
			messages_processed: number;
			events_purged: number;
			summary: string;
		}>(`/api/chronicles/${chronicleId}/re-chronicle`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	// ============================================================================
	// Token Counting Methods
	// ============================================================================

	// Count tokens for text using the hybrid token counter
	async countTokens(request: TokenCountRequest): Promise<Result<TokenCountResponse, ApiError>> {
		return this.fetch<TokenCountResponse>('/api/chat/count-tokens', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// ============================================================================
	// LLM Management Methods (Local Models)
	// ============================================================================
	// These methods are conditionally included based on ENABLE_LOCAL_LLM feature flag

	// Get LLM system information and available models
	async getLlmInfo(): Promise<Result<LlmInfoResponse, ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		return this.fetch<LlmInfoResponse>('/api/llm/info');
	}

	// Get smart model recommendations based on hardware
	async getModelRecommendations(): Promise<Result<ModelRecommendation[], ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		return this.fetch<ModelRecommendation[]>('/api/llm/recommendations');
	}

	// Get the best single model recommendation
	async getBestRecommendation(): Promise<Result<ModelRecommendation | null, ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		return this.fetch<ModelRecommendation | null>('/api/llm/recommendations/best');
	}

	// Download a specific model
	async downloadModel(modelId: string): Promise<Result<DownloadModelResponse, ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		const request: DownloadModelRequest = { model_id: modelId };
		return this.fetch<DownloadModelResponse>('/api/llm/models/download', {
			method: 'POST',
			body: JSON.stringify(request)
		});
	}

	// Delete a downloaded model
	async deleteModel(modelId: string): Promise<Result<ModelActionResponse, ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		return this.fetch<ModelActionResponse>(`/api/llm/models/${modelId}`, {
			method: 'DELETE'
		});
	}

	// Activate/switch to a different model
	async activateModel(modelId: string): Promise<Result<ModelActionResponse, ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		return this.fetch<ModelActionResponse>(`/api/llm/models/${modelId}/activate`, {
			method: 'POST'
		});
	}

	// Download and activate the best recommended model
	async downloadBestModel(): Promise<Result<ModelActionResponse, ApiError>> {
		if (!ENABLE_LOCAL_LLM) {
			return err(new ApiResponseError(404, 'Local LLM feature not enabled'));
		}
		return this.fetch<ModelActionResponse>('/api/llm/download/best', {
			method: 'POST'
		});
	}

	/**
	 * Get all available models with their capabilities
	 */
	async getAllModels(): Promise<Result<Record<string, any>, ApiError>> {
		return this.fetch<Record<string, any>>('/api/llm/models/all');
	}

	// Create an EventSource for download progress (Server-Sent Events)
	createDownloadProgressStream(): EventSource | null {
		if (!ENABLE_LOCAL_LLM) {
			return null; // Feature not enabled
		}
		if (typeof EventSource === 'undefined') {
			return null; // SSE not supported (e.g., server-side rendering)
		}

		const url = `${this.baseUrl}/api/llm/download/progress`;
		return new EventSource(url, {
			withCredentials: true // Include cookies for authentication
		});
	}
}

// Export a singleton instance
export const apiClient = new ApiClient();

// Export debug utilities for testing
export { debugCookies };
