import { Result, err, ok } from 'neverthrow';
import type { ApiError } from '$lib/errors/api';
import { ApiResponseError, ApiNetworkError } from '$lib/errors/api';
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
	ScribeAssistantResponse
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

	constructor(baseUrl: string = '') {
		// Use PUBLIC_API_URL if available, otherwise fall back to relative paths
		// Trim whitespace/newlines that might be added by environment variable processing
		this.baseUrl = (baseUrl || env.PUBLIC_API_URL || '').trim();
	}

	// Generic fetch method with error handling
	private async fetch<T>(
		endpoint: string,
		options: RequestInit = {},
		fetchFn: typeof fetch = globalThis.fetch
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
					// Only update auth store and redirect if we're in the browser
					if (browser) {
						console.log(
							`[${new Date().toISOString()}] ApiClient.fetch: 401 Unauthorized. Session expired, performing comprehensive logout.`
						);
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

	async deleteChatById(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/remove/${id}`, {
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
	async getMessagesByChatId(chatId: string): Promise<Result<Message[], ApiError>> {
		return this.fetch<Message[]>(`/api/chats/${chatId}/messages`);
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
	async expandText(chatId: string, originalText: string): Promise<Result<ExpandTextResponse, ApiError>> {
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
}

// Export a singleton instance
export const apiClient = new ApiClient();

// Export debug utilities for testing
export { debugCookies };
