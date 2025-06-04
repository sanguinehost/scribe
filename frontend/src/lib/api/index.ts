import { Result, err, ok } from 'neverthrow';
import type { ApiError } from '$lib/errors/api';
import { ApiResponseError, ApiNetworkError } from '$lib/errors/api';
import type { User, Message, Vote, Suggestion, Session, AuthUser, ScribeChatSession, LoginSuccessData, Lorebook, LorebookEntry, CreateLorebookPayload, UpdateLorebookPayload, CreateLorebookEntryPayload, UpdateLorebookEntryPayload, LorebookUploadPayload, ScribeMinimalLorebook, ChatSessionLorebookAssociation, Character, UserPersona, CreateUserPersonaRequest, UpdateUserPersonaRequest, CreateChatRequest, CreateMessageRequest, CreateDocumentRequest, CreateSuggestionRequest, DocumentResponse, SessionResponse, SuggestedActionsResponse, UpdateChatSessionSettingsRequest } from '$lib/types';

// Actual API client
class ApiClient {
	private baseUrl: string;

	constructor(baseUrl: string = '') {
		this.baseUrl = baseUrl;
	}

	// Generic fetch method with error handling
	private async fetch<T>(
		endpoint: string,
		options: RequestInit = {},
		fetchFn: typeof fetch = globalThis.fetch
	): Promise<Result<T, ApiError>> {
		console.log(`[${new Date().toISOString()}] ApiClient.fetch: ENTER - ${options.method || 'GET'} ${endpoint}`);
		try {
			const response = await fetchFn(`${this.baseUrl}${endpoint}`, {
				...options,
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json',
					...options.headers
				}
			});

			console.log(`[${new Date().toISOString()}] ApiClient.fetch: Response status ${response.status} for ${endpoint}`);
			if (!response.ok) {
				let errorData = { message: 'An unknown error occurred' };
				try {
					errorData = await response.json();
				} catch (parseError) {
					console.error(`[${new Date().toISOString()}] ApiClient.fetch: Failed to parse error JSON for ${endpoint}`, parseError);
				}
				console.error(`[${new Date().toISOString()}] ApiClient.fetch: EXIT - API Error ${response.status}`, errorData);
				return err(new ApiResponseError(response.status, errorData.message));
			}

			// Check if response is empty (like for a 204 No Content)
			if (response.status === 204) {
				console.log(`[${new Date().toISOString()}] ApiClient.fetch: EXIT - Success (204 No Content) for ${endpoint}`);
				return ok({} as T);
			}

			const data = await response.json();
			console.log(`[${new Date().toISOString()}] ApiClient.fetch: EXIT - Success (200 OK) for ${endpoint}`);
			return ok(data as T);
		} catch (error) {
			console.error(`[${new Date().toISOString()}] ApiClient.fetch: EXIT - Network/Fetch Error for ${endpoint}`, error);
			return err(new ApiNetworkError('Network error', error as Error));
		}
	}

	// Auth methods
	async getUser(fetchFn: typeof fetch = globalThis.fetch): Promise<Result<User, ApiError>> {
		return this.fetch<User>('/api/auth/me', {}, fetchFn);
	}

	async authenticateUser(data: { identifier: string; password: string }, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<LoginSuccessData, ApiError>> {
		return this.fetch<LoginSuccessData>('/api/auth/login', {
			method: 'POST',
			body: JSON.stringify(data)
		}, fetchFn);
	}

	async getAuthUser(data: { email: string }, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<LoginSuccessData, ApiError>> {
		console.warn('getAuthUser called - consider using authenticateUser for standard login flow');
		// This method likely also needs to align with the LoginSuccessData response if it's hitting the same /api/auth/login endpoint
		// For now, assuming it should also return LoginSuccessData. If it's a different flow, this might need adjustment.
		return this.fetch<LoginSuccessData>('/api/auth/login', {
			method: 'POST',
			body: JSON.stringify({ identifier: data.email, password: '' }) // Assuming password can be empty for this specific getAuthUser flow
		}, fetchFn);
	}

	async createUser(data: { email: string; username: string; password: string }, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<AuthUser, ApiError>> {
		return this.fetch<AuthUser>('/api/auth/register', {
			method: 'POST',
			body: JSON.stringify(data)
		}, fetchFn);
	}

	async logout(fetchFn: typeof fetch = globalThis.fetch): Promise<Result<void, ApiError>> {
		return this.fetch<void>('/api/auth/logout', {
			method: 'POST'
		}, fetchFn);
	}

	// Session methods
	async createSession(session: Session, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<Session, ApiError>> {
		return this.fetch<Session>('/api/auth/session', {
			method: 'POST',
			body: JSON.stringify(session)
		}, fetchFn);
	}

	// Updated to call /api/auth/session/current and not take sessionId
	async getSession(fetchFn: typeof fetch = globalThis.fetch): Promise<Result<SessionResponse, ApiError>> {
		return this.fetch<SessionResponse>('/api/auth/session/current', {}, fetchFn);
	}

	async extendSession(sessionId: string, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<Session, ApiError>> {
		return this.fetch<Session>(`/api/auth/session/${sessionId}/extend`, {
			method: 'POST'
		}, fetchFn);
	}

	async deleteSession(sessionId: string, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<undefined, ApiError>> {
		return this.fetch<undefined>(`/api/auth/session/${sessionId}`, {
			method: 'DELETE'
		}, fetchFn);
	}

	async deleteSessionsForUser(userId: string, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<undefined, ApiError>> {
		return this.fetch<undefined>(`/api/auth/user/${userId}/sessions`, {
			method: 'DELETE'
		}, fetchFn);
	}

	// Chat methods
	async getChats(): Promise<Result<ScribeChatSession[], ApiError>> { // Use ScribeChatSession from types.ts if it matches API response
		return this.fetch<ScribeChatSession[]>('/api/chats');
	}

	async getChatsByCharacter(characterId: string): Promise<Result<ScribeChatSession[], ApiError>> {
		return this.fetch<ScribeChatSession[]>(`/api/chats/by-character/${characterId}`);
	}

	// Updated createChat to accept and send character details
	async createChat(data: CreateChatRequest): Promise<Result<ScribeChatSession, ApiError>> { // Use ScribeChatSession
		console.log(`[${new Date().toISOString()}] ApiClient.createChat: Creating chat with data:`, data);
		return this.fetch<ScribeChatSession>('/api/chat/create_session', { // Use ScribeChatSession
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getChatById(id: string): Promise<Result<ScribeChatSession, ApiError>> { // Use ScribeChatSession
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

	async createMessage(
		chatId: string,
		data: CreateMessageRequest
	): Promise<Result<Message, ApiError>> {
		return this.fetch<Message>(`/api/chats/${chatId}/messages`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getMessageById(id: string): Promise<Result<Message, ApiError>> {
		return this.fetch<Message>(`/api/messages/${id}`);
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
	async getChatSessionSettings(sessionId: string): Promise<Result<ScribeChatSession, ApiError>> {
		return this.fetch<ScribeChatSession>(`/api/chats/${sessionId}/settings`);
	}

	async updateChatSessionSettings(
		sessionId: string,
		settings: UpdateChatSessionSettingsRequest
	): Promise<Result<ScribeChatSession, ApiError>> {
		return this.fetch<ScribeChatSession>(`/api/chats/${sessionId}/settings`, {
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

	async updateUserPersona(id: string, data: UpdateUserPersonaRequest): Promise<Result<UserPersona, ApiError>> {
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

	async updateLorebook(id: string, data: UpdateLorebookPayload): Promise<Result<Lorebook, ApiError>> {
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

	async getLorebookEntry(lorebookId: string, entryId: string): Promise<Result<LorebookEntry, ApiError>> {
		return this.fetch<LorebookEntry>(`/api/lorebooks/${lorebookId}/entries/${entryId}`);
	}

	async createLorebookEntry(lorebookId: string, data: CreateLorebookEntryPayload): Promise<Result<LorebookEntry, ApiError>> {
		return this.fetch<LorebookEntry>(`/api/lorebooks/${lorebookId}/entries`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async updateLorebookEntry(lorebookId: string, entryId: string, data: UpdateLorebookEntryPayload): Promise<Result<LorebookEntry, ApiError>> {
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
	async associateLorebookToChat(chatId: string, lorebookId: string): Promise<Result<ChatSessionLorebookAssociation, ApiError>> {
		return this.fetch<ChatSessionLorebookAssociation>(`/api/chats/${chatId}/lorebooks`, {
			method: 'POST',
			body: JSON.stringify({ lorebook_id: lorebookId })
		});
	}

	async getChatLorebookAssociations(chatId: string): Promise<Result<ChatSessionLorebookAssociation[], ApiError>> {
		return this.fetch<ChatSessionLorebookAssociation[]>(`/api/chats/${chatId}/lorebooks`);
	}

	async disassociateLorebookFromChat(chatId: string, lorebookId: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/${chatId}/lorebooks/${lorebookId}`, {
			method: 'DELETE'
		});
	}

	// Import/Export methods
	async importLorebook(data: LorebookUploadPayload): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>('/api/lorebooks/import?format=silly_tavern_full', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async importLorebookScribeMinimal(data: ScribeMinimalLorebook): Promise<Result<Lorebook, ApiError>> {
		return this.fetch<Lorebook>('/api/lorebooks/import?format=scribe_minimal', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async exportLorebook(lorebookId: string, format: 'scribe_minimal' | 'silly_tavern_full' = 'silly_tavern_full'): Promise<Result<ScribeMinimalLorebook | LorebookUploadPayload, ApiError>> {
		return this.fetch<ScribeMinimalLorebook | LorebookUploadPayload>(`/api/lorebooks/${lorebookId}/export?format=${format}`);
	}
}

// Export a singleton instance
export const apiClient = new ApiClient(); 