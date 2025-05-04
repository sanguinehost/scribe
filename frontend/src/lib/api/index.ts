import { Result, err, ok } from 'neverthrow';
import type { ApiError } from '$lib/errors/api';
import { ApiResponseError, ApiNetworkError } from '$lib/errors/api';
import type { User, Chat, Message, Vote, Suggestion, Session, AuthUser } from '$lib/types';

// Type definitions for message parts
export interface TextPart {
	text: string;
}

export interface ImagePart {
	image_url: string;
	alt?: string;
}

export type MessagePart = TextPart | ImagePart;

export interface MessageAttachment {
	type: string;
	data: unknown;
}

// Type definitions for API requests
export type CreateChatRequest = {
	title: string;
	character_id: string;
};

export type CreateMessageRequest = {
	role: string;
	content: string;
	parts?: MessagePart[];
	attachments?: MessageAttachment[];
};

export type VoteRequest = {
	type_: 'up' | 'down';
};

export type UpdateChatVisibilityRequest = {
	visibility: 'public' | 'private';
};

export type CreateDocumentRequest = {
	title: string;
	content?: string;
	kind: string;
};

export type CreateSuggestionRequest = {
	document_id: string;
	document_created_at: string;
	original_text: string;
	suggested_text: string;
	description?: string;
};

// Type definitions for API responses
export type ChatResponse = {
	id: string;
	title: string;
	created_at: Date;
	user_id: string;
	visibility?: string;
};

export type MessageResponse = {
	id: string;
	chat_id: string;
	role: string;
	parts: MessagePart[];
	attachments: MessageAttachment[];
	created_at: Date;
};

export type DocumentResponse = {
	id: string;
	created_at: Date;
	title: string;
	content?: string;
	kind: string;
	user_id: string;
};

export type SessionResponse = {
	session: {
		id: string;
		user_id: string;
		expires_at: string | Date; // Could be ISO string from backend
	};
	user: User;
};

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

	async authenticateUser(data: { identifier: string; password: string }, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<AuthUser, ApiError>> {
		return this.fetch<AuthUser>('/api/auth/login', {
			method: 'POST',
			body: JSON.stringify(data)
		}, fetchFn);
	}

	async getAuthUser(data: { email: string }, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<AuthUser, ApiError>> {
		console.warn('getAuthUser called - consider using authenticateUser for standard login flow');
		return this.fetch<AuthUser>('/api/auth/login', {
			method: 'POST',
			body: JSON.stringify({ identifier: data.email, password: '' })
		}, fetchFn);
	}

	async createUser(data: { email: string; username: string; password: string }, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<AuthUser, ApiError>> {
		return this.fetch<AuthUser>('/api/auth/register', {
			method: 'POST',
			body: JSON.stringify(data)
		}, fetchFn);
	}

	// Session methods
	async createSession(session: Session, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<Session, ApiError>> {
		return this.fetch<Session>('/api/auth/session', {
			method: 'POST',
			body: JSON.stringify(session)
		}, fetchFn);
	}

	async getSession(sessionId: string, fetchFn: typeof fetch = globalThis.fetch): Promise<Result<SessionResponse, ApiError>> {
		return this.fetch<SessionResponse>(`/api/auth/session/${sessionId}`, {}, fetchFn);
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
	async getChats(): Promise<Result<Chat[], ApiError>> {
		return this.fetch<Chat[]>('/api/chats');
	}

	async createChat(data: CreateChatRequest): Promise<Result<Chat, ApiError>> {
		return this.fetch<Chat>('/api/chats', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async getChatById(id: string): Promise<Result<Chat, ApiError>> {
		return this.fetch<Chat>(`/api/chats/${id}`);
	}

	async deleteChatById(id: string): Promise<Result<void, ApiError>> {
		return this.fetch<void>(`/api/chats/${id}`, {
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
}

// Export a singleton instance
export const apiClient = new ApiClient(); 