// frontend/src/lib/services/apiClient.ts
import type { ChatMessage } from '$lib/stores/chatStore'; // Keep type import

// Re-export Message type for convenience if it's defined in chatStore
export type { ChatMessage };

const API_BASE = '/api'; // Or load from environment variables

/**
 * Creates a new chat session for a given character.
 * @param characterId - The ID of the character to chat with.
 * @returns A promise resolving to the new session ID.
 */
export async function createChatSession(characterId: string): Promise<{ sessionId: string }> {
	const response = await fetch(`${API_BASE}/chats`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, // Added Accept
		body: JSON.stringify({ character_id: characterId }),
		credentials: 'include', // Ensure cookies are sent if needed for auth
	});

	if (!response.ok) {
		let errorMsg = `Failed to create chat session: ${response.status} ${response.statusText}`;
		try {
			const errorBody = await response.json();
			errorMsg = errorBody.message || errorBody.detail || errorMsg; // Use backend error message if available
		} catch { // Omit unused variable
			// Ignore if response body is not JSON
		}
		throw new Error(errorMsg);
	}

	const data = await response.json();
	// Ensure the backend returns an object with an 'id' field
	if (!data || typeof data.id !== 'string') {
		console.error('Backend response missing or invalid session id:', data);
		throw new Error('Failed to create chat session: Invalid response from server.');
	}
	// Use the 'id' field from the response
	return { sessionId: data.id };
}

/**
 * Fetches all messages for a given chat session.
 * @param sessionId - The ID of the chat session.
 * @returns A promise resolving to an array of messages.
 */
export async function fetchChatMessages(sessionId: string): Promise<ChatMessage[]> {
	if (!sessionId) {
		throw new Error('Session ID is required to fetch messages.');
	}
	const response = await fetch(`${API_BASE}/chats/${sessionId}/messages`, {
		method: 'GET',
		headers: { Accept: 'application/json' },
		credentials: 'include', // Ensure cookies are sent
	});

	if (!response.ok) {
		let errorMsg = `Failed to fetch chat messages: ${response.status} ${response.statusText}`;
		try {
			const errorBody = await response.json();
			errorMsg = errorBody.message || errorBody.detail || errorMsg;
		} catch { // Omit unused variable
			// Ignore if response body is not JSON
		}
		throw new Error(errorMsg);
	}

	// Assuming the backend returns an array of messages compatible with the Message interface
	// Add validation if necessary
	const messages: ChatMessage[] = await response.json();
	return messages;
}


/**
 * Sends a user message and handles the streaming SSE response from the backend via fetch.
 *
 * @param sessionId - The ID of the chat session.
 * @param userMessage - The content of the user's message.
 * @param onChunk - Callback function invoked for each received text chunk.
 * @param onError - Callback function invoked if an error occurs during the stream.
 * @param onComplete - Callback function invoked when the stream finishes successfully.
 */
export async function generateChatResponse(
	sessionId: string,
	userMessage: string,
	onChunk: (chunk: string, messageId: string) => void, // Pass messageId too
	onError: (error: Error) => void, // Use Error type
	onComplete: (messageId: string | null) => void // Allow null messageId
): Promise<void> {
	if (!sessionId) {
		onError(new Error('Session ID is required to generate response.'));
		return;
	}

	let response: Response;
	try {
		response = await fetch(`${API_BASE}/chats/${sessionId}/generate`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Accept: 'text/event-stream', // Expect SSE stream
			},
			body: JSON.stringify({ content: userMessage }),
			credentials: 'include', // Send cookies
		});

		if (!response.ok) {
			let errorMsg = `API error: ${response.status} ${response.statusText}`;
			try {
				const errorBody = await response.json(); // Try to get specific error from backend
				errorMsg = errorBody.message || errorBody.detail || errorMsg;
			} catch { // Omit unused variable
				// Ignore if response body isn't JSON
			}
			throw new Error(errorMsg);
		}

		if (!response.body) {
			throw new Error('Response body is null');
		}

		// Manually process the stream
		const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
		let buffer = '';
		let currentMessageId: string | null = null;

		while (true) {
			const { done, value } = await reader.read();
			if (done) {
				// console.log('Stream finished.');
				// Always call onComplete when the stream ends, with either the messageId or null
				onComplete(currentMessageId);
				break;
			}

			buffer += value;
			const lines = buffer.split('\n'); // Use const

			// Process all complete lines except the last (which might be partial)
			for (let i = 0; i < lines.length - 1; i++) {
				const line = lines[i].trim();

				// Look for standard SSE fields: id, data, event (optional)
				if (line.startsWith('id:')) {
					const idValue = line.substring(3).trim();
					if (idValue) {
						currentMessageId = idValue;
						// console.log(`SSE Event ID received: ${currentMessageId}`);
					}
				} else if (line.startsWith('data:')) {
					// Per instructions, treat data as plain text chunk
					const textData = line.substring(5).trim();
					if (textData) {
						// Pass the raw text chunk and the last known message ID
						// If the backend sends a specific termination signal like "[DONE]",
						// it might need special handling here or in chatStore.
						if (textData === '[DONE]') {
							// console.log('Received [DONE] signal.'); // Optional: Handle if needed
						} else {
							onChunk(textData, currentMessageId || ''); // Pass empty string if ID unknown
						}
					}
				} else if (line.startsWith('event:')) {
					// Optional: Handle custom event types if needed in the future
					// const eventType = line.substring(6).trim();
					// console.log(`Received event type: ${eventType}`);
				}
				// Ignore empty lines and comments (lines starting with ':')
			}

			// Keep the last partial line in the buffer
			buffer = lines[lines.length - 1];
		}

	} catch (error) {
		console.error('Error during fetch or stream processing:', error);
		// Ensure we pass an Error object to the callback
		if (error instanceof Error) {
			onError(error);
		} else {
			onError(new Error(`Unknown error during stream processing: ${error}`));
		}
	}
}


// --- Authentication API Calls ---
// Define a basic User type based on expected API response
export interface User {
	id: string; // Or number, depending on backend
	username: string;
	email?: string; // Add email if backend returns it
	// Add other relevant user fields if returned by the API (e.g., roles)
}

/**
	* Attempts to log in a user using username and password.
	* @param username - The user's username.
	* @param password - The user's password.
	* @returns A promise resolving to the user data upon successful login.
	* @throws An error if login fails.
	*/
export async function login(username: string, password: string): Promise<User> {
	const response = await fetch(`${API_BASE}/auth/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
		body: JSON.stringify({ username, password }), // Use username for login
		credentials: 'include', // Send cookies
	});

	if (!response.ok) {
		const errorData = await response.json().catch(() => ({ message: 'Login failed' })); // Try to parse error, fallback
		throw new Error(errorData.message || `Login failed: ${response.status}`);
	}

	return await response.json(); // Assuming backend returns user info on success
}

/**
 * Attempts to register a new user with username, email, and password.
 * @param username - The desired username.
 * @param email - The user's email address.
 * @param password - The desired password.
 * @returns A promise resolving to the user data upon successful registration.
 * @throws An error if registration fails.
 */
export async function register(username: string, email: string, password: string): Promise<User> {
 const response = await fetch(`${API_BASE}/auth/register`, {
 	method: 'POST',
 	headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
 	body: JSON.stringify({ username, email, password }), // Add email to registration payload
 	credentials: 'include', // Send cookies if needed for session creation immediately
 });

 if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Registration failed' })); // Try to parse error, fallback
		throw new Error(errorData.message || `Registration failed: ${response.status}`);
	}

	return await response.json(); // Assuming backend returns user info or success message
}

/**
 * Logs out the current user.
 * @returns A promise resolving when logout is complete.
 * @throws An error if logout fails.
 */
export async function logout() {
	const response = await fetch(`${API_BASE}/auth/logout`, {
		method: 'POST',
        credentials: 'include', // Send cookies to invalidate session
	});

	if (!response.ok) {
        // Logout might return 204 No Content on success, or redirect, handle gracefully
        if (response.status !== 204) {
            const errorData = await response.json().catch(() => ({ message: 'Logout failed' }));
            throw new Error(errorData.message || `Logout failed: ${response.status}`);
        }
	}
    // No content expected on successful logout typically
}

/**
 * Checks the current authentication status by fetching user data.
 * @returns A promise resolving to the user data if authenticated, or null otherwise.
 */
export async function checkAuthStatus(): Promise<User | null> {
 try {
 	const response = await fetch(`${API_BASE}/auth/me`, {
 		method: 'GET',
		headers: { Accept: 'application/json' },
		credentials: 'include', // Send cookies to identify session
		});

		if (response.ok) {
			return await response.json(); // Return user data if logged in
		} else if (response.status === 401) {
            return null; // Unauthorized, not logged in
        } else {
            // Handle other potential errors (e.g., server error 500)
            console.error(`Auth check failed: ${response.status}`);
            return null; // Treat other errors as not logged in for safety
        }
	} catch (error) {
		console.error('Network error during auth check:', error);
		return null; // Network errors mean we can't confirm auth status
	}
}


// --- Character API Calls ---
// Define a basic Character type based on expected API response
export interface Character {
	id: string; // Or number, depending on backend
	name: string;
	description: string;
	greeting: string; // Assuming these fields exist based on UI spec needs
	// Add other relevant fields like avatar_url if the backend provides them directly
}

/**
 * Fetches the list of characters for the authenticated user.
 * @returns A promise resolving to an array of characters.
 * @throws An error if fetching fails.
 */
export async function listCharacters(): Promise<Character[]> {
	const response = await fetch(`${API_BASE}/characters`, {
		method: 'GET',
		headers: { Accept: 'application/json' },
		credentials: 'include', // Send cookies for authentication
	});

	if (!response.ok) {
		const errorData = await response.json().catch(() => ({ message: 'Failed to fetch characters' }));
		throw new Error(errorData.message || `Failed to fetch characters: ${response.status}`);
	}

	return await response.json(); // Assuming backend returns Character[]
}

/**
 * Uploads a new character card (PNG file).
 * @param formData - The FormData object containing the file to upload (e.g., under key 'character_card').
 * @returns A promise resolving to the newly created character data.
 * @throws An error if upload fails.
 */
export async function uploadCharacter(formData: FormData): Promise<Character> {
	const response = await fetch(`${API_BASE}/characters/upload`, {
		method: 'POST',
		credentials: 'include', // Send cookies for authentication
		body: formData, // Send FormData directly
		// Note: Do NOT set Content-Type header when sending FormData;
		// the browser sets it correctly with the boundary.
		headers: { Accept: 'application/json' }, // Expect JSON response
	});

	if (!response.ok) {
		const errorData = await response.json().catch(() => ({ message: 'Failed to upload character' }));
		throw new Error(errorData.message || `Failed to upload character: ${response.status}`);
	}

	return await response.json(); // Assuming backend returns the new Character on success
}

/**
 * Constructs the URL for fetching a character's avatar image.
 * @param characterId - The ID of the character.
 * @returns The URL string for the character's image.
 */
export function getCharacterImageUrl(characterId: string): string {
	// Ensure the base URL doesn't end with a slash and the path doesn't start with one
	// or handle potential double slashes appropriately.
	return `${API_BASE}/characters/${characterId}/image`;
}


// --- Chat Settings API Calls ---

// Define the settings type based on SettingsPanel and API expectations (snake_case)
export interface ChatSettings {
	system_prompt?: string | null; // Allow null from backend
	temperature?: number | null;
	max_output_tokens?: number | null;
	frequency_penalty?: number | null;
	presence_penalty?: number | null;
	top_k?: number | null;
	top_p?: number | null;
	repetition_penalty?: number | null;
	min_p?: number | null;
	top_a?: number | null;
	seed?: number | null;
	logit_bias?: Record<string, number> | null; // Expect object from API
}


/**
 * Fetches the current settings for a given chat session.
 * @param sessionId - The ID of the chat session.
 * @returns A promise resolving to the chat settings object.
 * @throws An error if fetching fails.
 */
export async function getChatSettings(sessionId: string): Promise<ChatSettings> {
	if (!sessionId) {
		throw new Error('Session ID is required to fetch chat settings.');
	}
	const response = await fetch(`${API_BASE}/chats/${sessionId}/settings`, {
		method: 'GET',
		headers: { Accept: 'application/json' },
		credentials: 'include',
	});

	if (!response.ok) {
		let errorMsg = `Failed to fetch chat settings: ${response.status} ${response.statusText}`;
		try {
			const errorBody = await response.json();
			errorMsg = errorBody.message || errorBody.detail || errorMsg;
		} catch {
			// Ignore if response body is not JSON
		}
		throw new Error(errorMsg);
	}

	const settings: ChatSettings = await response.json();
	// Basic validation or transformation could happen here if needed
	return settings;
}

/**
 * Updates the settings for a given chat session.
 * @param sessionId - The ID of the chat session.
 * @param settings - An object containing the settings fields to update.
 * @returns A promise resolving when the update is complete.
 * @throws An error if updating fails.
 */
export async function updateChatSettings(sessionId: string, settings: Partial<ChatSettings>): Promise<void> {
	if (!sessionId) {
		throw new Error('Session ID is required to update chat settings.');
	}

	// Basic validation before sending (e.g., ensure numbers are numbers)
	// More complex validation (like JSON parsing for logit_bias if it were passed as string)
	// would happen before calling this function.

	const response = await fetch(`${API_BASE}/chats/${sessionId}/settings`, {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json',
		},
		body: JSON.stringify(settings),
		credentials: 'include',
	});

	if (!response.ok) {
		let errorMsg = `Failed to update chat settings: ${response.status} ${response.statusText}`;
		try {
			const errorBody = await response.json();
			errorMsg = errorBody.message || errorBody.detail || errorMsg;
		} catch {
			// Ignore if response body is not JSON
		}
		throw new Error(errorMsg);
	}

	// Expecting 200 OK or 204 No Content on success, no body needed typically.
}

// Export an apiClient object that contains references to all the API functions
// This allows components to import { apiClient } from '$lib/services/apiClient'
export const apiClient = {
	// Chat functions
	createChatSession,
	fetchChatMessages,
	generateChatResponse,
	
	// Auth functions
	login,
	register,
	logout,
	checkAuthStatus,
	
	// Character functions
	listCharacters,
	uploadCharacter,
	getCharacterImageUrl,
	
	// Settings functions
	getChatSettings,
	updateChatSettings
};