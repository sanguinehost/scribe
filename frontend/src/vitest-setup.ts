import '@testing-library/jest-dom';
import { vi } from 'vitest';
import { Result, ok } from 'neverthrow';

// Mock window.matchMedia for jsdom
Object.defineProperty(window, 'matchMedia', {
	writable: true,
	value: vi.fn().mockImplementation((query) => ({
		matches: false, // Default to not matching
		media: query,
		onchange: null,
		addListener: vi.fn(), // Deprecated but sometimes used
		removeListener: vi.fn(), // Deprecated but sometimes used
		addEventListener: vi.fn(),
		removeEventListener: vi.fn(),
		dispatchEvent: vi.fn()
	}))
});

// Mock global fetch
global.fetch = vi.fn((url: RequestInfo | URL, _init?: RequestInit) => {
	if (url.toString().includes('/api/personas')) {
		return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
	}
	if (url.toString().includes('/api/chat/')) {
		// Mock for chat-related API calls
		return Promise.resolve(new Response(JSON.stringify({}), { status: 200 }));
	}
	// Default mock response for other fetches
	return Promise.resolve(new Response(JSON.stringify({}), { status: 200 }));
});

// Mock apiClient
vi.mock('$lib/api', async (importActual) => {
	const actual = await importActual<typeof import('$lib/api')>();
	return {
		...actual,
		apiClient: {
			...actual.apiClient,
			getChatSessionSettings: vi.fn(() =>
				Promise.resolve(
					ok({
						temperature: 1.0,
						max_output_tokens: 1000,
						frequency_penalty: 0.0,
						presence_penalty: 0.0,
						top_p: 0.95,
						top_k: 40,
						seed: null,
						system_prompt: '',
						model_name: '',
						gemini_thinking_budget: null,
						gemini_enable_code_execution: false,
						context_total_token_limit: 200000,
						context_recent_history_budget: 150000,
						context_rag_budget: 40000
					})
				)
			),
			getChatLorebookAssociations: vi.fn(() => Promise.resolve(ok([]))),
			updateChatSessionSettings: vi.fn(() => Promise.resolve(ok({}))),
			disassociateLorebookFromChat: vi.fn(() => Promise.resolve(ok(undefined))),
			setCharacterLorebookOverride: vi.fn(() => Promise.resolve(ok(undefined))),
			removeCharacterLorebookOverride: vi.fn(() => Promise.resolve(ok(undefined))),
			getLorebook: vi.fn((id: string) =>
				Promise.resolve(ok({ id, name: `Mock Lorebook ${id.substring(0, 4)}` }))
			),
			getChatSession: vi.fn(() =>
				Promise.resolve(
					ok({
						id: 'chat-123',
						title: 'Mock Chat',
						character_id: 'char-456',
						character_name: 'Mock Character',
						user_id: 'user-789',
						created_at: '2023-01-01T00:00:00Z',
						updated_at: '2023-01-01T00:00:00Z',
						active_custom_persona_id: null,
						model_name: 'gemini-1.5-pro'
					})
				)
			),
			getCharacter: vi.fn(() =>
				Promise.resolve(
					ok({
						id: 'char-456',
						name: 'Mock Character',
						user_id: 'user-789',
						created_at: '2023-01-01T00:00:00Z',
						updated_at: '2023-01-01T00:00:00Z',
						description: 'A mock character.',
						first_mes: 'Hello from mock character!',
						mes_example: 'Example message.',
						scenario: 'A mock scenario.',
						system_prompt: 'You are a helpful assistant.',
						tags: [],
						visibility: 'private',
						avatar_url: null,
						alternate_greetings: [],
						creator_id: 'user-789',
						creator_name: 'Mock User',
						last_chat_message_at: null,
						chat_count: 0,
						lorebook_count: 0,
						asset_count: 0,
						is_public: false,
						is_editable: true,
						is_removable: true,
						is_deletable: true,
						is_private: true,
						is_system: false,
						is_favorite: false,
						is_archived: false,
						is_nsfw: false,
						is_locked: false,
						is_searchable: true,
						is_cloneable: true,
						is_shareable: true,
						is_downloadable: true,
						is_editable_by_user: true,
						is_removable_by_user: true,
						is_deletable_by_user: true,
						is_private_by_user: true,
						is_system_by_user: false,
						is_favorite_by_user: false,
						is_archived_by_user: false,
						is_nsfw_by_user: false,
						is_locked_by_user: false,
						is_searchable_by_user: true,
						is_cloneable_by_user: true,
						is_shareable_by_user: true,
						is_downloadable_by_user: true,
						is_editable_by_creator: true,
						is_removable_by_creator: true,
						is_deletable_by_creator: true,
						is_private_by_creator: true,
						is_system_by_creator: false,
						is_favorite_by_creator: false,
						is_archived_by_creator: false,
						is_nsfw_by_creator: false,
						is_locked_by_creator: false,
						is_searchable_by_creator: true,
						is_cloneable_by_creator: true,
						is_shareable_by_creator: true,
						is_downloadable_by_creator: true
					})
				)
			),
			listUserPersonas: vi.fn(() => Promise.resolve(ok([]))),
			getChatMessages: vi.fn(() => Promise.resolve(ok([]))),
			fetchSuggestedActions: vi.fn(() => Promise.resolve(ok({ actions: [] })))
		}
	};
});
