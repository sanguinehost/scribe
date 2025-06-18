import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import ChatConfigPanel from './ChatConfigPanel.svelte';
import { apiClient } from '$lib/api';
import type { EnhancedChatSessionLorebookAssociation, ScribeChatSession } from '$lib/types';

// Mock the API client
vi.mock('$lib/api', () => ({
	apiClient: {
		getChatLorebookAssociations: vi.fn(),
		disassociateLorebookFromChat: vi.fn(),
		setCharacterLorebookOverride: vi.fn(),
		removeCharacterLorebookOverride: vi.fn(),
		getChatSessionSettings: vi.fn(),
		updateChatSessionSettings: vi.fn(),
		getUserSettings: vi.fn()
	}
}));

// Mock toast
vi.mock('svelte-sonner', () => ({
	toast: {
		success: vi.fn(),
		error: vi.fn(),
		info: vi.fn()
	}
}));

// Import the mocked toast for use in tests
import { toast } from 'svelte-sonner';

describe('ChatConfigPanel - Redundant Lorebook Associations', () => {
	const mockChat: ScribeChatSession = {
		id: 'chat-123',
		title: 'Test Chat',
		character_id: 'char-456',
		character_name: 'Test Character',
		chat_mode: 'Character',
		user_id: 'user-789',
		created_at: '2023-01-01T00:00:00Z',
		updated_at: '2023-01-01T00:00:00Z',
		active_custom_persona_id: null,
		model_name: 'gemini-1.5-pro'
	};

	const chatOnlyAssociation: EnhancedChatSessionLorebookAssociation = {
		chat_session_id: 'chat-123',
		lorebook_id: 'lorebook-chat-only',
		user_id: 'user-789',
		lorebook_name: 'Chat Only Lorebook',
		source: 'Chat',
		is_overridden: false,
		created_at: '2023-01-01T00:00:00Z'
	};

	const characterOnlyAssociation: EnhancedChatSessionLorebookAssociation = {
		chat_session_id: 'chat-123',
		lorebook_id: 'lorebook-char-only',
		user_id: 'user-789',
		lorebook_name: 'Character Only Lorebook',
		source: 'Character',
		is_overridden: false,
		created_at: '2023-01-01T00:00:00Z'
	};

	const characterDisabledAssociation: EnhancedChatSessionLorebookAssociation = {
		chat_session_id: 'chat-123',
		lorebook_id: 'lorebook-char-disabled',
		user_id: 'user-789',
		lorebook_name: 'Character Disabled Lorebook',
		source: 'Character',
		is_overridden: true,
		override_action: 'disable',
		created_at: '2023-01-01T00:00:00Z'
	};

	const characterEnabledOverrideAssociation: EnhancedChatSessionLorebookAssociation = {
		chat_session_id: 'chat-123',
		lorebook_id: 'lorebook-char-enabled-override',
		user_id: 'user-789',
		lorebook_name: 'Character Enabled Override Lorebook',
		source: 'Character',
		is_overridden: true,
		override_action: 'enable',
		created_at: '2023-01-01T00:00:00Z'
	};

	// This represents the scenario where the backend correctly dedupes and prioritizes 'Chat'
	const dedupedAssociations: EnhancedChatSessionLorebookAssociation[] = [
		{
			chat_session_id: 'chat-123',
			lorebook_id: 'lorebook-redundant',
			user_id: 'user-789',
			lorebook_name: 'Redundant Lorebook',
			source: 'Chat', // Backend should prioritize Chat source
			is_overridden: false,
			created_at: '2023-01-01T00:00:00Z'
		}
	];

	beforeEach(() => {
		vi.clearAllMocks();

		// Mock API responses
		vi.mocked(apiClient.getChatSessionSettings).mockResolvedValue({
			isOk: () => true,
			value: {
				model_name: 'gemini-1.5-pro',
				temperature: 0.7,
				max_output_tokens: 1000,
				gemini_thinking_budget: null
			}
		} as any);

		vi.mocked(apiClient.getUserSettings).mockResolvedValue({
			isOk: () => true,
			value: {
				default_model_name: 'gemini-1.5-pro',
				default_temperature: 1.0,
				default_max_output_tokens: 1000,
				default_frequency_penalty: 0.0,
				default_presence_penalty: 0.0,
				default_top_p: 0.95,
				default_top_k: 40,
				default_seed: null,
				default_gemini_thinking_budget: null,
				default_gemini_enable_code_execution: false,
				default_context_total_token_limit: 8000,
				default_context_recent_history_budget: 4000,
				default_context_rag_budget: 2000
			}
		} as any);

		// Default mock for lorebook associations to return a mix
		vi.mocked(apiClient.getChatLorebookAssociations).mockResolvedValue({
			isOk: () => true,
			value: [
				chatOnlyAssociation,
				characterOnlyAssociation,
				characterDisabledAssociation,
				characterEnabledOverrideAssociation,
				...dedupedAssociations // Include the deduped redundant one
			]
		} as any);
	});

	it('should display chat-only lorebooks with "Remove" button', async () => {
		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Chat Only Lorebook')).toBeInTheDocument();
		});

		const chatLorebookCard = screen
			.getByText('Chat Only Lorebook')
			.closest('[data-testid="lorebook-card"]');
		expect(chatLorebookCard).toBeInTheDocument();
		expect(within(chatLorebookCard!).getByText('Chat')).toBeInTheDocument();
		expect(within(chatLorebookCard!).getByText('Remove')).toBeInTheDocument();
		expect(within(chatLorebookCard!).queryByText('Disable')).not.toBeInTheDocument();
		expect(within(chatLorebookCard!).queryByText('Restore')).not.toBeInTheDocument();
	});

	it('should display character-only lorebooks with "Disable" button', async () => {
		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Character Only Lorebook')).toBeInTheDocument();
		});

		const charLorebookCard = screen
			.getByText('Character Only Lorebook')
			.closest('[data-testid="lorebook-card"]');
		expect(charLorebookCard).toBeInTheDocument();
		expect(within(charLorebookCard!).getByText('Character')).toBeInTheDocument();
		expect(within(charLorebookCard!).getByText('Disable')).toBeInTheDocument();
		expect(within(charLorebookCard!).queryByText('Remove')).not.toBeInTheDocument();
		expect(within(charLorebookCard!).queryByText('Restore')).not.toBeInTheDocument();
	});

	it('should display disabled character lorebooks with "Restore" button and "Disabled" badge', async () => {
		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Character Disabled Lorebook')).toBeInTheDocument();
		});

		const disabledCharLorebookCard = screen
			.getByText('Character Disabled Lorebook')
			.closest('[data-testid="lorebook-card"]');
		expect(disabledCharLorebookCard).toBeInTheDocument();
		expect(within(disabledCharLorebookCard!).getByText('Character')).toBeInTheDocument();
		expect(within(disabledCharLorebookCard!).getByText('Disabled')).toBeInTheDocument();
		expect(within(disabledCharLorebookCard!).getByText('Restore')).toBeInTheDocument();
		expect(within(disabledCharLorebookCard!).queryByText('Remove')).not.toBeInTheDocument();
		expect(within(disabledCharLorebookCard!).queryByText('Disable')).not.toBeInTheDocument();
	});

	it('should display character lorebooks with "Enable" override with "Enable" badge and "Disable" button', async () => {
		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Character Enabled Override Lorebook')).toBeInTheDocument();
		});

		const enabledOverrideCharLorebookCard = screen
			.getByText('Character Enabled Override Lorebook')
			.closest('[data-testid="lorebook-card"]');
		expect(enabledOverrideCharLorebookCard).toBeInTheDocument();
		expect(within(enabledOverrideCharLorebookCard!).getByText('Character')).toBeInTheDocument();
		expect(within(enabledOverrideCharLorebookCard!).getByText('Enabled')).toBeInTheDocument();
		expect(within(enabledOverrideCharLorebookCard!).getByText('Disable')).toBeInTheDocument(); // Still "Disable" as it's an override
		expect(within(enabledOverrideCharLorebookCard!).queryByText('Remove')).not.toBeInTheDocument();
		expect(within(enabledOverrideCharLorebookCard!).queryByText('Restore')).not.toBeInTheDocument();
	});

	it('should only show one entry for a lorebook that is both chat-associated and character-associated (backend dedupes)', async () => {
		// Mock the API to return the deduped version
		vi.mocked(apiClient.getChatLorebookAssociations).mockResolvedValue({
			isOk: () => true,
			value: dedupedAssociations
		} as any);

		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getAllByText('Redundant Lorebook')).toHaveLength(1);
		});

		const lorebookCard = screen
			.getByText('Redundant Lorebook')
			.closest('[data-testid="lorebook-card"]');
		expect(lorebookCard).toBeInTheDocument();
		expect(within(lorebookCard!).getByText('Chat')).toBeInTheDocument(); // Should be prioritized as Chat source
		expect(within(lorebookCard!).getByText('Remove')).toBeInTheDocument();
		expect(within(lorebookCard!).queryByText('Character')).not.toBeInTheDocument();
		expect(within(lorebookCard!).queryByText('Disable')).not.toBeInTheDocument();
		expect(within(lorebookCard!).queryByText('Restore')).not.toBeInTheDocument();
	});

	it('should call disassociateLorebookFromChat when "Remove" is clicked for a chat-associated lorebook', async () => {
		vi.mocked(apiClient.disassociateLorebookFromChat).mockResolvedValue({
			isOk: () => true,
			value: undefined
		} as any);

		// Only return the chat-only association for this test
		vi.mocked(apiClient.getChatLorebookAssociations)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [chatOnlyAssociation]
			} as any)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [] // After removal
			} as any);

		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Chat Only Lorebook')).toBeInTheDocument();
		});

		const removeButton = screen.getByText('Remove');
		await fireEvent.click(removeButton);

		expect(apiClient.disassociateLorebookFromChat).toHaveBeenCalledWith(
			mockChat.id,
			chatOnlyAssociation.lorebook_id
		);
		await waitFor(() => {
			expect(screen.queryByText('Chat Only Lorebook')).not.toBeInTheDocument();
		});
		expect(toast.success).toHaveBeenCalledWith('Lorebook removed from chat');
	});

	it('should call setCharacterLorebookOverride with "disable" when "Disable" is clicked for a character-associated lorebook', async () => {
		vi.mocked(apiClient.setCharacterLorebookOverride).mockResolvedValue({
			isOk: () => true,
			value: undefined
		} as any);

		// Only return the character-only association for this test
		vi.mocked(apiClient.getChatLorebookAssociations)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [characterOnlyAssociation]
			} as any)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [characterDisabledAssociation] // After disabling
			} as any);

		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Character Only Lorebook')).toBeInTheDocument();
		});

		const disableButton = screen.getByText('Disable');
		await fireEvent.click(disableButton);

		expect(apiClient.setCharacterLorebookOverride).toHaveBeenCalledWith(
			mockChat.id,
			characterOnlyAssociation.lorebook_id,
			'disable'
		);
		await waitFor(() => {
			expect(screen.getByText('Character Disabled Lorebook')).toBeInTheDocument();
			expect(screen.getByText('Disabled')).toBeInTheDocument();
			expect(screen.getByText('Restore')).toBeInTheDocument();
		});
		expect(toast.success).toHaveBeenCalledWith('Character lorebook disabled for this chat');
	});

	it('should call removeCharacterLorebookOverride when "Restore" is clicked for a disabled character lorebook', async () => {
		vi.mocked(apiClient.removeCharacterLorebookOverride).mockResolvedValue({
			isOk: () => true,
			value: undefined
		} as any);

		// Only return the disabled character association for this test
		vi.mocked(apiClient.getChatLorebookAssociations)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [characterDisabledAssociation]
			} as any)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [characterOnlyAssociation] // After restoring
			} as any);

		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Character Disabled Lorebook')).toBeInTheDocument();
		});

		const restoreButton = screen.getByText('Restore');
		await fireEvent.click(restoreButton);

		expect(apiClient.removeCharacterLorebookOverride).toHaveBeenCalledWith(
			mockChat.id,
			characterDisabledAssociation.lorebook_id
		);
		await waitFor(() => {
			expect(screen.getByText('Character Only Lorebook')).toBeInTheDocument();
			expect(screen.queryByText('Disabled')).not.toBeInTheDocument();
			expect(screen.getByText('Disable')).toBeInTheDocument();
		});
		expect(toast.success).toHaveBeenCalledWith('Override removed');
	});

	it('should call setCharacterLorebookOverride with "disable" when "Disable" is clicked for an enabled-override character lorebook', async () => {
		vi.mocked(apiClient.setCharacterLorebookOverride).mockResolvedValue({
			isOk: () => true,
			value: undefined
		} as any);

		// Only return the enabled-override character association for this test
		vi.mocked(apiClient.getChatLorebookAssociations)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [characterEnabledOverrideAssociation]
			} as any)
			.mockResolvedValueOnce({
				isOk: () => true,
				value: [characterDisabledAssociation] // After disabling
			} as any);

		render(ChatConfigPanel, {
			props: {
				chat: mockChat,
				availablePersonas: []
			}
		});

		await waitFor(() => {
			expect(screen.getByText('Character Enabled Override Lorebook')).toBeInTheDocument();
		});

		const disableButton = screen.getByText('Disable');
		await fireEvent.click(disableButton);

		expect(apiClient.setCharacterLorebookOverride).toHaveBeenCalledWith(
			mockChat.id,
			characterEnabledOverrideAssociation.lorebook_id,
			'disable'
		);
		await waitFor(() => {
			expect(screen.getByText('Character Disabled Lorebook')).toBeInTheDocument();
			expect(screen.getByText('Disabled')).toBeInTheDocument();
			expect(screen.getByText('Restore')).toBeInTheDocument();
		});
		expect(toast.success).toHaveBeenCalledWith('Character lorebook disabled for this chat');
	});
});
