import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import AiAssistantDialog from './ai-assistant-dialog-v2.svelte';
import type { CharacterContext } from '$lib/types';

// Mock the API client
vi.mock('$lib/api', () => ({
	apiClient: {
		// Mock API methods if needed
	}
}));

// Mock fetch for the generation API calls
global.fetch = vi.fn();

describe('AI Assistant Dialog - Lorebook Integration', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('should include lorebook_id in generation request when lorebooks are selected', async () => {
		const mockFetch = vi.mocked(fetch);
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				content: 'Generated content with lorebook context',
				style_used: 'narrative',
				metadata: { tokens_used: 100 }
			})
		} as Response);

		const characterContext: CharacterContext = {
			name: 'Lassenia',
			description: 'A mysterious princess',
			selectedLorebooks: ['lorebook-uuid-123', 'lorebook-uuid-456']
		};

		const mockOnGenerated = vi.fn();
		const mockOnOpenChange = vi.fn();

		render(AiAssistantDialog, {
			props: {
				open: true,
				fieldName: 'description',
				fieldValue: '',
				characterContext,
				onGenerated: mockOnGenerated,
				onOpenChange: mockOnOpenChange
			}
		});

		// Find and fill the user input
		const textArea = screen.getByRole('textbox');
		await fireEvent.input(textArea, { target: { value: 'Generate a description of Lassenia' } });

		// Find and click the generate button
		const generateButton = screen.getByText('Generate');
		await fireEvent.click(generateButton);

		// Wait for the API call
		await waitFor(() => {
			expect(mockFetch).toHaveBeenCalledWith('/api/characters/generate/field', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					field: 'description',
					style: null,
					user_prompt: 'Generate a description of Lassenia',
					character_context: expect.objectContaining({
						name: 'Lassenia',
						description: 'A mysterious princess'
					}),
					generation_options: null,
					lorebook_id: 'lorebook-uuid-123' // Should use first selected lorebook
				})
			});
		});

		expect(mockOnGenerated).toHaveBeenCalledWith('Generated content with lorebook context');
	});

	it('should not include lorebook_id when no lorebooks are selected', async () => {
		const mockFetch = vi.mocked(fetch);
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				content: 'Generated content without lorebook',
				style_used: 'auto',
				metadata: { tokens_used: 80 }
			})
		} as Response);

		const characterContext: CharacterContext = {
			name: 'BasicChar',
			selectedLorebooks: [] // Empty array
		};

		const mockOnGenerated = vi.fn();
		const mockOnOpenChange = vi.fn();

		render(AiAssistantDialog, {
			props: {
				open: true,
				fieldName: 'personality',
				fieldValue: '',
				characterContext,
				onGenerated: mockOnGenerated,
				onOpenChange: mockOnOpenChange
			}
		});

		const textArea = screen.getByRole('textbox');
		await fireEvent.input(textArea, { target: { value: 'Generate personality' } });

		const generateButton = screen.getByText('Generate');
		await fireEvent.click(generateButton);

		await waitFor(() => {
			expect(mockFetch).toHaveBeenCalledWith('/api/characters/generate/field', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					field: 'personality',
					style: null,
					user_prompt: 'Generate personality',
					character_context: expect.objectContaining({
						name: 'BasicChar'
					}),
					generation_options: null,
					lorebook_id: null // Should be null when no lorebooks selected
				})
			});
		});
	});

	it('should handle missing characterContext gracefully', async () => {
		const mockFetch = vi.mocked(fetch);
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				content: 'Generated content',
				style_used: 'auto',
				metadata: { tokens_used: 60 }
			})
		} as Response);

		const mockOnGenerated = vi.fn();
		const mockOnOpenChange = vi.fn();

		render(AiAssistantDialog, {
			props: {
				open: true,
				fieldName: 'scenario',
				fieldValue: '',
				characterContext: undefined, // No character context
				onGenerated: mockOnGenerated,
				onOpenChange: mockOnOpenChange
			}
		});

		const textArea = screen.getByRole('textbox');
		await fireEvent.input(textArea, { target: { value: 'Generate scenario' } });

		const generateButton = screen.getByText('Generate');
		await fireEvent.click(generateButton);

		await waitFor(() => {
			expect(mockFetch).toHaveBeenCalledWith('/api/characters/generate/field', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					field: 'scenario',
					style: null,
					user_prompt: 'Generate scenario',
					character_context: null,
					generation_options: null,
					lorebook_id: null
				})
			});
		});
	});

	it('should handle API errors gracefully', async () => {
		const mockFetch = vi.mocked(fetch);
		mockFetch.mockRejectedValueOnce(new Error('Network error'));

		const characterContext: CharacterContext = {
			name: 'ErrorChar',
			selectedLorebooks: ['lorebook-uuid-error']
		};

		const mockOnGenerated = vi.fn();
		const mockOnOpenChange = vi.fn();

		// Mock toast.error to avoid errors in test
		vi.mock('svelte-sonner', () => ({
			toast: {
				error: vi.fn(),
				success: vi.fn()
			}
		}));

		render(AiAssistantDialog, {
			props: {
				open: true,
				fieldName: 'description',
				fieldValue: '',
				characterContext,
				onGenerated: mockOnGenerated,
				onOpenChange: mockOnOpenChange
			}
		});

		const textArea = screen.getByRole('textbox');
		await fireEvent.input(textArea, { target: { value: 'This will fail' } });

		const generateButton = screen.getByText('Generate');
		await fireEvent.click(generateButton);

		// Should not call onGenerated when there's an error
		await waitFor(() => {
			expect(mockOnGenerated).not.toHaveBeenCalled();
		});
	});

	it('should correctly map alternate greeting field names', async () => {
		const mockFetch = vi.mocked(fetch);
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: async () => ({
				content: 'Alternate greeting content',
				style_used: 'auto',
				metadata: { tokens_used: 120 }
			})
		} as Response);

		const characterContext: CharacterContext = {
			name: 'GreetingChar',
			selectedLorebooks: ['lorebook-uuid-greeting']
		};

		const mockOnGenerated = vi.fn();
		const mockOnOpenChange = vi.fn();

		render(AiAssistantDialog, {
			props: {
				open: true,
				fieldName: 'alternate_greeting_1', // Frontend field name
				fieldValue: '',
				characterContext,
				onGenerated: mockOnGenerated,
				onOpenChange: mockOnOpenChange
			}
		});

		const textArea = screen.getByRole('textbox');
		await fireEvent.input(textArea, { target: { value: 'Generate greeting' } });

		const generateButton = screen.getByText('Generate');
		await fireEvent.click(generateButton);

		await waitFor(() => {
			expect(mockFetch).toHaveBeenCalledWith('/api/characters/generate/field', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					field: 'alternate_greeting', // Should be mapped to backend field name
					style: null,
					user_prompt: expect.stringContaining('Generate greeting'),
					character_context: expect.objectContaining({
						name: 'GreetingChar'
					}),
					generation_options: null,
					lorebook_id: 'lorebook-uuid-greeting'
				})
			});
		});
	});

	it('should include greeting number in prompt for alternate greetings', async () => {
		const mockFetch = vi.mocked(fetch);
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: async () => ({ content: 'Greeting 2 content' })
		} as Response);

		const characterContext: CharacterContext = {
			name: 'MultiGreetingChar',
			selectedLorebooks: ['lorebook-uuid-multi']
		};

		render(AiAssistantDialog, {
			props: {
				open: true,
				fieldName: 'alternate_greeting_2', // Second greeting
				fieldValue: '',
				characterContext,
				onGenerated: vi.fn(),
				onOpenChange: vi.fn()
			}
		});

		const textArea = screen.getByRole('textbox');
		await fireEvent.input(textArea, { target: { value: 'Create second greeting' } });

		const generateButton = screen.getByText('Generate');
		await fireEvent.click(generateButton);

		await waitFor(() => {
			const fetchCall = mockFetch.mock.calls[0];
			const requestBody = JSON.parse(fetchCall[1].body as string);
			
			// Should include greeting number context in the user prompt
			expect(requestBody.user_prompt).toContain('2');
		});
	});
});