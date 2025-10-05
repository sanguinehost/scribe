import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import TemplateSelector from '../TemplateSelector.svelte';
import { apiClient as _apiClient } from '$lib/api';
import type { PromptTemplateInfo, PromptTemplateListResponse } from '$lib/types';
import { ok } from 'neverthrow';

// Mock API client
vi.mock('$lib/api', () => ({
	apiClient: {
		getPromptTemplates: vi.fn()
	}
}));

// Mock toast
vi.mock('svelte-sonner', () => ({
	toast: {
		error: vi.fn(),
		warning: vi.fn()
	}
}));

describe('TemplateSelector', () => {
	const mockTemplates: PromptTemplateInfo[] = [
		{
			id: 'neutral_roleplay',
			version: '1.0.0',
			name: 'Neutral Roleplay',
			description: 'Balanced roleplay with narration and dialogue',
			compatibility: {
				requires_character: true,
				supports_rag: true,
				supports_personas: true
			}
		},
		{
			id: 'chatbot_dialogue',
			version: '1.0.0',
			name: 'Chatbot Dialogue',
			description: 'Pure conversation, like texting with a friend',
			compatibility: {
				requires_character: false,
				supports_rag: true,
				supports_personas: true
			}
		}
	];

	const mockApiResponse: PromptTemplateListResponse = {
		templates: mockTemplates
	};

	beforeEach(() => {
		vi.clearAllMocks();
		vi.mocked(_apiClient.getPromptTemplates).mockResolvedValue(ok(mockApiResponse));
	});

	it('renders with loading state initially', () => {
		const { getByText } = render(TemplateSelector, {
			props: {
				selectedTemplateId: 'neutral_roleplay'
			}
		});

		expect(getByText('Prompt Style')).toBeInTheDocument();
	});

	it('loads and displays templates after mount', async () => {
		const { getByText, getByRole: _getByRole } = render(TemplateSelector, {
			props: {
				selectedTemplateId: 'neutral_roleplay'
			}
		});

		// Wait for templates to load
		await waitFor(() => {
			expect(getByText('Neutral Roleplay')).toBeInTheDocument();
		});

		// Check that the API was called
		expect(_apiClient.getPromptTemplates).toHaveBeenCalledTimes(1);
	});

	it('shows dropdown when clicked', async () => {
		const { getByText, getByRole } = render(TemplateSelector, {
			props: {
				selectedTemplateId: 'neutral_roleplay'
			}
		});

		// Wait for templates to load
		await waitFor(() => {
			expect(getByText('Neutral Roleplay')).toBeInTheDocument();
		});

		// Click the selector button
		const button = getByRole('button');
		await fireEvent.click(button);

		// Check that dropdown options are shown
		await waitFor(() => {
			expect(getByText('Chatbot Dialogue')).toBeInTheDocument();
		});
	});

	it('calls onTemplateChange when a template is selected', async () => {
		const mockOnTemplateChange = vi.fn();
		const { getByText, getByRole } = render(TemplateSelector, {
			props: {
				selectedTemplateId: 'neutral_roleplay',
				onTemplateChange: mockOnTemplateChange
			}
		});

		// Wait for templates to load
		await waitFor(() => {
			expect(getByText('Neutral Roleplay')).toBeInTheDocument();
		});

		// Click the selector button
		const button = getByRole('button');
		await fireEvent.click(button);

		// Wait for dropdown to appear and click on chatbot option
		await waitFor(() => {
			expect(getByText('Chatbot Dialogue')).toBeInTheDocument();
		});

		const chatbotOption = getByText('Chatbot Dialogue');
		await fireEvent.click(chatbotOption);

		// Verify that the callback was called
		expect(mockOnTemplateChange).toHaveBeenCalledWith('chatbot_dialogue');
	});

	it('shows compatibility badges correctly', async () => {
		const { getByText, getByRole, getAllByText } = render(TemplateSelector, {
			props: {
				selectedTemplateId: 'neutral_roleplay',
				showCompatibility: true,
				currentChatMode: 'Character'
			}
		});

		// Wait for templates to load
		await waitFor(() => {
			expect(getByText('Neutral Roleplay')).toBeInTheDocument();
		});

		// Click the selector button
		const button = getByRole('button');
		await fireEvent.click(button);

		// Wait for dropdown to appear
		await waitFor(() => {
			expect(getByText('Chatbot Dialogue')).toBeInTheDocument();
		});

		// The neutral_roleplay template should show as recommended for Character mode
		// since it requires_character: true which matches Character mode
		const recommendedBadges = getAllByText('Recommended');
		expect(recommendedBadges.length).toBeGreaterThan(0);

		// The chatbot_dialogue template should show as Limited for Character mode
		// since it requires_character: false which doesn't match Character mode
		const limitedBadges = getAllByText('Limited');
		expect(limitedBadges.length).toBeGreaterThan(0);
	});

	it('handles API errors gracefully', async () => {
		const mockError = new Error('API Error');
		vi.mocked(_apiClient.getPromptTemplates).mockRejectedValue(mockError);

		const { getByText } = render(TemplateSelector, {
			props: {
				selectedTemplateId: 'neutral_roleplay'
			}
		});

		// Wait for error to be handled
		await waitFor(() => {
			// Component should still show the label even if loading failed
			expect(getByText('Prompt Style')).toBeInTheDocument();
		});

		// Check that API was called
		expect(_apiClient.getPromptTemplates).toHaveBeenCalledTimes(1);
	});
});
