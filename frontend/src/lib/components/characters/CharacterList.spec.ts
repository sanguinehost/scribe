// First, set up the mocks
vi.mock('./CharacterCard.svelte', () => ({
    default: vi.fn().mockImplementation(({ target, props }) => {
        // Create a simple DOM element for the mock
        const el = document.createElement('div');
        if (props?.character) {
            el.textContent = `MockCard-${props.character.name}`;
            el.setAttribute('data-testid', `character-card-${props.character.id}`);
        } else {
            el.textContent = 'MockCard-NoData';
        }
        if (target) target.replaceWith(el);
        return { $set: vi.fn(), $destroy: vi.fn() };
    })
}));

// Mock the API client with all required functions
vi.mock('$lib/services/apiClient', () => {
    const getCharacterImageUrl = vi.fn().mockImplementation((id) => `/mock-image-url/${id || 'default'}.jpg`);
    
    return {
        apiClient: {
            listCharacters: vi.fn(),
            getCharacterImageUrl
        },
        getCharacterImageUrl
    };
});

// Import everything after mocks
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import CharacterList from './CharacterList.svelte';
import type { Character } from '$lib/services/apiClient';
import { apiClient } from '$lib/services/apiClient';

describe('CharacterList.svelte', () => {
	const mockCharacters: Character[] = [
		{ id: 'char1', name: 'Character One', description: 'Desc 1', greeting: 'Hi 1' },
		{ id: 'char2', name: 'Character Two', description: 'Desc 2', greeting: 'Hi 2' }
	];

	beforeEach(() => {
		// Reset mocks before each test
		vi.clearAllMocks();
		// Default successful response
		vi.mocked(apiClient.listCharacters).mockResolvedValue(mockCharacters);
	});

	it('renders loading state initially', () => {
		render(CharacterList);
		// Just verify the component renders
		expect(screen.getByText(/loading/i)).toBeInTheDocument();
	});

	it('calls listCharacters on mount', async () => {
		render(CharacterList);
		// Just verify the API was called
		expect(apiClient.listCharacters).toHaveBeenCalled();
	});

	it('handles errors when fetching characters fails', async () => {
		const errorMessage = 'Failed to fetch characters';
		vi.mocked(apiClient.listCharacters).mockRejectedValue(new Error(errorMessage));

		render(CharacterList);
		// Just verify the component renders
		await waitFor(() => {
			expect(screen.getByText(/error/i)).toBeInTheDocument();
		}, { timeout: 1000 });
	});

	// Add tests later for selection logic if implemented within this component
});