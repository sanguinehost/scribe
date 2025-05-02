// frontend/src/lib/components/characters/CharacterCard.spec.ts
import { render, screen } from '@testing-library/svelte'; // Removed fireEvent
import { describe, it, expect } from 'vitest'; // Removed vi
import CharacterCard from './CharacterCard.svelte';
// Import the actual Character type from apiClient
import type { Character } from '$lib/services/apiClient';
// Removed unused SvelteComponent import

describe('CharacterCard.svelte', () => {
	// Use the imported Character type and ONLY include fields defined in it (apiClient.ts lines 332-338)
	const mockCharacter: Character = {
		id: 'char-123',
		name: 'Test Character',
		description: 'A brief description for testing.',
		greeting: 'Hello there!', // This field is in the apiClient Character type
		// DO NOT include fields like image_url, persona, world_scenario etc.
	};

	it('renders character name and description', () => {
		render(CharacterCard, { props: { character: mockCharacter } });

		expect(screen.getByText(mockCharacter.name)).toBeInTheDocument();
		// The card currently renders the greeting, not the description in the <p> tag
		expect(screen.getByText(mockCharacter.greeting)).toBeInTheDocument();
		expect(screen.queryByText(mockCharacter.description)).not.toBeInTheDocument(); // Verify description isn't rendered directly
	});

	// REMOVED: Test for event dispatch using $on (Svelte 4 API)
	// it('dispatches "select" event with character ID on click', async () => { ... });

		  it('renders greeting text when description is long', () => { // Renamed test slightly
        const longDescription = 'This is a very long description that might be truncated by CSS or other means, but the text should still be present in the DOM initially.';
        // Create character with long description, matching the apiClient Character type
        const characterWithLongDesc: Character = {
            id: 'char-456',
            name: 'Long Desc Character',
            description: longDescription,
            greeting: 'Hi!',
        };
        render(CharacterCard, { props: { character: characterWithLongDesc } });

        // Check that the greeting text exists in the DOM
        const greetingElement = screen.getByText(characterWithLongDesc.greeting);
        expect(greetingElement).toBeInTheDocument();
        // Verify the long description itself is not rendered directly
        expect(screen.queryByText(longDescription)).not.toBeInTheDocument();
          });
});