import { render, screen } from '@testing-library/svelte'; // Removed waitFor
import { expect, test } from 'vitest'; // Removed vi, beforeEach
import Page from './+page.svelte';

// Removed beforeEach as mocks are no longer needed

test('should render static welcome content', () => {
	// No need to mock fetch as the page is static now
	render(Page);

	// Check for the main heading
	const heading = screen.getByRole('heading', { level: 1, name: /Welcome to Scribe/i });
	expect(heading).toBeInTheDocument();

	// Check for some paragraph text
	expect(screen.getByText(/This is the root page./)).toBeInTheDocument();
	expect(screen.getByText(/If logged in, you should typically be redirected to \/characters./)).toBeInTheDocument();
	expect(screen.getByText(/If logged out, you should typically be redirected to \/login./)).toBeInTheDocument();
});

// Removed the second test ('displays error message on failed health check') as it's no longer relevant
