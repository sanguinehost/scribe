import { describe, test, expect, vi, beforeEach } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte'; // Removed unused waitFor
import Page from './+page.svelte';

beforeEach(() => {
	vi.resetAllMocks();
});

describe('/+page.svelte', () => {
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
});
